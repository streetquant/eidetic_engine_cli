//! EE-08 search-index job recovery contract tests.
//!
//! These tests exercise the public workspace requeue path.  Advisory leases
//! are deliberately seeded through the same public acquisition API used by a
//! publisher, so recovery is proved against the persisted owner contract
//! rather than a private fixture-only shortcut.

use std::fmt::Debug;

use ee::db::{
    AdvisoryLockId, CreateSearchIndexJobInput, CreateWorkspaceInput, DbConnection,
    SearchIndexJobStatus, SearchIndexJobType, StoredSearchIndexJob,
};

type TestResult = Result<(), String>;

const WORKSPACE_ID: &str = "wsp_ee08_requeue_0000000000001";

fn connection() -> Result<DbConnection, String> {
    let connection = DbConnection::open_memory().map_err(|error| error.to_string())?;
    connection.migrate().map_err(|error| error.to_string())?;
    connection
        .insert_workspace(
            WORKSPACE_ID,
            &CreateWorkspaceInput {
                path: "/tmp/ee08-public-requeue".to_owned(),
                name: Some("EE-08 public requeue fixture".to_owned()),
            },
        )
        .map_err(|error| error.to_string())?;
    Ok(connection)
}

fn insert_running_job(connection: &DbConnection, job_id: &str) -> TestResult {
    connection
        .insert_search_index_job(
            job_id,
            &CreateSearchIndexJobInput {
                workspace_id: WORKSPACE_ID.to_owned(),
                job_type: SearchIndexJobType::Incremental,
                document_source: Some("cass".to_owned()),
                document_id: Some(format!("session-{job_id}")),
                documents_total: 7,
            },
        )
        .map_err(|error| error.to_string())?;
    if !connection
        .start_search_index_job(job_id)
        .map_err(|error| error.to_string())?
    {
        return Err(format!("job {job_id} did not enter running state"));
    }
    if !connection
        .update_search_index_job_progress(job_id, 3)
        .map_err(|error| error.to_string())?
    {
        return Err(format!("job {job_id} progress update was not applied"));
    }
    Ok(())
}

fn stored_job(connection: &DbConnection, job_id: &str) -> Result<StoredSearchIndexJob, String> {
    connection
        .get_search_index_job(job_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("job {job_id} disappeared"))
}

fn assert_status(job: &StoredSearchIndexJob, expected: SearchIndexJobStatus, context: &str) {
    assert_eq!(
        job.status_enum(),
        Some(expected),
        "{context}: unexpected job state: {job:?}"
    );
}

fn assert_eq_debug<T: Debug + PartialEq>(actual: &T, expected: &T, context: &str) {
    assert_eq!(actual, expected, "{context}");
}

#[test]
fn public_requeue_preserves_unprobeable_remote_holder_then_requeues_after_release() -> TestResult {
    let connection = connection()?;
    let job_id = "sidx_ee08_remote_00000000000001";
    insert_running_job(&connection, job_id)?;

    let lock_id = AdvisoryLockId::index(WORKSPACE_ID);
    let holder_id = "remote-node:publisher-7:ee08";
    assert!(
        connection
            .acquire_advisory_lock(
                &lock_id,
                holder_id,
                Some(600),
                Some("EE-08 unprobeable remote publisher"),
            )
            .map_err(|error| error.to_string())?
            .is_acquired()
    );
    let before = stored_job(&connection, job_id)?;

    // This is the public requeue entry point used by recovery callers. An
    // unprobeable holder is authoritative even though it has no local PID.
    assert_eq!(
        connection
            .requeue_cancelled_search_index_jobs(WORKSPACE_ID)
            .map_err(|error| error.to_string())?,
        0,
        "remote holder must prevent public requeue"
    );
    let after_blocked = stored_job(&connection, job_id)?;
    assert_eq_debug(
        &after_blocked,
        &before,
        "remote holder must leave the running row byte-for-byte unchanged",
    );
    assert_eq!(
        connection
            .is_lock_held(&lock_id)
            .map_err(|error| error.to_string())?
            .map(|lock| lock.holder_id),
        Some(holder_id.to_owned()),
        "remote lease remains persisted while recovery is blocked",
    );

    assert!(
        connection
            .release_advisory_lock(&lock_id, holder_id)
            .map_err(|error| error.to_string())?,
        "fixture owner releases its persisted lease"
    );
    assert_eq!(
        connection
            .requeue_cancelled_search_index_jobs(WORKSPACE_ID)
            .map_err(|error| error.to_string())?,
        1,
        "unowned running row is requeued after remote lease release"
    );
    let pending = stored_job(&connection, job_id)?;
    assert_status(
        &pending,
        SearchIndexJobStatus::Pending,
        "released remote owner",
    );
    assert_eq!(pending.documents_indexed, 0);
    assert!(pending.started_at.is_none());
    assert!(pending.completed_at.is_none());
    assert!(pending.error_message.is_none());
    assert_eq!(
        connection
            .requeue_cancelled_search_index_jobs(WORKSPACE_ID)
            .map_err(|error| error.to_string())?,
        0,
        "second public requeue is idempotent"
    );
    Ok(())
}

#[test]
fn public_requeue_is_atomic_for_multiple_jobs_under_one_live_or_remote_holder() -> TestResult {
    let live_holder = format!("index:{}:ee08-live", std::process::id());
    for (label, holder_id) in [
        ("live", live_holder),
        ("remote", "remote-node:publisher-8:ee08".to_owned()),
    ] {
        let connection = connection()?;
        let job_ids = [
            "sidx_ee08_atomic_a_000000000001".to_owned(),
            "sidx_ee08_atomic_b_000000000001".to_owned(),
        ];
        for job_id in &job_ids {
            insert_running_job(&connection, job_id)?;
        }

        let lock_id = AdvisoryLockId::index(WORKSPACE_ID);
        assert!(
            connection
                .acquire_advisory_lock(
                    &lock_id,
                    &holder_id,
                    Some(600),
                    Some("EE-08 atomic publication owner"),
                )
                .map_err(|error| error.to_string())?
                .is_acquired(),
            "{label} holder fixture must acquire the one workspace lease"
        );
        let before = job_ids
            .iter()
            .map(|job_id| stored_job(&connection, job_id))
            .collect::<Result<Vec<_>, _>>()?;

        // The recovery decision covers the logical workspace in one database
        // transaction. One protected holder therefore prevents a partial
        // requeue of the two running rows.
        assert_eq!(
            connection
                .requeue_cancelled_search_index_jobs(WORKSPACE_ID)
                .map_err(|error| error.to_string())?,
            0,
            "{label} holder must protect every running job"
        );
        let after_blocked = job_ids
            .iter()
            .map(|job_id| stored_job(&connection, job_id))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq_debug(
            &after_blocked,
            &before,
            "one holder must prevent any partial multi-job requeue",
        );
        assert_eq!(
            connection
                .is_lock_held(&lock_id)
                .map_err(|error| error.to_string())?
                .map(|lock| lock.holder_id),
            Some(holder_id.clone()),
            "{label} holder remains authoritative",
        );

        assert!(
            connection
                .release_advisory_lock(&lock_id, &holder_id)
                .map_err(|error| error.to_string())?,
            "{label} holder fixture releases its lease"
        );
        assert_eq!(
            connection
                .requeue_cancelled_search_index_jobs(WORKSPACE_ID)
                .map_err(|error| error.to_string())?,
            2,
            "unowned {label} rows requeue together"
        );
        for job_id in &job_ids {
            let pending = stored_job(&connection, job_id)?;
            assert_status(&pending, SearchIndexJobStatus::Pending, label);
        }
        assert_eq!(
            connection
                .requeue_cancelled_search_index_jobs(WORKSPACE_ID)
                .map_err(|error| error.to_string())?,
            0,
            "repeating {label} recovery is idempotent"
        );
    }
    Ok(())
}

#[test]
fn public_requeue_recovers_dead_owner_idempotently_without_replaying_the_lease() -> TestResult {
    let connection = connection()?;
    let job_id = "sidx_ee08_dead_0000000000000001";
    insert_running_job(&connection, job_id)?;

    let lock_id = AdvisoryLockId::index(WORKSPACE_ID);
    let holder_id = "index:2147483647:ee08-dead";
    assert!(
        connection
            .acquire_advisory_lock(
                &lock_id,
                holder_id,
                Some(600),
                Some("EE-08 dead publisher fixture"),
            )
            .map_err(|error| error.to_string())?
            .is_acquired()
    );

    assert_eq!(
        connection
            .requeue_cancelled_search_index_jobs(WORKSPACE_ID)
            .map_err(|error| error.to_string())?,
        1,
        "dead owner should requeue through public recovery"
    );
    let first = stored_job(&connection, job_id)?;
    assert_status(&first, SearchIndexJobStatus::Pending, "dead owner recovery");
    assert_eq!(first.documents_indexed, 0);
    assert!(first.started_at.is_none());
    assert!(first.completed_at.is_none());
    assert!(first.error_message.is_none());
    assert_eq!(
        connection
            .is_lock_held(&lock_id)
            .map_err(|error| error.to_string())?
            .map(|lock| lock.holder_id),
        Some(holder_id.to_owned()),
        "job recovery does not invent a lease deletion or transfer",
    );

    assert_eq!(
        connection
            .requeue_cancelled_search_index_jobs(WORKSPACE_ID)
            .map_err(|error| error.to_string())?,
        0,
        "repeating dead-owner recovery must be idempotent"
    );
    let second = stored_job(&connection, job_id)?;
    assert_eq_debug(
        &second,
        &first,
        "idempotent recovery must preserve the requeued row",
    );
    Ok(())
}
