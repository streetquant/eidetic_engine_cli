//! Disposable V121 schema-migration preservation regression.
//!
//! The fixture is deliberately seeded at V120, copied as a SQLite bundle, and
//! migrated only through the public `DbConnection::migrate` API on the copy.
//! This keeps the regression independent of live EE state and makes it
//! sensitive to accidental rewrites of unrelated durable rows.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use ee::db::{
    CreateMemoryInput, CreateRememberIdempotencyKeyInput, CreateSearchIndexJobInput,
    CreateWorkspaceInput, DbConnection, MIGRATIONS, MigrationRecord, SearchIndexJobType,
};

type TestResult = Result<(), String>;

const PRE_V121_VERSION: u32 = 120;
const WORKSPACE_ID: &str = "wsp_01234567890123456789012345";
const MEMORY_ID: &str = "mem_01234567890123456789012345";
const JOB_ID: &str = "sidx_01234567890123456789012345";
const IDEMPOTENCY_KEY: &str = "v121-preservation-idempotency-key";
const MEMORY_CONTENT: &str = "V121 preservation fixture keeps this memory byte-for-byte stable.";
const FIXED_APPLIED_AT: &str = "2026-09-01T00:00:00Z";

#[derive(Clone, Debug, Eq, PartialEq)]
struct RowFingerprint {
    id: String,
    content_hash: String,
    state_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreservationSnapshot {
    workspace: RowFingerprint,
    memory: RowFingerprint,
    idempotency: RowFingerprint,
    index_job: RowFingerprint,
}

fn hash_fields(fields: &[String]) -> String {
    let mut encoded = Vec::new();
    for field in fields {
        encoded.extend_from_slice(&(field.len() as u64).to_be_bytes());
        encoded.extend_from_slice(field.as_bytes());
    }
    format!("blake3:{}", blake3::hash(&encoded).to_hex())
}

fn optional_text(value: Option<&str>) -> String {
    value.unwrap_or("<null>").to_owned()
}

fn seed_database_through(path: &Path, through_version: u32) -> TestResult {
    let connection = DbConnection::open_file(path).map_err(|error| error.to_string())?;
    connection
        .ensure_migration_table()
        .map_err(|error| format!("ensure migration table: {error}"))?;

    for migration in MIGRATIONS
        .iter()
        .filter(|migration| migration.version() <= through_version)
    {
        connection
            .execute_raw(migration.sql())
            .map_err(|error| format!("apply V{}: {error}", migration.version()))?;
        let record = MigrationRecord::new(
            migration.version(),
            migration.name(),
            migration.checksum_label(),
            FIXED_APPLIED_AT,
        )
        .map_err(|error| format!("record V{}: {error}", migration.version()))?;
        connection
            .record_migration(&record)
            .map_err(|error| format!("record V{}: {error}", migration.version()))?;
    }

    connection.close().map_err(|error| error.to_string())
}

fn seed_rows(path: &Path) -> Result<PreservationSnapshot, String> {
    let connection = DbConnection::open_file(path).map_err(|error| error.to_string())?;
    connection
        .insert_workspace(
            WORKSPACE_ID,
            &CreateWorkspaceInput {
                path: path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .display()
                    .to_string(),
                name: Some("V121 preservation workspace".to_owned()),
            },
        )
        .map_err(|error| format!("insert workspace: {error}"))?;

    connection
        .insert_memory(
            MEMORY_ID,
            &CreateMemoryInput {
                workspace_id: WORKSPACE_ID.to_owned(),
                level: "semantic".to_owned(),
                kind: "fact".to_owned(),
                content: MEMORY_CONTENT.to_owned(),
                workflow_id: None,
                confidence: 0.91,
                utility: 0.82,
                importance: 0.73,
                provenance_uri: Some("test://v121-preservation".to_owned()),
                trust_class: "human_explicit".to_owned(),
                trust_subclass: Some("v121-test".to_owned()),
                tags: Vec::new(),
                valid_from: Some(FIXED_APPLIED_AT.to_owned()),
                valid_to: None,
            },
        )
        .map_err(|error| format!("insert memory: {error}"))?;

    let memory_content_hash = hash_fields(&[MEMORY_CONTENT.to_owned()]);
    connection
        .insert_remember_idempotency_key(&CreateRememberIdempotencyKeyInput {
            workspace_id: WORKSPACE_ID.to_owned(),
            idempotency_key: IDEMPOTENCY_KEY.to_owned(),
            content_hash: memory_content_hash,
            memory_id: MEMORY_ID.to_owned(),
        })
        .map_err(|error| format!("insert idempotency row: {error}"))?;

    connection
        .insert_search_index_job(
            JOB_ID,
            &CreateSearchIndexJobInput {
                workspace_id: WORKSPACE_ID.to_owned(),
                job_type: SearchIndexJobType::Incremental,
                document_source: Some("memory".to_owned()),
                document_id: Some(MEMORY_ID.to_owned()),
                documents_total: 7,
            },
        )
        .map_err(|error| format!("insert index job: {error}"))?;
    if !connection
        .start_search_index_job(JOB_ID)
        .map_err(|error| format!("start index job: {error}"))?
    {
        return Err("index job did not transition to running".to_owned());
    }
    if !connection
        .update_search_index_job_progress(JOB_ID, 3)
        .map_err(|error| format!("update index job: {error}"))?
    {
        return Err("index job progress update was not applied".to_owned());
    }

    let snapshot = snapshot_rows(&connection)?;
    connection.close().map_err(|error| error.to_string())?;
    Ok(snapshot)
}

fn snapshot_rows(connection: &DbConnection) -> Result<PreservationSnapshot, String> {
    let workspace = connection
        .get_workspace(WORKSPACE_ID)
        .map_err(|error| format!("get workspace: {error}"))?
        .ok_or_else(|| "workspace fixture row is missing".to_owned())?;
    let workspace_state = vec![
        workspace.id.clone(),
        workspace.path.clone(),
        optional_text(workspace.name.as_deref()),
        workspace.scope_kind.clone(),
        optional_text(workspace.repository_root.as_deref()),
        optional_text(workspace.repository_fingerprint.as_deref()),
        optional_text(workspace.subproject_path.as_deref()),
        workspace.created_at.clone(),
        workspace.updated_at.clone(),
    ];
    let workspace_fingerprint = RowFingerprint {
        id: workspace.id,
        content_hash: hash_fields(&[workspace_state[1].clone(), workspace_state[2].clone()]),
        state_hash: hash_fields(&workspace_state),
    };

    let memory = connection
        .get_memory(MEMORY_ID)
        .map_err(|error| format!("get memory: {error}"))?
        .ok_or_else(|| "memory fixture row is missing".to_owned())?;
    let memory_state = vec![
        memory.id.clone(),
        memory.workspace_id.clone(),
        memory.level.clone(),
        memory.kind.clone(),
        memory.content.clone(),
        optional_text(memory.workflow_id.as_deref()),
        memory.confidence.to_bits().to_string(),
        memory.utility.to_bits().to_string(),
        memory.importance.to_bits().to_string(),
        optional_text(memory.provenance_uri.as_deref()),
        memory.trust_class.clone(),
        optional_text(memory.trust_subclass.as_deref()),
        optional_text(memory.provenance_chain_hash.as_deref()),
        memory.provenance_chain_hash_version.clone(),
        memory.provenance_verification_status.clone(),
        optional_text(memory.provenance_verified_at.as_deref()),
        optional_text(memory.provenance_verification_note.as_deref()),
        memory.created_at.clone(),
        memory.updated_at.clone(),
        optional_text(memory.tombstoned_at.as_deref()),
        optional_text(memory.valid_from.as_deref()),
        optional_text(memory.valid_to.as_deref()),
    ];
    let memory_fingerprint = RowFingerprint {
        id: memory.id,
        content_hash: hash_fields(&[memory_state[4].clone()]),
        state_hash: hash_fields(&memory_state),
    };

    let idempotency = connection
        .get_remember_idempotency_key(WORKSPACE_ID, IDEMPOTENCY_KEY)
        .map_err(|error| format!("get idempotency row: {error}"))?
        .ok_or_else(|| "idempotency fixture row is missing".to_owned())?;
    let idempotency_state = vec![
        idempotency.workspace_id.clone(),
        idempotency.idempotency_key.clone(),
        idempotency.content_hash.clone(),
        idempotency.memory_id.clone(),
        idempotency.created_at.clone(),
    ];
    let idempotency_fingerprint = RowFingerprint {
        id: format!(
            "{}:{}",
            idempotency.workspace_id, idempotency.idempotency_key
        ),
        content_hash: idempotency.content_hash,
        state_hash: hash_fields(&idempotency_state),
    };

    let index_job = connection
        .get_search_index_job(JOB_ID)
        .map_err(|error| format!("get index job: {error}"))?
        .ok_or_else(|| "index-job fixture row is missing".to_owned())?;
    let index_job_state = vec![
        index_job.id.clone(),
        index_job.workspace_id.clone(),
        index_job.job_type.clone(),
        optional_text(index_job.document_source.as_deref()),
        optional_text(index_job.document_id.as_deref()),
        index_job.status.clone(),
        index_job.documents_total.to_string(),
        index_job.documents_indexed.to_string(),
        optional_text(index_job.error_message.as_deref()),
        index_job.created_at.clone(),
        optional_text(index_job.started_at.as_deref()),
        optional_text(index_job.completed_at.as_deref()),
    ];
    let index_job_fingerprint = RowFingerprint {
        id: index_job.id,
        content_hash: hash_fields(&[
            index_job_state[1].clone(),
            index_job_state[2].clone(),
            index_job_state[3].clone(),
            index_job_state[4].clone(),
        ]),
        state_hash: hash_fields(&index_job_state),
    };

    Ok(PreservationSnapshot {
        workspace: workspace_fingerprint,
        memory: memory_fingerprint,
        idempotency: idempotency_fingerprint,
        index_job: index_job_fingerprint,
    })
}

fn copy_sqlite_bundle(source: &Path, destination: &Path) -> TestResult {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("create clone directory: {error}"))?;
    }
    fs::copy(source, destination).map_err(|error| format!("copy database: {error}"))?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let source_sidecar = PathBuf::from(format!("{}{}", source.display(), suffix));
        if source_sidecar.exists() {
            let destination_sidecar = PathBuf::from(format!("{}{}", destination.display(), suffix));
            fs::copy(&source_sidecar, &destination_sidecar)
                .map_err(|error| format!("copy {suffix} sidecar: {error}"))?;
        }
    }
    Ok(())
}

#[test]
fn v121_preserves_rows_on_supported_migration_clone_and_idempotent_rerun() -> TestResult {
    let tempdir = tempfile::tempdir().map_err(|error| error.to_string())?;
    let source_dir = tempdir.path().join("source");
    let clone_dir = tempdir.path().join("clone");
    fs::create_dir_all(&source_dir).map_err(|error| error.to_string())?;
    fs::create_dir_all(&clone_dir).map_err(|error| error.to_string())?;
    let source_db = source_dir.join("ee.db");
    let clone_db = clone_dir.join("ee.db");

    seed_database_through(&source_db, PRE_V121_VERSION)?;
    let before = seed_rows(&source_db)?;
    copy_sqlite_bundle(&source_db, &clone_db)?;

    let clone = DbConnection::open_file(&clone_db).map_err(|error| error.to_string())?;
    let clone_before = snapshot_rows(&clone)?;
    if clone_before != before {
        return Err(format!(
            "isolated clone changed before migration: source={before:?} clone={clone_before:?}"
        ));
    }

    let first = clone
        .migrate()
        .map_err(|error| format!("first migrate: {error}"))?;
    if !first.applied().contains(&121) {
        return Err(format!(
            "supported migration did not apply V121: {:?}",
            first.applied()
        ));
    }
    if clone.schema_version().map_err(|error| error.to_string())? != Some(121) {
        return Err("clone schema version did not advance to V121".to_owned());
    }
    let after_first = snapshot_rows(&clone)?;
    if after_first != before {
        return Err(format!(
            "V121 changed preserved rows: before={before:?} after={after_first:?}"
        ));
    }

    let v121_records = clone
        .applied_migrations()
        .map_err(|error| format!("list migrations: {error}"))?
        .into_iter()
        .filter(|record| record.version() == 121)
        .collect::<Vec<_>>();
    if v121_records.len() != 1 {
        return Err(format!(
            "expected exactly one V121 ledger row, got {}",
            v121_records.len()
        ));
    }
    let expected_v121 = MIGRATIONS
        .iter()
        .find(|migration| migration.version() == 121)
        .ok_or_else(|| "compiled V121 migration is missing".to_owned())?;
    let record = &v121_records[0];
    if record.name() != expected_v121.name() || record.checksum() != expected_v121.checksum() {
        return Err(format!(
            "V121 ledger identity drifted: name={} checksum={}",
            record.name(),
            record.checksum()
        ));
    }

    let second = clone
        .migrate()
        .map_err(|error| format!("idempotent migrate rerun: {error}"))?;
    if !second.applied().is_empty() || !second.skipped().contains(&121) {
        return Err(format!(
            "idempotent rerun was not a no-op: applied={:?} skipped={:?}",
            second.applied(),
            second.skipped()
        ));
    }
    let after_second = snapshot_rows(&clone)?;
    if after_second != after_first {
        return Err(format!(
            "idempotent rerun changed preserved rows: first={after_first:?} second={after_second:?}"
        ));
    }
    clone.close().map_err(|error| error.to_string())?;

    let source = DbConnection::open_file_read_only(&source_db)
        .map_err(|error| format!("open source read-only: {error}"))?;
    let source_after = snapshot_rows(&source)?;
    if source_after != before {
        return Err(format!(
            "migration mutated source instead of isolated clone: before={before:?} source={source_after:?}"
        ));
    }
    if source.schema_version().map_err(|error| error.to_string())? != Some(PRE_V121_VERSION) {
        return Err("source schema unexpectedly advanced past V120".to_owned());
    }
    if !source
        .needs_migration()
        .map_err(|error| error.to_string())?
    {
        return Err("source should still report V121 as pending".to_owned());
    }
    source.close().map_err(|error| error.to_string())?;
    Ok(())
}
