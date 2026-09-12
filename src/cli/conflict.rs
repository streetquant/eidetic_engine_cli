//! bd-1n0np.7.3 — `ee conflict list|explain|cluster` read-only contradiction surface.
//!
//! Thin CLI layer over
//! [`crate::core::contradiction_detect::assemble_conflict_surface`] (which reuses
//! the 7.2 gather + explicit-evidence detector). list|explain|cluster are
//! read-only. `resolve` (bd-3a1op.4, ADR 0066) plans via the pure
//! [`crate::core::contradiction_detect::plan_conflict_resolution`] engine and,
//! only under `--apply`, executes all planned atoms in one audited database
//! transaction with a durable operation receipt for replay.

use std::collections::BTreeSet;
use std::path::Path;

use chrono::{SecondsFormat, Utc};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::core::contradiction_detect::{
    ConflictResolutionPlan, ConflictSurface, ContradictionDetectionConfig, PlannedResolutionAction,
    assemble_conflict_surface,
};
use crate::db::{DbConnection, MemoryLinkRelation, MemoryLinkSource};
use crate::models::{DomainError, MemoryId, RESPONSE_SCHEMA_V2};

/// Subcommands for `ee conflict` (read-only contradiction surfacing).
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum ConflictCommand {
    /// List ranked conflicting memory pairs with both bodies + the preferred side.
    List(ConflictListArgs),
    /// Explain the conflicts implicating a specific memory id.
    Explain(ConflictExplainArgs),
    /// List detected contradiction clusters (k-truss + Louvain).
    Cluster(ConflictClusterArgs),
    /// Resolve one conflicting pair through audited mutations (dry-run default).
    Resolve(ConflictResolveArgs),
}

/// `ee conflict resolve <MEMORY_A> <MEMORY_B> --verb ...` (bd-3a1op.4).
#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct ConflictResolveArgs {
    /// One side of the conflicting pair (order-independent).
    #[arg(value_name = "MEMORY_A")]
    pub memory_a: String,
    /// The other side of the conflicting pair.
    #[arg(value_name = "MEMORY_B")]
    pub memory_b: String,
    /// Resolution verb: supersede | reject-one | scope-split | both-valid.
    #[arg(long, value_name = "VERB")]
    pub verb: String,
    /// Surviving memory id (required by supersede and reject-one).
    #[arg(long, value_name = "MEMORY_ID")]
    pub keep: Option<String>,
    /// Rationale persisted as the decision memory's rationale.
    #[arg(long, value_name = "TEXT")]
    pub reason: Option<String>,
    /// scope-split only: comma-separated tags scoping memory A.
    #[arg(long, value_name = "TAGS")]
    pub scope_a_tags: Option<String>,
    /// scope-split only: comma-separated tags scoping memory B.
    #[arg(long, value_name = "TAGS")]
    pub scope_b_tags: Option<String>,
    /// Execute the plan. Without this flag the command is a dry-run report.
    #[arg(long)]
    pub apply: bool,
    /// Actor recorded in audit rows.
    #[arg(long, value_name = "ACTOR")]
    pub actor: Option<String>,
}

/// Per-atom execution evidence: every applied mutation names its audit trail.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionActionResult {
    pub action: String,
    pub audit_ids: Vec<String>,
    pub created_memory_id: Option<String>,
}

/// Durable result of one conflict-resolution operation. The operation id is
/// deterministic for the request and is also the audit-log receipt key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictExecutionReport {
    pub operation_id: String,
    pub replayed: bool,
    pub results: Vec<ResolutionActionResult>,
}

const CONFLICT_OPERATION_AUDIT_ACTION: &str = "conflict.resolve.operation";
const CONFLICT_OPERATION_RECEIPT_SCHEMA: &str = "ee.audit.conflict_resolution.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConflictOperationReceipt {
    schema: String,
    operation_id: String,
    workspace_id: String,
    reason: String,
    actor: Option<String>,
    plan: ConflictResolutionPlan,
    results: Vec<ResolutionActionResult>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConflictOperationIdentity<'a> {
    schema: &'static str,
    workspace_id: &'a str,
    memory_a: &'a str,
    memory_b: &'a str,
    verb: &'a str,
    keep: Option<&'a str>,
    reason: &'a str,
    scope_a_tags: Vec<String>,
    scope_b_tags: Vec<String>,
    actor: Option<&'a str>,
}

fn canonical_tags(tags: &[String]) -> Vec<String> {
    tags.iter()
        .map(|tag| tag.trim())
        .filter(|tag| !tag.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn operation_id_from_json(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).expect("conflict operation identity is serializable");
    let digest = blake3::hash(&bytes).to_hex().to_string();
    format!("audit_{}", &digest[..32])
}

pub fn conflict_operation_id(
    workspace: &Path,
    database_path: &Path,
    memory_a: &str,
    memory_b: &str,
    verb: &str,
    keep: Option<&str>,
    reason: &str,
    scope_a_tags: &[String],
    scope_b_tags: &[String],
    actor: Option<&str>,
) -> Result<String, DomainError> {
    let connection = open_conflict_database(database_path)?;
    let workspace_id = crate::core::memory::workspace_id_for_database(&connection, workspace);
    let identity = ConflictOperationIdentity {
        schema: "ee.conflict.resolve.operation.v1",
        workspace_id: &workspace_id,
        memory_a,
        memory_b,
        verb,
        keep,
        reason,
        scope_a_tags: canonical_tags(scope_a_tags),
        scope_b_tags: canonical_tags(scope_b_tags),
        actor,
    };
    Ok(operation_id_from_json(
        &serde_json::to_value(identity).expect("identity serializable"),
    ))
}

fn conflict_db_error(error: crate::db::DbError) -> DomainError {
    DomainError::Storage {
        message: format!("Conflict resolution storage failure: {error}"),
        repair: Some("Run ee doctor --json and retry the resolution.".to_owned()),
    }
}

fn conflict_malformed(message: impl Into<String>) -> crate::db::DbError {
    crate::db::DbError::MalformedRow {
        operation: crate::db::DbOperation::Query,
        message: message.into(),
    }
}

fn read_operation_receipt_db(
    connection: &DbConnection,
    operation_id: &str,
    workspace_id: &str,
) -> crate::db::Result<Option<ConflictOperationReceipt>> {
    let Some(audit) = connection.get_audit(operation_id)? else {
        return Ok(None);
    };
    if audit.action != CONFLICT_OPERATION_AUDIT_ACTION {
        return Ok(None);
    }
    if audit.workspace_id.as_deref() != Some(workspace_id) {
        return Err(conflict_malformed(format!(
            "conflict operation receipt {operation_id} belongs to another workspace"
        )));
    }
    let details = audit
        .details
        .as_deref()
        .ok_or_else(|| conflict_malformed("conflict operation receipt has no details"))?;
    let receipt: ConflictOperationReceipt = serde_json::from_str(details).map_err(|error| {
        conflict_malformed(format!("invalid conflict operation receipt: {error}"))
    })?;
    if receipt.operation_id != operation_id || receipt.workspace_id != workspace_id {
        return Err(conflict_malformed(format!(
            "conflict operation receipt {operation_id} has an identity mismatch"
        )));
    }
    Ok(Some(receipt))
}

fn ensure_receipt_matches_request(
    receipt: &ConflictOperationReceipt,
    plan: &ConflictResolutionPlan,
    reason: &str,
    actor: Option<&str>,
) -> crate::db::Result<()> {
    if receipt.plan != *plan || receipt.reason != reason || receipt.actor.as_deref() != actor {
        return Err(conflict_malformed(
            "conflict operation id was already used for a different request",
        ));
    }
    Ok(())
}

pub fn load_conflict_resolution_replay(
    workspace: &Path,
    database_path: &Path,
    operation_id: &str,
) -> Result<Option<(ConflictResolutionPlan, ConflictExecutionReport)>, DomainError> {
    let connection = open_conflict_database(database_path)?;
    let workspace_id = crate::core::memory::workspace_id_for_database(&connection, workspace);
    let Some(receipt) = read_operation_receipt_db(&connection, operation_id, &workspace_id)
        .map_err(conflict_db_error)?
    else {
        return Ok(None);
    };
    Ok(Some((
        receipt.plan,
        ConflictExecutionReport {
            operation_id: receipt.operation_id,
            replayed: true,
            results: receipt.results,
        },
    )))
}

fn open_conflict_database(database_path: &Path) -> Result<DbConnection, DomainError> {
    let connection = DbConnection::open_file(database_path).map_err(conflict_db_error)?;
    connection.migrate().map_err(conflict_db_error)?;
    Ok(connection)
}

fn conflict_search_index_job_id() -> String {
    let memory_id = MemoryId::now().to_string();
    format!("sidx_{}", memory_id.trim_start_matches("mem_"))
}

fn conflict_memory_link_id() -> String {
    let memory_id = MemoryId::now().to_string();
    format!("link_{}", memory_id.trim_start_matches("mem_"))
}

fn current_memory_at(memory: &crate::db::StoredMemory, now: chrono::DateTime<Utc>) -> bool {
    if memory.tombstoned_at.is_some() {
        return false;
    }
    let valid_from = memory
        .valid_from
        .as_deref()
        .map(chrono::DateTime::parse_from_rfc3339)
        .and_then(Result::ok)
        .map(|value| value.with_timezone(&Utc));
    let valid_to = memory
        .valid_to
        .as_deref()
        .map(chrono::DateTime::parse_from_rfc3339)
        .and_then(Result::ok)
        .map(|value| value.with_timezone(&Utc));
    (memory.valid_from.is_none() || valid_from.is_some())
        && (memory.valid_to.is_none() || valid_to.is_some())
        && !valid_from.is_some_and(|value| value > now)
        && !valid_to.is_some_and(|value| value <= now)
}

fn current_pair_matches(
    connection: &DbConnection,
    workspace_id: &str,
    plan: &ConflictResolutionPlan,
) -> crate::db::Result<bool> {
    if plan.memory_a == plan.memory_b {
        return Ok(false);
    }
    let (Some(a), Some(b)) = (
        connection.get_memory(&plan.memory_a)?,
        connection.get_memory(&plan.memory_b)?,
    ) else {
        return Ok(false);
    };
    if a.workspace_id != workspace_id
        || b.workspace_id != workspace_id
        || !current_memory_at(&a, Utc::now())
        || !current_memory_at(&b, Utc::now())
    {
        return Ok(false);
    }
    let surface = assemble_conflict_surface(connection, ContradictionDetectionConfig::default());
    Ok(surface.pairs.iter().any(|pair| {
        pair.conflict_id == plan.conflict_id
            && ((pair.memory_a.id == plan.memory_a && pair.memory_b.id == plan.memory_b)
                || (pair.memory_a.id == plan.memory_b && pair.memory_b.id == plan.memory_a))
    }))
}

fn decision_content(
    topic: &str,
    chosen: &str,
    alternatives: &[String],
    rationale: &str,
    supersedes: Option<&str>,
) -> Result<String, DomainError> {
    let mut options = Vec::with_capacity(alternatives.len() + 1);
    options.push(chosen.to_owned());
    for alternative in alternatives {
        if !alternative.trim().is_empty() && !options.iter().any(|item| item == alternative) {
            options.push(alternative.clone());
        }
    }
    if options.len() < 2 {
        return Err(DomainError::Usage {
            message: "Conflict resolution requires at least one distinct alternative.".to_owned(),
            repair: Some("Re-run the conflict resolution with a concrete rationale.".to_owned()),
        });
    }
    let mut lines = vec![
        format!("Topic: {topic}"),
        format!("Options: {}", options.join(", ")),
        format!("Chosen: {chosen}"),
        format!("Rationale: {rationale}"),
    ];
    if let Some(supersedes) = supersedes {
        lines.push(format!("Supersedes: {supersedes}"));
    }
    Ok(lines.join("\n"))
}

fn prepare_conflict_decision_write(
    connection: &DbConnection,
    workspace: &Path,
    database_path: &Path,
    plan: &ConflictResolutionPlan,
    topic: &str,
    chosen: &str,
    alternatives: &[String],
    reason: &str,
    supersedes: Option<&str>,
) -> Result<crate::core::memory::PreparedRememberTxnWrite, DomainError> {
    let content = decision_content(topic, chosen, alternatives, reason, supersedes)?;
    let tags = format!("decision,conflict:{}", plan.conflict_id);
    let options = crate::core::memory::RememberMemoryOptions {
        workspace_path: workspace,
        database_path: Some(database_path),
        content: &content,
        workflow_id: None,
        level: "semantic",
        kind: "decision",
        tags: Some(&tags),
        confidence: 0.85,
        source: None,
        allow_secret_mention: false,
        valid_from: None,
        valid_to: None,
        dry_run: false,
        auto_link: false,
        propose_candidates: false,
    };
    crate::core::memory::prepare_remember_txn_write_for_connection(connection, &options, true)
}

fn expire_memory_in_txn(
    connection: &DbConnection,
    workspace_id: &str,
    memory_id: &str,
    reason: &str,
    actor: Option<&str>,
) -> crate::db::Result<Vec<String>> {
    let Some(memory) = connection.get_memory(memory_id)? else {
        return Err(conflict_malformed(format!(
            "cannot expire missing memory {memory_id}"
        )));
    };
    if memory.workspace_id != workspace_id || !current_memory_at(&memory, Utc::now()) {
        return Err(conflict_malformed(format!(
            "cannot expire non-current or cross-workspace memory {memory_id}"
        )));
    }
    let expires_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    if !connection.expire_memory_valid_to(memory_id, &expires_at)? {
        return Err(conflict_malformed(format!(
            "memory {memory_id} changed before conflict expiration"
        )));
    }
    let audit_id = crate::db::generate_audit_id();
    let mut audit_ids = vec![audit_id.clone()];
    connection.insert_audit(
        &audit_id,
        &crate::db::CreateAuditInput {
            workspace_id: Some(workspace_id.to_owned()),
            actor: actor
                .map(str::to_owned)
                .or_else(|| Some("ee conflict resolve".to_owned())),
            action: crate::db::audit_actions::MEMORY_EXPIRE.to_owned(),
            target_type: Some("memory".to_owned()),
            target_id: Some(memory_id.to_owned()),
            details: Some(
                serde_json::json!({
                    "schema": "ee.audit.memory_expire.v1",
                    "reason": reason,
                    "deletion": "none_valid_to_only",
                    "resolution": "reject_one",
                })
                .to_string(),
            ),
        },
    )?;
    if memory.level == "semantic" {
        if let Some(level_audit_id) = connection
            .apply_memory_level_transition_in_current_transaction(
                memory_id,
                &crate::db::ApplyMemoryLevelTransitionInput {
                    workspace_id: workspace_id.to_owned(),
                    expected_level: Some(memory.level),
                    level: "episodic".to_owned(),
                    updated_at: expires_at.clone(),
                    actor: actor.map(str::to_owned),
                    reason: "time_bound_fact".to_owned(),
                    automatic: true,
                    event: "valid_to.set".to_owned(),
                    evidence_refs: vec![expires_at.clone(), reason.to_owned()],
                    source_action: Some(crate::db::audit_actions::MEMORY_EXPIRE.to_owned()),
                },
            )?
        {
            audit_ids.push(level_audit_id);
        }
    }
    connection.insert_search_index_job(
        &conflict_search_index_job_id(),
        &crate::db::CreateSearchIndexJobInput {
            workspace_id: workspace_id.to_owned(),
            job_type: crate::db::SearchIndexJobType::SingleDocument,
            document_source: Some("memory".to_owned()),
            document_id: Some(memory_id.to_owned()),
            documents_total: 1,
        },
    )?;
    Ok(audit_ids)
}

fn add_tags_in_txn(
    connection: &DbConnection,
    workspace_id: &str,
    memory_id: &str,
    tags: &[String],
    actor: Option<&str>,
) -> crate::db::Result<Vec<String>> {
    let Some(memory) = connection.get_memory(memory_id)? else {
        return Err(conflict_malformed(format!(
            "cannot tag missing memory {memory_id}"
        )));
    };
    if memory.workspace_id != workspace_id || !current_memory_at(&memory, Utc::now()) {
        return Err(conflict_malformed(format!(
            "cannot tag non-current or cross-workspace memory {memory_id}"
        )));
    }
    let current = connection.get_memory_tags(memory_id)?;
    let current_set: BTreeSet<&str> = current.iter().map(String::as_str).collect();
    let added = tags
        .iter()
        .filter(|tag| !current_set.contains(tag.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if added.is_empty() {
        return Ok(Vec::new());
    }
    connection.add_memory_tags(memory_id, &added)?;
    let next = connection.get_memory_tags(memory_id)?;
    let audit_id = crate::db::generate_audit_id();
    connection.insert_audit(
        &audit_id,
        &crate::db::CreateAuditInput {
            workspace_id: Some(workspace_id.to_owned()),
            actor: actor
                .map(str::to_owned)
                .or_else(|| Some("ee conflict resolve".to_owned())),
            action: crate::db::audit_actions::MEMORY_TAG_ADD.to_owned(),
            target_type: Some("memory".to_owned()),
            target_id: Some(memory_id.to_owned()),
            details: Some(
                serde_json::json!({
                    "schema": "ee.audit.memory_tags.v1",
                    "previous_tags": current,
                    "tags": next,
                    "added_tags": added,
                    "removed_tags": [],
                    "resolution": "scope_split",
                })
                .to_string(),
            ),
        },
    )?;
    connection.insert_search_index_job(
        &conflict_search_index_job_id(),
        &crate::db::CreateSearchIndexJobInput {
            workspace_id: workspace_id.to_owned(),
            job_type: crate::db::SearchIndexJobType::SingleDocument,
            document_source: Some("memory".to_owned()),
            document_id: Some(memory_id.to_owned()),
            documents_total: 1,
        },
    )?;
    Ok(vec![audit_id])
}

fn create_link_in_txn(
    connection: &DbConnection,
    workspace_id: &str,
    plan: &ConflictResolutionPlan,
    from: &str,
    to: &str,
    relation: &str,
    metadata_json: Option<&str>,
    actor: Option<&str>,
) -> crate::db::Result<Vec<String>> {
    let relation = MemoryLinkRelation::parse(relation)
        .ok_or_else(|| conflict_malformed(format!("unknown link relation {relation}")))?;
    let (Some(source), Some(target)) = (connection.get_memory(from)?, connection.get_memory(to)?)
    else {
        return Err(conflict_malformed("cannot link missing conflict memories"));
    };
    if source.workspace_id != workspace_id
        || target.workspace_id != workspace_id
        || !current_memory_at(&source, Utc::now())
        || !current_memory_at(&target, Utc::now())
    {
        return Err(conflict_malformed(
            "cannot link non-current or cross-workspace memories",
        ));
    }
    let existing = connection
        .get_memory_link_by_edge(from, to, relation)?
        .or(connection.get_memory_link_by_edge(to, from, relation)?);
    if existing.is_some() {
        return Ok(Vec::new());
    }
    let link_id = conflict_memory_link_id();
    let audit_id = crate::db::generate_audit_id();
    connection.insert_memory_link(
        &link_id,
        &crate::db::CreateMemoryLinkInput {
            src_memory_id: from.to_owned(),
            dst_memory_id: to.to_owned(),
            relation,
            weight: 1.0,
            confidence: 1.0,
            directed: matches!(relation, MemoryLinkRelation::Supersedes),
            evidence_count: 1,
            last_reinforced_at: None,
            source: MemoryLinkSource::Agent,
            created_by: actor
                .map(str::to_owned)
                .or_else(|| Some("ee conflict resolve".to_owned())),
            metadata_json: metadata_json.map(str::to_owned),
        },
    )?;
    connection.insert_audit(
        &audit_id,
        &crate::db::CreateAuditInput {
            workspace_id: Some(workspace_id.to_owned()),
            actor: actor.map(str::to_owned).or_else(|| Some("ee conflict resolve".to_owned())),
            action: crate::db::audit_actions::MEMORY_LINK_CREATE.to_owned(),
            target_type: Some("memory_link".to_owned()),
            target_id: Some(link_id),
            details: Some(
                serde_json::json!({
                    "schema": "ee.audit.memory_link.v1",
                    "sourceMemoryId": from,
                    "targetMemoryId": to,
                    "relation": relation.as_str(),
                    "directed": matches!(relation, MemoryLinkRelation::Supersedes),
                    "resolution": plan.verb.as_str(),
                    "metadata": metadata_json.and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok()),
                })
                .to_string(),
            ),
        },
    )?;
    Ok(vec![audit_id])
}

fn record_decision_in_txn(
    connection: &DbConnection,
    workspace_id: &str,
    plan: &ConflictResolutionPlan,
    topic: &str,
    chosen: &str,
    alternatives: &[String],
    supersedes: Option<&str>,
    reason: &str,
    actor: Option<&str>,
    write: &crate::core::memory::PreparedRememberTxnWrite,
) -> crate::db::Result<ResolutionActionResult> {
    if write.workspace_id() != workspace_id {
        return Err(conflict_malformed(format!(
            "prepared conflict decision belongs to workspace {}, expected {workspace_id}",
            write.workspace_id()
        )));
    }
    crate::core::memory::record_prepared_remember_txn_write_in_txn(connection, write)?;
    let mut audit_ids = vec![write.audit_id().to_owned()];
    if let Some(loser_id) = supersedes {
        let metadata = serde_json::json!({
            "schema": "ee.conflict.supersede.v1",
            "conflictId": plan.conflict_id,
            "topic": topic,
            "reason": reason,
        })
        .to_string();
        audit_ids.extend(create_link_in_txn(
            connection,
            workspace_id,
            plan,
            write.memory_id(),
            loser_id,
            "supersedes",
            Some(&metadata),
            actor,
        )?);
        audit_ids.extend(expire_memory_in_txn(
            connection,
            workspace_id,
            loser_id,
            &format!("superseded by conflict decision {}", write.memory_id()),
            actor,
        )?);
    }
    let _ = chosen;
    let _ = alternatives;
    Ok(ResolutionActionResult {
        action: "recordDecision".to_owned(),
        audit_ids,
        created_memory_id: Some(write.memory_id().to_owned()),
    })
}

fn execute_action_in_txn(
    connection: &DbConnection,
    workspace_id: &str,
    plan: &ConflictResolutionPlan,
    action: &PlannedResolutionAction,
    decision_write: Option<&crate::core::memory::PreparedRememberTxnWrite>,
    reason: &str,
    actor: Option<&str>,
) -> crate::db::Result<ResolutionActionResult> {
    match action {
        PlannedResolutionAction::RecordDecision {
            topic,
            chosen,
            alternatives,
            supersedes,
        } => record_decision_in_txn(
            connection,
            workspace_id,
            plan,
            topic,
            chosen,
            alternatives,
            supersedes.as_deref(),
            reason,
            actor,
            decision_write.ok_or_else(|| conflict_malformed("missing prepared decision write"))?,
        ),
        PlannedResolutionAction::ExpireMemory { memory_id, reason } => Ok(ResolutionActionResult {
            action: "expireMemory".to_owned(),
            audit_ids: expire_memory_in_txn(connection, workspace_id, memory_id, reason, actor)?,
            created_memory_id: None,
        }),
        PlannedResolutionAction::CreateLink {
            from,
            to,
            relation,
            metadata_json,
        } => Ok(ResolutionActionResult {
            action: "createLink".to_owned(),
            audit_ids: create_link_in_txn(
                connection,
                workspace_id,
                plan,
                from,
                to,
                relation,
                metadata_json.as_deref(),
                actor,
            )?,
            created_memory_id: None,
        }),
        PlannedResolutionAction::AddTags { memory_id, tags } => Ok(ResolutionActionResult {
            action: "addTags".to_owned(),
            audit_ids: add_tags_in_txn(connection, workspace_id, memory_id, tags, actor)?,
            created_memory_id: None,
        }),
    }
}

enum ConflictTransactionOutcome {
    Applied(Vec<ResolutionActionResult>),
    Replayed(ConflictOperationReceipt),
    Stale,
}

pub fn execute_conflict_resolution_idempotent(
    workspace: &Path,
    database_path: &Path,
    operation_id: &str,
    plan: &ConflictResolutionPlan,
    reason: &str,
    actor: Option<&str>,
) -> Result<ConflictExecutionReport, DomainError> {
    let connection = open_conflict_database(database_path)?;
    let workspace_id = crate::core::memory::workspace_id_for_database(&connection, workspace);

    if let Some(receipt) = read_operation_receipt_db(&connection, operation_id, &workspace_id)
        .map_err(conflict_db_error)?
    {
        ensure_receipt_matches_request(&receipt, plan, reason, actor).map_err(conflict_db_error)?;
        return Ok(ConflictExecutionReport {
            operation_id: receipt.operation_id,
            replayed: true,
            results: receipt.results,
        });
    }

    let mut prepared_writes = Vec::new();
    for action in &plan.actions {
        if let PlannedResolutionAction::RecordDecision {
            topic,
            chosen,
            alternatives,
            supersedes,
        } = action
        {
            prepared_writes.push(prepare_conflict_decision_write(
                &connection,
                workspace,
                database_path,
                plan,
                topic,
                chosen,
                alternatives,
                reason,
                supersedes.as_deref(),
            )?);
        }
    }

    let tx_outcome = connection
        .with_transaction(|| {
            if let Some(receipt) =
                read_operation_receipt_db(&connection, operation_id, &workspace_id)?
            {
                ensure_receipt_matches_request(&receipt, plan, reason, actor)?;
                return Ok(ConflictTransactionOutcome::Replayed(receipt));
            }
            if !current_pair_matches(&connection, &workspace_id, plan)? {
                return Ok(ConflictTransactionOutcome::Stale);
            }

            let mut decision_writes = prepared_writes.into_iter();
            let mut results = Vec::with_capacity(plan.actions.len());
            for action in &plan.actions {
                let write = matches!(action, PlannedResolutionAction::RecordDecision { .. })
                    .then(|| decision_writes.next())
                    .flatten();
                results.push(execute_action_in_txn(
                    &connection,
                    &workspace_id,
                    plan,
                    action,
                    write.as_ref(),
                    reason,
                    actor,
                )?);
            }
            if decision_writes.next().is_some() {
                return Err(conflict_malformed("unused prepared decision write"));
            }
            let receipt = ConflictOperationReceipt {
                schema: CONFLICT_OPERATION_RECEIPT_SCHEMA.to_owned(),
                operation_id: operation_id.to_owned(),
                workspace_id: workspace_id.clone(),
                reason: reason.to_owned(),
                actor: actor.map(str::to_owned),
                plan: plan.clone(),
                results: results.clone(),
            };
            connection.insert_audit(
                operation_id,
                &crate::db::CreateAuditInput {
                    workspace_id: Some(workspace_id.clone()),
                    actor: actor.map(str::to_owned),
                    action: CONFLICT_OPERATION_AUDIT_ACTION.to_owned(),
                    target_type: Some("conflict_resolution".to_owned()),
                    target_id: Some(plan.conflict_id.clone()),
                    details: Some(
                        serde_json::to_string(&receipt)
                            .expect("conflict operation receipt is serializable"),
                    ),
                },
            )?;
            Ok(ConflictTransactionOutcome::Applied(results))
        })
        .map_err(conflict_db_error)?;

    match tx_outcome {
        ConflictTransactionOutcome::Applied(results) => Ok(ConflictExecutionReport {
            operation_id: operation_id.to_owned(),
            replayed: false,
            results,
        }),
        ConflictTransactionOutcome::Replayed(receipt) => Ok(ConflictExecutionReport {
            operation_id: receipt.operation_id,
            replayed: true,
            results: receipt.results,
        }),
        ConflictTransactionOutcome::Stale => Err(DomainError::UsageCodeWithDetails {
            code: "conflict_resolve_stale_surface",
            message: format!(
                "({}, {}) is not a pair on the CURRENT conflict surface; workspace state moved before apply.",
                plan.memory_a, plan.memory_b
            ),
            repair: Some(
                "ee conflict explain <memory-id> --json  # re-orient on the live surface"
                    .to_owned(),
            ),
            details_json: serde_json::json!({
                "memoryA": plan.memory_a,
                "memoryB": plan.memory_b,
                "operationId": operation_id,
            })
            .to_string(),
        }),
    }
}

pub fn execute_conflict_resolution(
    workspace: &Path,
    database_path: &Path,
    plan: &ConflictResolutionPlan,
    reason: &str,
    actor: Option<&str>,
) -> Result<Vec<ResolutionActionResult>, DomainError> {
    let connection = open_conflict_database(database_path)?;
    let workspace_id = crate::core::memory::workspace_id_for_database(&connection, workspace);
    let operation_id = operation_id_from_json(&serde_json::json!({
        "schema": "ee.conflict.resolve.plan.v1",
        "workspaceId": workspace_id,
        "plan": plan,
        "reason": reason,
        "actor": actor,
    }));
    execute_conflict_resolution_idempotent(
        workspace,
        database_path,
        &operation_id,
        plan,
        reason,
        actor,
    )
    .map(|report| report.results)
}

/// `ee conflict list`
#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct ConflictListArgs {}

/// `ee conflict explain <MEMORY_ID>`
#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct ConflictExplainArgs {
    /// Memory id whose conflicts should be explained.
    #[arg(value_name = "MEMORY_ID")]
    pub memory_id: String,
}

/// `ee conflict cluster`
#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct ConflictClusterArgs {}

fn open_workspace_db(workspace: &Path) -> Result<DbConnection, DomainError> {
    let database_path = workspace.join(".ee").join("ee.db");
    if !database_path.exists() {
        return Err(DomainError::Storage {
            message: format!("No workspace database at {}.", database_path.display()),
            repair: Some("Run `ee init --workspace . --json` first.".to_owned()),
        });
    }
    DbConnection::open_file(&database_path).map_err(|error| DomainError::Storage {
        message: format!("Failed to open workspace database: {error}"),
        repair: Some("Run `ee doctor --workspace . --json`.".to_owned()),
    })
}

/// Build the full read-only conflict surface for a workspace.
pub fn build_conflict_surface(workspace: &Path) -> Result<ConflictSurface, DomainError> {
    let connection = open_workspace_db(workspace)?;
    Ok(assemble_conflict_surface(
        &connection,
        ContradictionDetectionConfig::default(),
    ))
}

/// Build the surface filtered to the conflicts implicating one memory
/// (`ee conflict explain <memory_id>`).
pub fn build_conflict_surface_for_memory(
    workspace: &Path,
    memory_id: &str,
) -> Result<ConflictSurface, DomainError> {
    Ok(build_conflict_surface(workspace)?.focused_on(memory_id))
}

/// Render the `ee.response.v2` envelope wrapping the `ee.conflict.v1` surface.
/// The same stable data schema is emitted for list/explain/cluster (explain is
/// pre-filtered); subcommands differ in the human rendering only.
#[must_use]
pub fn render_conflict_json(surface: &ConflictSurface) -> String {
    serde_json::json!({
        "schema": RESPONSE_SCHEMA_V2,
        "success": true,
        "data": surface,
        "degraded": [],
    })
    .to_string()
}

fn truncate_body(content: &str) -> String {
    const MAX: usize = 72;
    let oneline = content.replace('\n', " ");
    if oneline.chars().count() <= MAX {
        oneline
    } else {
        let kept: String = oneline.chars().take(MAX).collect();
        format!("{kept}…")
    }
}

/// Compact human-readable summary, emphasizing pairs (list/explain) or clusters.
#[must_use]
pub fn render_conflict_human(surface: &ConflictSurface, command: &ConflictCommand) -> String {
    let mut out = String::new();
    match command {
        ConflictCommand::Cluster(_) => {
            out.push_str(&format!(
                "Contradiction clusters: {}\n",
                surface.clusters.len()
            ));
            for cluster in &surface.clusters {
                out.push_str(&format!(
                    "  - cluster {} ({:?}, size {}): centrality {}, load-bearing {}m, score {:.3}\n",
                    cluster.louvain_id,
                    cluster.severity,
                    cluster.size,
                    cluster.centrality,
                    cluster.load_bearing_milli,
                    cluster.rank_score,
                ));
            }
        }
        _ => {
            out.push_str(&format!("Conflicting pairs: {}\n", surface.pairs.len()));
            for pair in &surface.pairs {
                out.push_str(&format!(
                    "  - {} [{}] prefers side {} ({})\n      A {}: {}\n      B {}: {}\n",
                    pair.conflict_id,
                    pair.signal,
                    pair.preferred_side,
                    pair.preferred_reason,
                    pair.memory_a.id,
                    truncate_body(&pair.memory_a.content),
                    pair.memory_b.id,
                    truncate_body(&pair.memory_b.content),
                ));
            }
        }
    }
    if !surface.deferred_signals.is_empty() {
        out.push_str(&format!(
            "Deferred signal kinds (not yet gathered): {}\n",
            surface.deferred_signals.join(", ")
        ));
    }
    if !surface.degraded.is_empty() {
        out.push_str(&format!("Degraded: {}\n", surface.degraded.join("; ")));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::thread;

    use super::{
        CONFLICT_OPERATION_AUDIT_ACTION, ConflictCommand, ConflictExecutionReport,
        ConflictListArgs, ConflictResolutionPlan, PlannedResolutionAction, build_conflict_surface,
        conflict_operation_id, execute_conflict_resolution_idempotent, render_conflict_human,
        render_conflict_json, truncate_body,
    };
    use crate::core::contradiction_detect::{
        CONFLICT_SURFACE_SCHEMA_V1, ConflictSurface, ResolveVerb,
    };
    use crate::core::workspace::stable_workspace_id;
    use crate::db::{
        CreateMemoryInput, CreateMemoryLinkInput, CreateWorkspaceInput, DbConnection,
        MemoryLinkRelation, MemoryLinkSource,
    };

    const MEMORY_A: &str = "mem_00000000000000000000000001";
    const MEMORY_B: &str = "mem_00000000000000000000000002";
    const LINK_ID: &str = "link_00000000000000000000000001";

    struct ConflictFixture {
        _temp: tempfile::TempDir,
        workspace: PathBuf,
        database: PathBuf,
        workspace_id: String,
    }

    fn fixture() -> ConflictFixture {
        let temp = tempfile::tempdir().expect("fixture tempdir");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("fixture workspace");
        std::fs::create_dir(workspace.join(".ee")).expect("fixture ee directory");
        let database = workspace.join(".ee").join("ee.db");
        let connection = DbConnection::open_file(&database).expect("fixture database");
        connection.migrate().expect("fixture migration");
        let canonical = workspace
            .canonicalize()
            .expect("canonical fixture workspace");
        let workspace_id = stable_workspace_id(&canonical);
        connection
            .insert_workspace(
                &workspace_id,
                &CreateWorkspaceInput {
                    path: canonical.to_string_lossy().into_owned(),
                    name: Some("conflict transaction fixture".to_owned()),
                },
            )
            .expect("fixture workspace row");
        for (id, content) in [(MEMORY_A, "claim A"), (MEMORY_B, "claim B")] {
            connection
                .insert_memory(
                    id,
                    &CreateMemoryInput {
                        workspace_id: workspace_id.clone(),
                        level: "semantic".to_owned(),
                        kind: "fact".to_owned(),
                        content: content.to_owned(),
                        workflow_id: None,
                        confidence: 0.9,
                        utility: 0.8,
                        importance: 0.7,
                        provenance_uri: None,
                        trust_class: "agent_assertion".to_owned(),
                        trust_subclass: None,
                        tags: Vec::new(),
                        valid_from: None,
                        valid_to: None,
                    },
                )
                .expect("fixture memory row");
        }
        connection
            .insert_memory_link(
                LINK_ID,
                &CreateMemoryLinkInput {
                    src_memory_id: MEMORY_A.to_owned(),
                    dst_memory_id: MEMORY_B.to_owned(),
                    relation: MemoryLinkRelation::Contradicts,
                    weight: 1.0,
                    confidence: 1.0,
                    directed: false,
                    evidence_count: 1,
                    last_reinforced_at: None,
                    source: MemoryLinkSource::Agent,
                    created_by: Some("conflict transaction fixture".to_owned()),
                    metadata_json: None,
                },
            )
            .expect("fixture contradiction link");
        drop(connection);
        ConflictFixture {
            _temp: temp,
            workspace,
            database,
            workspace_id,
        }
    }

    fn live_conflict_id(fixture: &ConflictFixture) -> String {
        build_conflict_surface(&fixture.workspace)
            .expect("fixture conflict surface")
            .pairs
            .first()
            .expect("fixture conflict pair")
            .conflict_id
            .clone()
    }

    fn both_valid_plan(conflict_id: String) -> ConflictResolutionPlan {
        ConflictResolutionPlan {
            conflict_id: conflict_id.clone(),
            verb: ResolveVerb::BothValid,
            memory_a: MEMORY_A.to_owned(),
            memory_b: MEMORY_B.to_owned(),
            keep: None,
            lose: None,
            actions: vec![
                PlannedResolutionAction::CreateLink {
                    from: MEMORY_A.to_owned(),
                    to: MEMORY_B.to_owned(),
                    relation: "related".to_owned(),
                    metadata_json: Some(
                        serde_json::json!({
                            "resolution": "both_valid",
                            "conflictId": conflict_id,
                        })
                        .to_string(),
                    ),
                },
                PlannedResolutionAction::RecordDecision {
                    topic: format!("conflict:{conflict_id}"),
                    chosen: "both-valid: retain both claims".to_owned(),
                    alternatives: vec![
                        format!("keep only {MEMORY_A}"),
                        format!("keep only {MEMORY_B}"),
                    ],
                    supersedes: None,
                },
            ],
        }
    }

    fn operation_id(fixture: &ConflictFixture, verb: &str) -> String {
        conflict_operation_id(
            &fixture.workspace,
            &fixture.database,
            MEMORY_A,
            MEMORY_B,
            verb,
            None,
            "fixture rationale",
            &[],
            &[],
            Some("fixture-test"),
        )
        .expect("fixture operation id")
    }

    fn operation_id_with_scopes(fixture: &ConflictFixture) -> String {
        conflict_operation_id(
            &fixture.workspace,
            &fixture.database,
            MEMORY_A,
            MEMORY_B,
            "scope-split",
            None,
            "fixture rationale",
            &["scope-a".to_owned()],
            &["scope-b".to_owned()],
            Some("fixture-test"),
        )
        .expect("fixture scoped operation id")
    }

    fn scope_split_plan(conflict_id: String) -> ConflictResolutionPlan {
        ConflictResolutionPlan {
            conflict_id: conflict_id.clone(),
            verb: ResolveVerb::ScopeSplit,
            memory_a: MEMORY_A.to_owned(),
            memory_b: MEMORY_B.to_owned(),
            keep: None,
            lose: None,
            actions: vec![
                PlannedResolutionAction::AddTags {
                    memory_id: MEMORY_A.to_owned(),
                    tags: vec!["scope-a".to_owned()],
                },
                PlannedResolutionAction::AddTags {
                    memory_id: MEMORY_B.to_owned(),
                    tags: vec!["scope-b".to_owned()],
                },
                PlannedResolutionAction::CreateLink {
                    from: MEMORY_A.to_owned(),
                    to: MEMORY_B.to_owned(),
                    relation: "related".to_owned(),
                    metadata_json: Some(
                        serde_json::json!({
                            "resolution": "scope_split",
                            "conflictId": conflict_id,
                            "scopeA": ["scope-a"],
                            "scopeB": ["scope-b"],
                        })
                        .to_string(),
                    ),
                },
                PlannedResolutionAction::RecordDecision {
                    topic: format!("conflict:{conflict_id}"),
                    chosen: format!(
                        "scope-split: {MEMORY_A} -> [scope-a]; {MEMORY_B} -> [scope-b]"
                    ),
                    alternatives: vec![
                        format!("scope A: {MEMORY_A}"),
                        format!("scope B: {MEMORY_B}"),
                    ],
                    supersedes: None,
                },
            ],
        }
    }

    fn reject_one_plan(conflict_id: String) -> ConflictResolutionPlan {
        ConflictResolutionPlan {
            conflict_id: conflict_id.clone(),
            verb: ResolveVerb::RejectOne,
            memory_a: MEMORY_A.to_owned(),
            memory_b: MEMORY_B.to_owned(),
            keep: Some(MEMORY_A.to_owned()),
            lose: Some(MEMORY_B.to_owned()),
            actions: vec![
                PlannedResolutionAction::ExpireMemory {
                    memory_id: MEMORY_B.to_owned(),
                    reason: "fixture rejection".to_owned(),
                },
                PlannedResolutionAction::RecordDecision {
                    topic: format!("conflict:{conflict_id}"),
                    chosen: format!("keep {MEMORY_A}; reject the other side"),
                    alternatives: vec![format!("keep only {MEMORY_B}")],
                    supersedes: None,
                },
            ],
        }
    }

    fn empty_surface() -> ConflictSurface {
        ConflictSurface {
            schema: CONFLICT_SURFACE_SCHEMA_V1,
            pairs: Vec::new(),
            clusters: Vec::new(),
            explicit_edge_count: 0,
            gathered_signals: vec!["contradiction_link".to_owned()],
            deferred_signals: vec!["validity_window_overlap".to_owned()],
            fuzzy_near_conflict_skipped: false,
            degraded: Vec::new(),
        }
    }

    #[test]
    fn human_render_reports_zero_pairs_and_deferred_kinds() {
        let surface = empty_surface();
        let text = render_conflict_human(&surface, &ConflictCommand::List(ConflictListArgs {}));
        assert!(text.contains("Conflicting pairs: 0"));
        // No-silent-cap: deferred signal kinds are visible even with no pairs.
        assert!(text.contains("validity_window_overlap"));
    }

    #[test]
    fn truncate_body_collapses_newlines_and_caps_length() {
        let body = "line one\nline two";
        assert_eq!(truncate_body(body), "line one line two");
        let long = "x".repeat(200);
        let truncated = truncate_body(&long);
        assert!(truncated.chars().count() <= 73, "capped with ellipsis");
        assert!(truncated.ends_with('…'));
    }

    #[test]
    fn conflict_json_envelope_includes_clean_degraded_array() {
        let surface = empty_surface();
        let raw = render_conflict_json(&surface);
        let envelope: serde_json::Value =
            serde_json::from_str(&raw).expect("conflict json envelope");

        assert_eq!(envelope["schema"], crate::models::RESPONSE_SCHEMA_V2);
        assert_eq!(envelope["success"], true);
        assert_eq!(envelope["data"]["schema"], CONFLICT_SURFACE_SCHEMA_V1);
        assert_eq!(envelope["degraded"], serde_json::json!([]));
    }

    #[test]
    fn response_loss_replays_receipt_after_pair_leaves_surface() {
        let fixture = fixture();
        let plan = both_valid_plan(live_conflict_id(&fixture));
        let operation_id = operation_id(&fixture, "both-valid");
        let first = execute_conflict_resolution_idempotent(
            &fixture.workspace,
            &fixture.database,
            &operation_id,
            &plan,
            "fixture rationale",
            Some("fixture-test"),
        )
        .expect("first conflict apply");
        assert!(!first.replayed);
        assert_eq!(first.operation_id, operation_id);

        let second = execute_conflict_resolution_idempotent(
            &fixture.workspace,
            &fixture.database,
            &operation_id,
            &plan,
            "fixture rationale",
            Some("fixture-test"),
        )
        .expect("replayed conflict apply");
        assert!(second.replayed);
        assert_eq!(
            second,
            ConflictExecutionReport {
                operation_id: operation_id.clone(),
                replayed: true,
                results: first.results.clone(),
            }
        );

        let connection = DbConnection::open_file(&fixture.database).expect("reopen fixture");
        let receipt = connection
            .get_audit(&operation_id)
            .expect("receipt query")
            .expect("operation receipt");
        assert_eq!(receipt.action, CONFLICT_OPERATION_AUDIT_ACTION);
        assert_eq!(
            receipt.workspace_id.as_deref(),
            Some(fixture.workspace_id.as_str())
        );
        assert_eq!(
            connection
                .list_audit_entries(Some(&fixture.workspace_id), None)
                .expect("audit listing")
                .iter()
                .filter(|entry| entry.action == CONFLICT_OPERATION_AUDIT_ACTION)
                .count(),
            1
        );
        assert!(
            build_conflict_surface(&fixture.workspace)
                .expect("post-resolution surface")
                .pairs
                .is_empty(),
            "the durable both-valid marker must remove the pair from the current surface"
        );
    }

    #[test]
    fn scope_split_tags_both_sides_and_removes_contradiction_surface() {
        let fixture = fixture();
        let plan = scope_split_plan(live_conflict_id(&fixture));
        let operation_id = operation_id_with_scopes(&fixture);
        let report = execute_conflict_resolution_idempotent(
            &fixture.workspace,
            &fixture.database,
            &operation_id,
            &plan,
            "fixture rationale",
            Some("fixture-test"),
        )
        .expect("scope split apply");
        assert!(!report.replayed);

        let connection = DbConnection::open_file(&fixture.database).expect("reopen fixture");
        assert_eq!(
            connection.get_memory_tags(MEMORY_A).expect("A tags"),
            vec!["scope-a".to_owned()]
        );
        assert_eq!(
            connection.get_memory_tags(MEMORY_B).expect("B tags"),
            vec!["scope-b".to_owned()]
        );
        assert!(
            build_conflict_surface(&fixture.workspace)
                .expect("post-scope-split surface")
                .pairs
                .is_empty(),
            "scope-split must leave the contradiction edge as history"
        );
        assert!(
            !connection
                .list_search_index_jobs(&fixture.workspace_id, None)
                .expect("index job listing")
                .is_empty()
        );
    }

    #[test]
    fn reject_one_expires_loser_and_records_durable_decision() {
        let fixture = fixture();
        let plan = reject_one_plan(live_conflict_id(&fixture));
        let operation_id = operation_id(&fixture, "reject-one");
        let report = execute_conflict_resolution_idempotent(
            &fixture.workspace,
            &fixture.database,
            &operation_id,
            &plan,
            "fixture rationale",
            Some("fixture-test"),
        )
        .expect("reject-one apply");
        assert!(!report.replayed);
        let connection = DbConnection::open_file(&fixture.database).expect("reopen fixture");
        let loser = connection
            .get_memory(MEMORY_B)
            .expect("loser query")
            .expect("loser memory");
        assert!(loser.valid_to.is_some());
        assert!(loser.tombstoned_at.is_none());
        assert!(
            build_conflict_surface(&fixture.workspace)
                .expect("post-reject surface")
                .pairs
                .is_empty()
        );
        assert_eq!(
            connection
                .get_audit(&operation_id)
                .expect("receipt query")
                .expect("operation receipt")
                .action,
            CONFLICT_OPERATION_AUDIT_ACTION
        );
    }

    #[test]
    fn failed_action_rolls_back_prior_action_and_receipt() {
        let fixture = fixture();
        let plan = ConflictResolutionPlan {
            conflict_id: live_conflict_id(&fixture),
            verb: ResolveVerb::ScopeSplit,
            memory_a: MEMORY_A.to_owned(),
            memory_b: MEMORY_B.to_owned(),
            keep: None,
            lose: None,
            actions: vec![
                PlannedResolutionAction::AddTags {
                    memory_id: MEMORY_A.to_owned(),
                    tags: vec!["rollback-marker".to_owned()],
                },
                PlannedResolutionAction::CreateLink {
                    from: MEMORY_A.to_owned(),
                    to: MEMORY_B.to_owned(),
                    relation: "not-a-memory-relation".to_owned(),
                    metadata_json: None,
                },
            ],
        };
        let operation_id = operation_id(&fixture, "scope-split");
        let error = execute_conflict_resolution_idempotent(
            &fixture.workspace,
            &fixture.database,
            &operation_id,
            &plan,
            "fixture rationale",
            Some("fixture-test"),
        )
        .expect_err("invalid action must fail");
        assert!(error.to_string().contains("unknown link relation"));

        let connection = DbConnection::open_file(&fixture.database).expect("reopen fixture");
        assert!(
            connection
                .get_memory_tags(MEMORY_A)
                .expect("tags query")
                .is_empty()
        );
        assert!(
            connection
                .get_audit(&operation_id)
                .expect("receipt query")
                .is_none()
        );
    }

    #[test]
    fn concurrent_same_operation_has_one_apply_and_one_replay() {
        let fixture = fixture();
        let plan = both_valid_plan(live_conflict_id(&fixture));
        let operation_id = operation_id(&fixture, "both-valid");
        let workspace_a = fixture.workspace.clone();
        let workspace_b = fixture.workspace.clone();
        let database_a = fixture.database.clone();
        let database_b = fixture.database.clone();
        let plan_a = plan.clone();
        let plan_b = plan.clone();
        let operation_a = operation_id.clone();
        let operation_b = operation_id.clone();
        let first = thread::spawn(move || {
            execute_conflict_resolution_idempotent(
                &workspace_a,
                &database_a,
                &operation_a,
                &plan_a,
                "fixture rationale",
                Some("fixture-test"),
            )
        });
        let second = thread::spawn(move || {
            execute_conflict_resolution_idempotent(
                &workspace_b,
                &database_b,
                &operation_b,
                &plan_b,
                "fixture rationale",
                Some("fixture-test"),
            )
        });
        let reports = [
            first
                .join()
                .expect("first operation thread")
                .expect("first operation"),
            second
                .join()
                .expect("second operation thread")
                .expect("second operation"),
        ];
        assert_eq!(reports.iter().filter(|report| !report.replayed).count(), 1);
        assert_eq!(reports.iter().filter(|report| report.replayed).count(), 1);
        assert_eq!(reports[0].results, reports[1].results);

        let connection = DbConnection::open_file(&fixture.database).expect("reopen fixture");
        assert_eq!(
            connection
                .list_audit_entries(Some(&fixture.workspace_id), None)
                .expect("audit listing")
                .iter()
                .filter(|entry| entry.action == CONFLICT_OPERATION_AUDIT_ACTION)
                .count(),
            1
        );
    }
}
