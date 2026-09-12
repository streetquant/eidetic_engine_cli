//! bd-1n0np.7.2 — contradiction detection from explicit DB evidence.
//!
//! Detects contradiction clusters from *explicit* signals only — the discipline
//! both wizards agreed on (explicit-evidence-FIRST). A [`ConflictEdge`] is an
//! already-extracted relationship between two memories that the store records
//! durably: a contradiction/supersession link, an overlapping validity window, a
//! duplicate-but-divergent pair, a trust/outcome split, or repeated co-selection.
//! The caller gathers these from the DB; this module is the pure detector.
//!
//! The explicit edges form a contradiction graph, and we **reuse**
//! `crate::graph::health` (k-truss + Louvain via
//! [`detect_contradiction_clusters_with_policy`]) — the same machinery
//! structural health uses — to find the clusters. Each cluster is then ranked by
//! *centrality* (conflict-edge degree over its members) and *load-bearing*
//! weight (the strength of the signals implicating it), so the most urgent,
//! most-connected contradictions sort first.
//!
//! The fuzzy near-conflict detector (embedding opposition) is the
//! false-positive-prone part; it stays **opt-in** behind
//! [`ContradictionDetectionConfig::include_fuzzy_near_conflict`] and is *not*
//! implemented in v1 — when requested, the report flags it as skipped (no silent
//! cap) rather than silently widening to fuzzy matches. The explicit graph is the
//! gate.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use fnx_classes::Graph;
use fnx_runtime::CompatibilityMode;

use serde::{Deserialize, Serialize};

use crate::core::contradiction_guard::{
    ContradictionPrecedence, authority_subclass_rank, confidence_rank_milli,
    decide_contradiction_survivor_with_precedence, recency_rank, verification_status_rank,
};
use crate::db::{DbConnection, MemoryLinkRelation, StoredMemory};
use crate::graph::health::{
    ContradictionCluster, ContradictionClusterPolicy, ContradictionSeverity,
    detect_contradiction_clusters_with_policy,
};
use crate::models::TrustClass;

/// A conflict signal between two memories. Link-backed variants are explicit DB
/// evidence; `BodyContradiction` is a conservative exact-body inference kept
/// separate so callers can distinguish its evidence source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ExplicitConflictSignal {
    /// A direct `contradicts` link between the two memories.
    ContradictionLink,
    /// One memory supersedes the other (supersession link).
    Supersession,
    /// Their validity windows overlap while asserting different things.
    ValidityWindowOverlap,
    /// Near-duplicate content that nonetheless diverges.
    DuplicateDivergent,
    /// Their trust / outcome evidence points in opposite directions.
    TrustOutcomeSplit,
    /// They are repeatedly co-selected into the same packs (co-occurrence).
    RepeatedCoSelection,
    /// Opposite explicit polarities for one exact entity/claim identity.
    BodyContradiction,
}

impl ExplicitConflictSignal {
    /// Stable snake_case form for JSON / edge labels.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContradictionLink => "contradiction_link",
            Self::Supersession => "supersession",
            Self::ValidityWindowOverlap => "validity_window_overlap",
            Self::DuplicateDivergent => "duplicate_divergent",
            Self::TrustOutcomeSplit => "trust_outcome_split",
            Self::RepeatedCoSelection => "repeated_co_selection",
            Self::BodyContradiction => "body_contradiction",
        }
    }

    /// Load-bearing weight (milli-units): how strongly this signal implicates a
    /// genuine contradiction. A direct contradiction link is the heaviest; mere
    /// repeated co-selection is the lightest explicit signal.
    #[must_use]
    pub const fn weight_milli(self) -> u64 {
        match self {
            Self::ContradictionLink => 1000,
            Self::Supersession => 900,
            Self::DuplicateDivergent => 700,
            Self::ValidityWindowOverlap => 600,
            Self::TrustOutcomeSplit => 500,
            Self::RepeatedCoSelection => 300,
            // Inferred body evidence remains below durable contradiction and
            // supersession links, but above weaker deferred signals.
            Self::BodyContradiction => 650,
        }
    }
}

/// One explicit conflict relationship between two memories (the detector input).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictEdge {
    pub memory_a: String,
    pub memory_b: String,
    pub signal: ExplicitConflictSignal,
}

impl ConflictEdge {
    #[must_use]
    pub fn new(memory_a: &str, memory_b: &str, signal: ExplicitConflictSignal) -> Self {
        Self {
            memory_a: memory_a.to_string(),
            memory_b: memory_b.to_string(),
            signal,
        }
    }
}

/// Detector configuration.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ContradictionDetectionConfig {
    /// Optional Louvain density threshold override (forwarded to
    /// [`ContradictionClusterPolicy`]). `None` uses the health default.
    pub density_threshold: Option<f64>,
    /// Opt-in for the fuzzy embedding-opposition detector. Deferred in v1: when
    /// `true`, the report records the fuzzy pass as *skipped* rather than running
    /// the false-positive-prone path.
    pub include_fuzzy_near_conflict: bool,
}

impl Default for ContradictionDetectionConfig {
    fn default() -> Self {
        Self {
            density_threshold: None,
            include_fuzzy_near_conflict: false,
        }
    }
}

/// A contradiction cluster (from health.rs) plus its explicit-evidence ranking.
#[derive(Clone, Debug, PartialEq)]
pub struct RankedContradictionCluster {
    /// The underlying cluster as detected by `graph::health` (k-truss + Louvain).
    pub cluster: ContradictionCluster,
    /// Conflict-edge degree summed over the cluster's exemplar members
    /// (a centrality proxy: how connected the cluster is in the conflict graph).
    pub centrality: u32,
    /// Sum of signal weights (milli) of conflict edges incident to the cluster's
    /// exemplar members — the cluster's load-bearing mass.
    pub load_bearing_milli: u64,
    /// Deterministic composite urgency score; higher sorts first.
    pub rank_score: f64,
}

/// Result of explicit-evidence contradiction detection.
#[derive(Clone, Debug, PartialEq)]
pub struct ContradictionDetectionReport {
    /// Detected clusters, ranked most-urgent first.
    pub clusters: Vec<RankedContradictionCluster>,
    /// Number of distinct (canonicalized) explicit conflict edges considered.
    pub explicit_edge_count: usize,
    /// `true` when the caller requested the fuzzy near-conflict pass but it was
    /// skipped (v1 defers it). Surfaced so the omission is never silent.
    pub fuzzy_near_conflict_skipped: bool,
}

/// Canonicalize an edge to an unordered, trimmed `(low, high)` pair, dropping
/// blanks and self-loops. Returns `None` if the edge is unusable.
fn canonical_pair(edge: &ConflictEdge) -> Option<(String, String)> {
    let a = edge.memory_a.trim();
    let b = edge.memory_b.trim();
    if a.is_empty() || b.is_empty() || a == b {
        return None;
    }
    if a <= b {
        Some((a.to_string(), b.to_string()))
    } else {
        Some((b.to_string(), a.to_string()))
    }
}

/// Polarity recognized by the conservative body pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum BodyClaimPolarity {
    Positive,
    Negative,
}

/// Exact grouping key for a body claim. Entity and claim are required fields;
/// workspace and optional scope prevent cross-context pairings.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct BodyClaimKey {
    workspace_id: String,
    scope: String,
    entity: String,
    claim: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BodyClaim {
    key: BodyClaimKey,
    polarity: BodyClaimPolarity,
}

/// Return the polarity of a recognized opposition token and, for paired values,
/// the canonical positive value to retain in the claim identity.
fn body_claim_polarity_token(token: &str) -> Option<(BodyClaimPolarity, Option<&'static str>)> {
    use BodyClaimPolarity::{Negative, Positive};

    match token {
        "not" | "no" | "never" | "without" | "cannot" | "cant" | "wont" | "dont" | "doesnt"
        | "didnt" | "shouldnt" | "mustnt" | "couldnt" | "wouldnt" | "none" => {
            Some((Negative, None))
        }
        "disabled" | "deactivated" | "inactive" => Some((Negative, Some("enabled"))),
        "off" => Some((Negative, Some("on"))),
        "false" => Some((Negative, Some("true"))),
        "denied" | "denies" | "deny" | "disallowed" | "forbidden" | "forbid" => {
            Some((Negative, Some("allowed")))
        }
        "rejected" | "rejects" | "reject" => Some((Negative, Some("accepted"))),
        "absent" | "missing" | "unavailable" => Some((Negative, Some("present"))),
        "closed" => Some((Negative, Some("open"))),
        "failed" | "fails" | "failure" => Some((Negative, Some("succeeded"))),
        // These are explicit positive counterparts to `never`, `not`, etc. The
        // modal itself is not part of the claim identity.
        "always" | "must" | "should" => Some((Positive, None)),
        "enabled" | "activated" | "active" => Some((Positive, Some("enabled"))),
        "on" => Some((Positive, Some("on"))),
        "true" => Some((Positive, Some("true"))),
        "allowed" | "allows" | "allow" => Some((Positive, Some("allowed"))),
        "accepted" | "accepts" | "accept" => Some((Positive, Some("accepted"))),
        "present" | "available" => Some((Positive, Some("present"))),
        "open" => Some((Positive, Some("open"))),
        "succeeded" | "succeeds" | "success" => Some((Positive, Some("succeeded"))),
        _ => None,
    }
}

fn canonical_body_claim_word(token: &str) -> &str {
    match token {
        "is" | "are" | "was" | "were" | "be" | "been" | "being" => "be",
        "does" | "did" => "do",
        "uses" | "using" | "used" => "use",
        "runs" | "running" | "ran" => "run",
        "requires" | "requiring" | "required" => "require",
        "supports" | "supporting" | "supported" => "support",
        "contains" | "containing" | "contained" => "contain",
        "allows" => "allow",
        "denies" => "deny",
        "accepts" => "accept",
        "succeeds" => "succeed",
        _ => token,
    }
}

fn tokenize_body_claim(content: &str) -> Vec<String> {
    let normalized = content
        .to_lowercase()
        .replace("doesn't", "does not")
        .replace("didn't", "did not")
        .replace("don't", "do not")
        .replace("can't", "cannot")
        .replace("couldn't", "could not")
        .replace("shouldn't", "should not")
        .replace("wouldn't", "would not")
        .replace("mustn't", "must not")
        .replace("isn't", "is not")
        .replace("aren't", "are not")
        .replace("wasn't", "was not")
        .replace("weren't", "were not")
        .replace("won't", "will not");
    let mut tokens = Vec::new();
    let mut current = String::new();
    for character in normalized.chars() {
        if character.is_alphanumeric() || matches!(character, '_' | '-' | ':') {
            current.push(character);
        } else if !current.is_empty() {
            tokens.push(canonical_body_claim_word(&current).to_owned());
            current.clear();
        }
    }
    if !current.is_empty() {
        tokens.push(canonical_body_claim_word(&current).to_owned());
    }
    tokens
}

const BODY_CLAIM_STOP_WORDS: &[&str] = &[
    "a",
    "an",
    "the",
    "this",
    "that",
    "these",
    "those",
    "fact",
    "claim",
    "assertion",
    "statement",
    "memory",
    "rule",
    "decision",
    "convention",
    "note",
    "according",
    "said",
    "says",
    "to",
    "of",
    "in",
    "at",
    "for",
    "from",
    "by",
    "with",
    "as",
    "into",
    "about",
    "and",
    "or",
    "but",
    "be",
    "do",
    "can",
    "could",
    "should",
    "would",
    "may",
    "might",
    "must",
    "shall",
    "will",
    "only",
    "just",
];

fn normalize_body_identity_component(raw: &str) -> String {
    let mut normalized = String::new();
    let mut previous_was_space = false;
    for character in raw.trim().to_lowercase().chars() {
        if character.is_alphanumeric() || matches!(character, '_' | '-' | ':' | '/') {
            normalized.push(character);
            previous_was_space = false;
        } else if !normalized.is_empty() && !previous_was_space {
            normalized.push(' ');
            previous_was_space = true;
        }
    }
    normalized.trim().to_owned()
}

/// Find one explicitly labeled value (`Entity: atlas; Claim: port`). A label
/// must have a boundary and `:`/`=` separator so prose containing “subject” or
/// “claim” cannot accidentally become an identity.
fn extract_body_labeled_field(content: &str, labels: &[&str]) -> Option<String> {
    let lower = content.to_ascii_lowercase();
    for label in labels {
        let mut search_from = 0;
        while let Some(relative) = lower[search_from..].find(label) {
            let start = search_from + relative;
            let before_ok = start == 0
                || (!lower.as_bytes()[start - 1].is_ascii_alphanumeric()
                    && lower.as_bytes()[start - 1] != b'_'
                    && lower.as_bytes()[start - 1] != b'-');
            let mut cursor = start + label.len();
            let after_ok = cursor == lower.len()
                || (!lower.as_bytes()[cursor].is_ascii_alphanumeric()
                    && lower.as_bytes()[cursor] != b'_'
                    && lower.as_bytes()[cursor] != b'-');
            if before_ok && after_ok {
                while cursor < lower.len() && lower.as_bytes()[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
                if cursor < lower.len() && matches!(lower.as_bytes()[cursor], b':' | b'=') {
                    cursor += 1;
                    while cursor < lower.len() && lower.as_bytes()[cursor].is_ascii_whitespace() {
                        cursor += 1;
                    }
                    let mut end = content.len();
                    for (offset, character) in content[cursor..].char_indices() {
                        if matches!(character, ';' | '|' | '\n' | '\r' | ',') {
                            end = cursor + offset;
                            break;
                        }
                        if character == '.'
                            && content[cursor + offset + character.len_utf8()..]
                                .chars()
                                .next()
                                .map_or(true, char::is_whitespace)
                        {
                            end = cursor + offset;
                            break;
                        }
                    }
                    let value = content[cursor..end]
                        .trim()
                        .trim_matches(['"', '\'', '`'])
                        .trim_end_matches(['.', ',']);
                    if !value.is_empty() {
                        return Some(value.to_owned());
                    }
                }
            }
            search_from = start.saturating_add(label.len()).max(search_from + 1);
        }
    }
    None
}

fn body_claim_polarity_marker(raw: &str) -> Option<BodyClaimPolarity> {
    match normalize_body_identity_component(raw).as_str() {
        "positive" | "affirmed" | "affirmative" | "present" | "current" | "true" | "yes"
        | "enabled" | "on" | "support" | "supported" | "allow" | "allowed" => {
            Some(BodyClaimPolarity::Positive)
        }
        "negative" | "negated" | "opposed" | "opposite" | "contradiction" | "conflict"
        | "false" | "no" | "not" | "disabled" | "off" | "deny" | "denied" => {
            Some(BodyClaimPolarity::Negative)
        }
        _ => None,
    }
}

fn claim_identity_and_polarity(claim: &str) -> Option<(String, Option<BodyClaimPolarity>)> {
    use BodyClaimPolarity::{Negative, Positive};
    let mut identity_tokens = Vec::new();
    let mut generic_negative_count = 0_u8;
    let mut value_polarity = None;
    for token in tokenize_body_claim(claim) {
        if let Some((polarity, canonical_value)) = body_claim_polarity_token(&token) {
            if canonical_value.is_none() && polarity == Negative {
                generic_negative_count = generic_negative_count.saturating_add(1);
            }
            if canonical_value.is_some() {
                if let Some(existing) = value_polarity {
                    if existing != polarity {
                        return None;
                    }
                } else {
                    value_polarity = Some(polarity);
                }
            }
            if let Some(canonical_value) = canonical_value {
                identity_tokens.push(canonical_value.to_owned());
            }
            continue;
        }
        if !BODY_CLAIM_STOP_WORDS.contains(&token.as_str()) {
            identity_tokens.push(token);
        }
    }
    if generic_negative_count > 1 {
        return None;
    }
    let polarity = match (generic_negative_count, value_polarity) {
        (0, Some(value)) => Some(value),
        (0, None) => None,
        (1, Some(Negative)) => None,
        (1, Some(Positive)) => Some(Negative),
        (1, None) => Some(Negative),
        // More than one generic negation is ambiguous (for example, "not
        // never"). Keep the inference fail-closed even when the counter has
        // saturated at its upper bound.
        (2_u8..=u8::MAX, _) => None,
    };
    let identity = identity_tokens.join(" ");
    (!identity.is_empty()).then_some((identity, polarity))
}

fn json_string_field(
    object: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
) -> Option<String> {
    names.iter().find_map(|name| {
        object.iter().find_map(|(key, value)| {
            (key.eq_ignore_ascii_case(name))
                .then(|| value.as_str().map(str::to_owned))
                .flatten()
        })
    })
}

fn json_bool_field(
    object: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
) -> Option<bool> {
    names.iter().find_map(|name| {
        object.iter().find_map(|(key, value)| {
            (key.eq_ignore_ascii_case(name))
                .then(|| value.as_bool())
                .flatten()
        })
    })
}

fn json_body_claim_fields(
    content: &str,
) -> Option<(
    String,
    String,
    Option<String>,
    Option<BodyClaimPolarity>,
    bool,
)> {
    let serde_json::Value::Object(object) = serde_json::from_str(content).ok()? else {
        return None;
    };
    let claim_key = object
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("claim_key"))
        .and_then(|(_, value)| value.as_object());
    let entity = json_string_field(&object, &["entity", "entity_id", "entityid", "subject"])
        .or_else(|| {
            claim_key.and_then(|nested| json_string_field(nested, &["subject", "entity"]))
        })?;
    let claim = json_string_field(
        &object,
        &[
            "claim",
            "claim_key",
            "predicate",
            "claim_predicate",
            "claimpredicate",
        ],
    )
    .or_else(|| claim_key.and_then(|nested| json_string_field(nested, &["predicate", "claim"])))?;
    let standard_marker = json_string_field(
        &object,
        &["polarity", "marker", "signal", "status", "state"],
    );
    let opposition_marker = json_string_field(
        &object,
        &["opposition", "negated", "negative", "opposed", "conflict"],
    );
    let bool_marker = json_bool_field(
        &object,
        &[
            "negated",
            "negative",
            "opposed",
            "opposes",
            "conflict",
            "opposition",
        ],
    );
    let (typed_polarity, typed_present) = if let Some(marker) = standard_marker {
        (body_claim_polarity_marker(&marker), true)
    } else if let Some(marker) = opposition_marker {
        (body_opposition_marker(&marker), true)
    } else if let Some(negative) = bool_marker {
        (
            Some(if negative {
                BodyClaimPolarity::Negative
            } else {
                BodyClaimPolarity::Positive
            }),
            true,
        )
    } else {
        (None, false)
    };
    let scope = json_string_field(&object, &["scope", "scope_id", "scopeid"]);
    Some((entity, claim, scope, typed_polarity, typed_present))
}

/// Interpret a marker whose field name itself means opposition. String and
/// boolean encodings are accepted, but unknown values remain unparseable so a
/// malformed marker cannot create a false contradiction.
fn body_opposition_marker(raw: &str) -> Option<BodyClaimPolarity> {
    match normalize_body_identity_component(raw).as_str() {
        "true" | "yes" | "1" => Some(BodyClaimPolarity::Negative),
        "false" | "no" | "0" => Some(BodyClaimPolarity::Positive),
        normalized => body_claim_polarity_marker(normalized),
    }
}

fn text_body_claim_fields(
    content: &str,
) -> Option<(
    String,
    String,
    Option<String>,
    Option<BodyClaimPolarity>,
    bool,
)> {
    let entity =
        extract_body_labeled_field(content, &["entity", "entity_id", "entityid", "subject"])?;
    let claim = extract_body_labeled_field(
        content,
        &[
            "claim",
            "claim_key",
            "predicate",
            "claim_predicate",
            "claimpredicate",
        ],
    )?;
    let scope = extract_body_labeled_field(content, &["scope", "scope_id", "scopeid"]);
    let opposition_marker = extract_body_labeled_field(
        content,
        &["opposition", "negated", "negative", "opposed", "conflict"],
    );
    let standard_marker = extract_body_labeled_field(
        content,
        &["polarity", "marker", "signal", "status", "state"],
    );
    let (typed_polarity, typed_present) = if let Some(marker) = opposition_marker {
        (body_opposition_marker(&marker), true)
    } else if let Some(marker) = standard_marker {
        (body_claim_polarity_marker(&marker), true)
    } else {
        (None, false)
    };
    Some((entity, claim, scope, typed_polarity, typed_present))
}

fn parse_body_claim(memory: &StoredMemory, reference_time: DateTime<Utc>) -> Option<BodyClaim> {
    if memory.id.trim().is_empty()
        || memory.workspace_id.trim().is_empty()
        || memory.tombstoned_at.is_some()
        || !body_memory_is_current(memory, reference_time)
    {
        return None;
    }
    let (entity, claim, scope, typed_polarity, typed_present) =
        json_body_claim_fields(&memory.content)
            .or_else(|| text_body_claim_fields(&memory.content))?;
    if typed_present && typed_polarity.is_none() {
        return None;
    }
    let entity = normalize_body_identity_component(&entity);
    if entity.is_empty() {
        return None;
    }
    let (claim, claim_polarity) = claim_identity_and_polarity(&claim)?;
    let polarity = match (claim_polarity, typed_polarity) {
        (Some(claim), Some(typed)) if claim != typed => return None,
        (Some(claim), _) => claim,
        (_, Some(typed)) => typed,
        // A plain labeled claim is the positive side; a counterpart must still
        // carry explicit negative/opposition evidence to form a pair.
        (None, None) => BodyClaimPolarity::Positive,
    };
    Some(BodyClaim {
        key: BodyClaimKey {
            workspace_id: memory.workspace_id.trim().to_owned(),
            scope: scope
                .as_deref()
                .map(normalize_body_identity_component)
                .unwrap_or_default(),
            entity,
            claim,
        },
        polarity,
    })
}

fn body_memory_is_current(memory: &StoredMemory, reference_time: DateTime<Utc>) -> bool {
    let valid_from = match memory.valid_from.as_deref() {
        Some(raw) => chrono::DateTime::parse_from_rfc3339(raw)
            .ok()
            .map(|value| value.with_timezone(&chrono::Utc)),
        None => None,
    };
    let valid_to = match memory.valid_to.as_deref() {
        Some(raw) => chrono::DateTime::parse_from_rfc3339(raw)
            .ok()
            .map(|value| value.with_timezone(&chrono::Utc)),
        None => None,
    };
    if memory.valid_from.is_some() && valid_from.is_none()
        || memory.valid_to.is_some() && valid_to.is_none()
    {
        return false;
    }
    !valid_from.is_some_and(|start| start > reference_time)
        && !valid_to.is_some_and(|end| end <= reference_time)
}

/// Discover only exact same-workspace/entity/claim pairs with opposite explicit
/// polarity. This is read-only: every original ID remains available to callers,
/// and no body/evidence row is merged, deleted, or rewritten.
#[must_use]
pub fn detect_body_contradiction_pairs(memories: &[StoredMemory]) -> Vec<ConflictEdge> {
    detect_body_contradiction_pairs_at(memories, Utc::now())
}

/// Discover exact body contradictions at a caller-supplied reference time.
///
/// The reference time is threaded through validity checks so historical
/// context/conflict replay cannot silently use the wall clock.
#[must_use]
pub fn detect_body_contradiction_pairs_at(
    memories: &[StoredMemory],
    reference_time: DateTime<Utc>,
) -> Vec<ConflictEdge> {
    let mut grouped: BTreeMap<BodyClaimKey, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    for memory in memories {
        let Some(claim) = parse_body_claim(memory, reference_time) else {
            continue;
        };
        let entry = grouped
            .entry(claim.key)
            .or_insert_with(|| (BTreeSet::new(), BTreeSet::new()));
        match claim.polarity {
            BodyClaimPolarity::Positive => {
                entry.0.insert(memory.id.trim().to_owned());
            }
            BodyClaimPolarity::Negative => {
                entry.1.insert(memory.id.trim().to_owned());
            }
        }
    }
    let mut pairs = BTreeSet::new();
    for (_key, (positive_ids, negative_ids)) in grouped {
        for positive_id in &positive_ids {
            for negative_id in &negative_ids {
                if positive_id != negative_id {
                    let pair = if positive_id < negative_id {
                        (positive_id.clone(), negative_id.clone())
                    } else {
                        (negative_id.clone(), positive_id.clone())
                    };
                    pairs.insert(pair);
                }
            }
        }
    }
    pairs
        .into_iter()
        .map(|(memory_a, memory_b)| {
            ConflictEdge::new(
                &memory_a,
                &memory_b,
                ExplicitConflictSignal::BodyContradiction,
            )
        })
        .collect()
}

/// Detect contradiction clusters from explicit conflict evidence (bd-1n0np.7.2).
///
/// Builds a contradiction graph from the (deduplicated) explicit edges, reuses
/// `graph::health` Louvain/k-truss clustering, then ranks each cluster by
/// centrality + load-bearing weight. Deterministic: edges are canonicalized and
/// deduplicated, and ties break on `louvain_id`.
#[must_use]
pub fn detect_explicit_contradictions(
    edges: &[ConflictEdge],
    config: ContradictionDetectionConfig,
) -> ContradictionDetectionReport {
    // Deduplicate edges to canonical unordered pairs, keeping the heaviest signal
    // weight seen for each pair (a pair backed by multiple signals is stronger).
    let mut pair_weight: BTreeMap<(String, String), u64> = BTreeMap::new();
    for edge in edges {
        if let Some(pair) = canonical_pair(edge) {
            let weight = edge.signal.weight_milli();
            pair_weight
                .entry(pair)
                .and_modify(|w| *w = (*w).max(weight))
                .or_insert(weight);
        }
    }

    // Per-memory conflict degree (centrality proxy) over the deduped edge set.
    let mut degree: BTreeMap<String, u32> = BTreeMap::new();
    for (a, b) in pair_weight.keys() {
        *degree.entry(a.clone()).or_insert(0) += 1;
        *degree.entry(b.clone()).or_insert(0) += 1;
    }

    // Build the contradiction graph (same construction health.rs uses for its
    // `Contradicts` relation graph) and reuse the proven cluster detector.
    let mut graph = Graph::new(CompatibilityMode::Strict);
    for (a, b) in pair_weight.keys() {
        graph.add_node(a);
        graph.add_node(b);
        let _ = graph.extend_edges_unrecorded([(a.as_str(), b.as_str())]);
    }
    let policy = ContradictionClusterPolicy::from_optional_config(config.density_threshold);
    let clusters = detect_contradiction_clusters_with_policy(&graph, policy);

    let mut ranked: Vec<RankedContradictionCluster> = clusters
        .into_iter()
        .map(|cluster| rank_cluster(cluster, &pair_weight, &degree))
        .collect();

    // Most urgent first; deterministic tie-break on louvain_id.
    ranked.sort_by(|left, right| {
        right
            .rank_score
            .partial_cmp(&left.rank_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(left.cluster.louvain_id.cmp(&right.cluster.louvain_id))
    });

    ContradictionDetectionReport {
        clusters: ranked,
        explicit_edge_count: pair_weight.len(),
        fuzzy_near_conflict_skipped: config.include_fuzzy_near_conflict,
    }
}

/// Rank one detected cluster by centrality + load-bearing weight.
fn rank_cluster(
    cluster: ContradictionCluster,
    pair_weight: &BTreeMap<(String, String), u64>,
    degree: &BTreeMap<String, u32>,
) -> RankedContradictionCluster {
    let members: BTreeSet<&String> = cluster.exemplar_memory_ids.iter().collect();

    let centrality: u32 = cluster
        .exemplar_memory_ids
        .iter()
        .map(|id| degree.get(id).copied().unwrap_or(0))
        .sum();

    // Load-bearing mass: each edge incident to a member contributes its weight
    // once (a member set is small, so a linear scan over deduped edges is fine).
    let load_bearing_milli: u64 = pair_weight
        .iter()
        .filter(|((a, b), _)| members.contains(a) || members.contains(b))
        .map(|(_, weight)| *weight)
        .sum();

    // Composite: severity multiplies, density and centrality scale, load-bearing
    // weight (in whole units) lifts. All inputs are deterministic.
    let severity_factor = match cluster.severity {
        crate::graph::health::ContradictionSeverity::Incoherent => 2.0,
        crate::graph::health::ContradictionSeverity::Inconsistent => 1.0,
    };
    let rank_score = severity_factor
        * cluster.density
        * (f64::from(centrality) + 1.0)
        * (1.0 + (load_bearing_milli as f64) / 1000.0);

    RankedContradictionCluster {
        cluster,
        centrality,
        load_bearing_milli,
        rank_score,
    }
}

/// Explicit conflict edges gathered from the database, with an honest record of
/// which signal kinds were covered (bd-1n0np.7.2 DB-gather).
///
/// The `deferred` list is surfaced so a not-yet-gathered signal kind is never
/// silently treated as "no conflict" — the same no-silent-cap discipline the
/// detector uses for its deferred fuzzy pass.
#[derive(Clone, Debug, PartialEq)]
pub struct GatheredConflictEdges {
    /// Conflict edges from durable links, ready to feed the detector.
    pub edges: Vec<ConflictEdge>,
    /// Read-only body-derived edges for exact, same-scope claims with opposite
    /// polarity. Kept separate from link evidence for honest reporting.
    pub automatic_body_edges: Vec<ConflictEdge>,
    /// Explicit signal kinds this gather covered; body-derived edges are
    /// reported separately above.
    pub gathered: Vec<ExplicitConflictSignal>,
    /// Explicit signal kinds deferred to a later DB-gather slice (reported, not
    /// silently dropped).
    pub deferred: Vec<ExplicitConflictSignal>,
    /// Set when a link, workspace, or memory read failed: the gather degrades to
    /// evidence it could read, and the read failure is reported instead of being
    /// swallowed.
    pub read_error: Option<String>,
    /// Canonical pairs a reviewed `both-valid` resolution marked as legitimate
    /// tension (`ee conflict resolve --verb both-valid` writes a `related` link
    /// with `resolution=both_valid` metadata): suppressed from the actionable
    /// pair surface, bd-3a1op.4.
    pub both_valid_resolved: std::collections::BTreeSet<(String, String)>,
    /// Canonical pairs settled by a scope-split resolution. The original
    /// contradiction edge remains durable history, while this marker keeps it
    /// off the actionable surface after both sides receive their scopes.
    pub scope_split_resolved: std::collections::BTreeSet<(String, String)>,
}

impl GatheredConflictEdges {
    /// Return durable-link and body-derived edges in deterministic order.
    #[must_use]
    pub fn all_edges(&self) -> Vec<ConflictEdge> {
        self.edges
            .iter()
            .chain(self.automatic_body_edges.iter())
            .cloned()
            .collect()
    }
}

/// Explicit signal kinds the v1 DB-gather covers (the link-based, least-ambiguous
/// evidence the store records directly).
const GATHERED_SIGNAL_KINDS: [ExplicitConflictSignal; 2] = [
    ExplicitConflictSignal::ContradictionLink,
    ExplicitConflictSignal::Supersession,
];

/// Explicit signal kinds deferred to later DB-gather slices. These require
/// cross-referencing memory rows / feedback events (and are more
/// false-positive-prone), so v1 reports them as not-yet-gathered.
const DEFERRED_SIGNAL_KINDS: [ExplicitConflictSignal; 4] = [
    ExplicitConflictSignal::DuplicateDivergent,
    ExplicitConflictSignal::ValidityWindowOverlap,
    ExplicitConflictSignal::TrustOutcomeSplit,
    ExplicitConflictSignal::RepeatedCoSelection,
];

/// Gather explicit conflict edges from the database (bd-1n0np.7.2 DB-gather).
///
/// v1 gathers the **link-based** explicit signals — the heaviest, least-ambiguous
/// evidence the store records directly — and runs a conservative body pass over
/// current memory rows. It reuses the exact same
/// [`DbConnection::list_all_memory_links`] load that `graph::health` uses, so the
/// contradiction graph stays consistent with structural health.
///
/// The remaining explicit signals (validity-window overlap, duplicate-divergent,
/// trust/outcome split, repeated co-selection) require cross-referencing memory
/// rows and feedback events; they are gathered in later slices and reported via
/// [`GatheredConflictEdges::deferred`] so an un-gathered kind is never silently
/// treated as absent. The fuzzy embedding-opposition detector remains opt-in and
/// out of scope here (the explicit graph is the gate).
///
/// Deterministic: links and body rows are loaded in the connection's deterministic
/// order; canonicalization/dedup happens downstream in
/// [`detect_explicit_contradictions`]. A body read failure suppresses only inferred
/// body edges; already-read direct links remain usable.
#[must_use]
pub fn gather_explicit_conflict_edges(connection: &DbConnection) -> GatheredConflictEdges {
    gather_explicit_conflict_edges_at(connection, Utc::now())
}

/// Gather explicit conflict edges at a caller-supplied reference time.
///
/// Body-derived evidence is evaluated against this same time, while direct
/// link evidence remains unchanged. This keeps historical context replay
/// consistent with the caller's temporal filters.
#[must_use]
pub fn gather_explicit_conflict_edges_at(
    connection: &DbConnection,
    reference_time: DateTime<Utc>,
) -> GatheredConflictEdges {
    gather_explicit_conflict_edges_at_with_scope(connection, None, reference_time)
}

/// Gather explicit conflict edges from one workspace only.
///
/// A database may contain several workspace rows (for example after a
/// migration or when a shared store is used). Conflict surfaces exposed by a
/// workspace command must never join those rows into one graph. The scope is
/// applied to both link endpoints and body inference before graph detection so
/// clusters, counts, and degradation details cannot disclose another
/// workspace's memory ids.
#[must_use]
pub fn gather_explicit_conflict_edges_for_workspace(
    connection: &DbConnection,
    workspace_id: &str,
) -> GatheredConflictEdges {
    gather_explicit_conflict_edges_at_for_workspace(connection, workspace_id, Utc::now())
}

/// Gather explicit conflict edges from one workspace at a caller-supplied time.
#[must_use]
pub fn gather_explicit_conflict_edges_at_for_workspace(
    connection: &DbConnection,
    workspace_id: &str,
    reference_time: DateTime<Utc>,
) -> GatheredConflictEdges {
    gather_explicit_conflict_edges_at_with_scope(connection, Some(workspace_id), reference_time)
}

fn gather_explicit_conflict_edges_at_with_scope(
    connection: &DbConnection,
    workspace_id: Option<&str>,
    reference_time: DateTime<Utc>,
) -> GatheredConflictEdges {
    let gathered = GATHERED_SIGNAL_KINDS.to_vec();
    let deferred = DEFERRED_SIGNAL_KINDS.to_vec();

    let mut read_errors = Vec::new();
    let scoped_memory_ids = match workspace_id {
        Some(workspace_id) => {
            match connection.list_memories_for_retrieval(workspace_id, None, true) {
                Ok(memories) => Some(
                    memories
                        .into_iter()
                        .map(|memory| memory.id)
                        .collect::<BTreeSet<_>>(),
                ),
                Err(error) => {
                    read_errors.push(format!(
                        "memories for workspace {workspace_id} could not be read: {error}"
                    ));
                    Some(BTreeSet::new())
                }
            }
        }
        None => None,
    };

    let (links, link_error) = match connection.list_all_memory_links(None) {
        Ok(links) => (links, None),
        Err(error) => (
            Vec::new(),
            Some(format!("memory links could not be read: {error}")),
        ),
    };

    if let Some(error) = link_error {
        read_errors.push(error);
    }

    let mut edges = Vec::new();
    let mut both_valid_resolved = std::collections::BTreeSet::new();
    let mut scope_split_resolved = std::collections::BTreeSet::new();
    for link in &links {
        if let Some(scoped_memory_ids) = scoped_memory_ids.as_ref()
            && (!scoped_memory_ids.contains(&link.src_memory_id)
                || !scoped_memory_ids.contains(&link.dst_memory_id))
        {
            continue;
        }
        let signal = match link.relation_enum() {
            Some(MemoryLinkRelation::Contradicts) => ExplicitConflictSignal::ContradictionLink,
            Some(MemoryLinkRelation::Supersedes) => ExplicitConflictSignal::Supersession,
            Some(MemoryLinkRelation::Related) => {
                // A reviewed both-valid resolution (bd-3a1op.4) marks the pair
                // as legitimate tension; record it so the surface suppresses
                // the pair instead of re-flagging a settled conflict.
                let resolution = link
                    .metadata_json
                    .as_deref()
                    .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
                    .and_then(|meta| {
                        meta.get("resolution")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    });
                if matches!(resolution.as_deref(), Some("both_valid" | "scope_split")) {
                    let (a, b) = (link.src_memory_id.as_str(), link.dst_memory_id.as_str());
                    let pair = if a <= b { (a, b) } else { (b, a) };
                    let pair = (pair.0.to_owned(), pair.1.to_owned());
                    if resolution.as_deref() == Some("scope_split") {
                        scope_split_resolved.insert(pair);
                    } else {
                        both_valid_resolved.insert(pair);
                    }
                }
                continue;
            }
            // Supports / DerivedFrom / CoTag / CoMention and any unparseable
            // relation are not explicit conflict evidence.
            _ => continue,
        };
        edges.push(ConflictEdge::new(
            &link.src_memory_id,
            &link.dst_memory_id,
            signal,
        ));
    }

    let mut current_memories = Vec::new();
    let mut body_inference_read_error = false;
    match workspace_id {
        Some(workspace_id) => {
            match connection.list_memories_for_retrieval(workspace_id, None, false) {
                Ok(memories) => current_memories.extend(memories),
                Err(error) => {
                    body_inference_read_error = true;
                    read_errors.push(format!(
                        "memories for workspace {workspace_id} could not be read: {error}"
                    ));
                }
            }
        }
        None => match connection.list_workspaces() {
            Ok(workspaces) => {
                for workspace in workspaces {
                    match connection.list_memories_for_retrieval(&workspace.id, None, false) {
                        Ok(memories) => current_memories.extend(memories),
                        Err(error) => {
                            body_inference_read_error = true;
                            read_errors.push(format!(
                                "memories for workspace {} could not be read: {error}",
                                workspace.id
                            ));
                        }
                    }
                }
            }
            Err(error) => {
                body_inference_read_error = true;
                read_errors.push(format!("workspaces could not be read: {error}"));
            }
        },
    }
    // An incomplete semantic corpus cannot prove that inferred pairs are
    // complete. Fail closed for unknown body evidence while retaining all
    // usable direct link edges gathered above.
    let automatic_body_edges = if body_inference_read_error {
        Vec::new()
    } else {
        detect_body_contradiction_pairs_at(&current_memories, reference_time)
    };

    GatheredConflictEdges {
        edges,
        automatic_body_edges,
        gathered,
        deferred,
        read_error: if read_errors.is_empty() {
            None
        } else {
            Some(read_errors.join("; "))
        },
        both_valid_resolved,
        scope_split_resolved,
    }
}

/// Convenience: gather explicit conflict edges from the database and run the
/// detector in one call (bd-1n0np.7.2). Returns the detection report alongside
/// the gather's coverage record so callers (the `ee conflict` surface,
/// bd-1n0np.7.3) can report both the clusters and which explicit signals were
/// considered vs deferred.
#[must_use]
pub fn detect_explicit_contradictions_from_connection(
    connection: &DbConnection,
    config: ContradictionDetectionConfig,
) -> (ContradictionDetectionReport, GatheredConflictEdges) {
    detect_explicit_contradictions_from_connection_at(connection, config, Utc::now())
}

/// Gather and detect contradictions at a caller-supplied reference time.
#[must_use]
pub fn detect_explicit_contradictions_from_connection_at(
    connection: &DbConnection,
    config: ContradictionDetectionConfig,
    reference_time: DateTime<Utc>,
) -> (ContradictionDetectionReport, GatheredConflictEdges) {
    let gathered = gather_explicit_conflict_edges_at(connection, reference_time);
    let all_edges = gathered.all_edges();
    let report = detect_explicit_contradictions(&all_edges, config);
    (report, gathered)
}

/// Gather and detect contradictions from one workspace only.
#[must_use]
pub fn detect_explicit_contradictions_from_connection_for_workspace(
    connection: &DbConnection,
    workspace_id: &str,
    config: ContradictionDetectionConfig,
) -> (ContradictionDetectionReport, GatheredConflictEdges) {
    detect_explicit_contradictions_from_connection_at_for_workspace(
        connection,
        workspace_id,
        config,
        Utc::now(),
    )
}

/// Gather and detect contradictions from one workspace at a caller-supplied time.
#[must_use]
pub fn detect_explicit_contradictions_from_connection_at_for_workspace(
    connection: &DbConnection,
    workspace_id: &str,
    config: ContradictionDetectionConfig,
    reference_time: DateTime<Utc>,
) -> (ContradictionDetectionReport, GatheredConflictEdges) {
    let gathered =
        gather_explicit_conflict_edges_at_for_workspace(connection, workspace_id, reference_time);
    let all_edges = gathered.all_edges();
    let report = detect_explicit_contradictions(&all_edges, config);
    (report, gathered)
}

// ---------------------------------------------------------------------------
// Read-only conflict surface (bd-1n0np.7.3): ee conflict list/explain/cluster.
//
// Joins the explicit-evidence detector output with the memory rows it implicates
// so an agent sees the ranked conflicting pairs WITH both bodies, which side is
// higher-trust/fresher, and the load-bearing status — without any mutation.
// ---------------------------------------------------------------------------

/// Schema id for the read-only conflict surface JSON.
pub const CONFLICT_SURFACE_SCHEMA_V1: &str = "ee.conflict.v1";
/// Schema id for the additive conflict surface carrying all corroborating signal kinds.
pub const CONFLICT_SURFACE_SCHEMA_V2: &str = "ee.conflict.v2";

/// Trust ranking for a memory's `trust_class` (higher = more trusted). Used only
/// to pick the "higher-trust side" of a conflicting pair. Ranks the canonical
/// memory trust-class vocabulary (the `memories.trust_class` CHECK set). Unknown
/// or corrupt classes rank below every known class so they never silently outrank
/// valid store data.
#[must_use]
pub fn trust_class_rank(trust_class: &str) -> u8 {
    match trust_class.parse::<TrustClass>() {
        Ok(TrustClass::HumanExplicit) => 6,
        Ok(TrustClass::PeerHumanAttested) => 5,
        Ok(TrustClass::AgentValidated) => 4,
        Ok(TrustClass::AgentAssertion) => 3,
        Ok(TrustClass::CassEvidence) => 2,
        Ok(TrustClass::LegacyImport) => 1,
        Err(_) => 0,
    }
}

/// Stable id for a canonical conflicting pair (order-independent).
fn conflict_pair_id(low: &str, high: &str) -> String {
    let digest = blake3::hash(format!("{low}\u{0}{high}").as_bytes()).to_hex();
    format!("cf_{}", &digest[..16])
}

/// One memory's read-only projection inside a conflicting pair.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictMemberView {
    pub id: String,
    pub content: String,
    pub level: String,
    pub kind: String,
    pub trust_class: String,
    pub trust_rank: u8,
    pub confidence: f32,
    pub importance: f32,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub updated_at: String,
    /// `true` when this side is the higher-trust / fresher side of the pair.
    pub preferred: bool,
}

/// One ranked conflicting pair with both bodies and the preferred side.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictPairView {
    pub conflict_id: String,
    /// The heaviest explicit signal implicating this pair (snake_case).
    pub signal: String,
    pub load_bearing_milli: u64,
    /// "a", "b", or "tie" — which member is the higher-trust/fresher side.
    pub preferred_side: String,
    /// Why that side was preferred: higher_trust, fresher, or tie_no_signal.
    pub preferred_reason: String,
    pub memory_a: ConflictMemberView,
    pub memory_b: ConflictMemberView,
}

/// Additive v2 projection of a conflicting pair. It preserves every distinct
/// corroborating signal while leaving the v1 struct-literal and wire shape
/// unchanged.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictPairViewV2 {
    pub conflict_id: String,
    /// The heaviest explicit signal implicating this pair (snake_case).
    pub signal: String,
    /// Every distinct signal kind backing the canonical pair, in precedence order.
    pub signals: Vec<String>,
    pub load_bearing_milli: u64,
    /// "a", "b", or "tie" — which member is the higher-trust/fresher side.
    pub preferred_side: String,
    /// Why that side was preferred: higher_trust, fresher, or tie_no_signal.
    pub preferred_reason: String,
    pub memory_a: ConflictMemberView,
    pub memory_b: ConflictMemberView,
}

impl ConflictPairViewV2 {
    /// All corroborating signal kinds, ordered strongest-first.
    #[must_use]
    pub fn signal_kinds(&self) -> &[String] {
        &self.signals
    }

    /// Project this additive v2 pair back to the stable v1 shape.
    #[must_use]
    pub fn as_v1(&self) -> ConflictPairView {
        ConflictPairView {
            conflict_id: self.conflict_id.clone(),
            signal: self.signal.clone(),
            load_bearing_milli: self.load_bearing_milli,
            preferred_side: self.preferred_side.clone(),
            preferred_reason: self.preferred_reason.clone(),
            memory_a: self.memory_a.clone(),
            memory_b: self.memory_b.clone(),
        }
    }
}

/// A detected contradiction cluster projected for the surface.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictClusterView {
    pub louvain_id: usize,
    pub size: usize,
    pub density: f64,
    pub severity: ContradictionSeverity,
    pub member_ids: Vec<String>,
    pub centrality: u32,
    pub load_bearing_milli: u64,
    pub rank_score: f64,
    pub suggested_action: String,
}

/// The full read-only conflict surface (`ee.conflict.v1`).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictSurface {
    pub schema: &'static str,
    /// Ranked conflicting pairs, heaviest load-bearing first (deterministic).
    pub pairs: Vec<ConflictPairView>,
    /// Detected contradiction clusters, most-urgent first.
    pub clusters: Vec<ConflictClusterView>,
    pub explicit_edge_count: usize,
    /// Explicit signal kinds the gather covered (snake_case).
    pub gathered_signals: Vec<String>,
    /// Explicit signal kinds deferred to later slices (reported, not silent).
    pub deferred_signals: Vec<String>,
    pub fuzzy_near_conflict_skipped: bool,
    /// Non-fatal degradations (e.g. a link-read failure); never silent loss.
    pub degraded: Vec<String>,
}

/// Additive v2 conflict surface. The v1 surface remains the default for
/// existing callers and keeps its original pair shape.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictSurfaceV2 {
    pub schema: &'static str,
    pub pairs: Vec<ConflictPairViewV2>,
    pub clusters: Vec<ConflictClusterView>,
    pub explicit_edge_count: usize,
    pub gathered_signals: Vec<String>,
    pub deferred_signals: Vec<String>,
    pub fuzzy_near_conflict_skipped: bool,
    pub degraded: Vec<String>,
}

impl ConflictSurfaceV2 {
    /// Pairs/clusters that implicate a memory id.
    #[must_use]
    pub fn focused_on(&self, memory_id: &str) -> ConflictSurfaceV2 {
        ConflictSurfaceV2 {
            schema: self.schema,
            pairs: self
                .pairs
                .iter()
                .filter(|pair| pair.memory_a.id == memory_id || pair.memory_b.id == memory_id)
                .cloned()
                .collect(),
            clusters: self
                .clusters
                .iter()
                .filter(|cluster| cluster.member_ids.iter().any(|id| id == memory_id))
                .cloned()
                .collect(),
            explicit_edge_count: self.explicit_edge_count,
            gathered_signals: self.gathered_signals.clone(),
            deferred_signals: self.deferred_signals.clone(),
            fuzzy_near_conflict_skipped: self.fuzzy_near_conflict_skipped,
            degraded: self.degraded.clone(),
        }
    }

    /// Project the additive v2 surface back to the stable v1 shape.
    #[must_use]
    pub fn as_v1(&self) -> ConflictSurface {
        ConflictSurface {
            schema: CONFLICT_SURFACE_SCHEMA_V1,
            pairs: self.pairs.iter().map(ConflictPairViewV2::as_v1).collect(),
            clusters: self.clusters.clone(),
            explicit_edge_count: self.explicit_edge_count,
            gathered_signals: self.gathered_signals.clone(),
            deferred_signals: self.deferred_signals.clone(),
            fuzzy_near_conflict_skipped: self.fuzzy_near_conflict_skipped,
            degraded: self.degraded.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct ConflictSurfaceComponents {
    pairs: Vec<ConflictPairViewV2>,
    clusters: Vec<ConflictClusterView>,
    explicit_edge_count: usize,
    gathered_signals: Vec<String>,
    deferred_signals: Vec<String>,
    fuzzy_near_conflict_skipped: bool,
    degraded: Vec<String>,
}

impl ConflictSurfaceComponents {
    fn into_v1(self) -> ConflictSurface {
        ConflictSurface {
            schema: CONFLICT_SURFACE_SCHEMA_V1,
            pairs: self.pairs.iter().map(ConflictPairViewV2::as_v1).collect(),
            clusters: self.clusters,
            explicit_edge_count: self.explicit_edge_count,
            gathered_signals: self.gathered_signals,
            deferred_signals: self.deferred_signals,
            fuzzy_near_conflict_skipped: self.fuzzy_near_conflict_skipped,
            degraded: self.degraded,
        }
    }

    fn into_v2(self) -> ConflictSurfaceV2 {
        ConflictSurfaceV2 {
            schema: CONFLICT_SURFACE_SCHEMA_V2,
            pairs: self.pairs,
            clusters: self.clusters,
            explicit_edge_count: self.explicit_edge_count,
            gathered_signals: self.gathered_signals,
            deferred_signals: self.deferred_signals,
            fuzzy_near_conflict_skipped: self.fuzzy_near_conflict_skipped,
            degraded: self.degraded,
        }
    }
}

impl ConflictSurface {
    /// Pairs/clusters that implicate `memory_id` (for `ee conflict explain`).
    #[must_use]
    pub fn focused_on(&self, memory_id: &str) -> ConflictSurface {
        let pairs: Vec<ConflictPairView> = self
            .pairs
            .iter()
            .filter(|p| p.memory_a.id == memory_id || p.memory_b.id == memory_id)
            .cloned()
            .collect();
        let clusters: Vec<ConflictClusterView> = self
            .clusters
            .iter()
            .filter(|c| c.member_ids.iter().any(|id| id == memory_id))
            .cloned()
            .collect();
        ConflictSurface {
            schema: self.schema,
            explicit_edge_count: self.explicit_edge_count,
            pairs,
            clusters,
            gathered_signals: self.gathered_signals.clone(),
            deferred_signals: self.deferred_signals.clone(),
            fuzzy_near_conflict_skipped: self.fuzzy_near_conflict_skipped,
            degraded: self.degraded.clone(),
        }
    }
}

/// Build a member view, marking `preferred` per the pair decision.
fn member_view(memory: &crate::db::StoredMemory, preferred: bool) -> ConflictMemberView {
    ConflictMemberView {
        id: memory.id.clone(),
        content: memory.content.clone(),
        level: memory.level.clone(),
        kind: memory.kind.clone(),
        trust_rank: trust_class_rank(&memory.trust_class),
        trust_class: memory.trust_class.clone(),
        confidence: memory.confidence,
        importance: memory.importance,
        valid_from: memory.valid_from.clone(),
        valid_to: memory.valid_to.clone(),
        updated_at: memory.updated_at.clone(),
        preferred,
    }
}

fn memory_currentness_rank(memory: &StoredMemory, reference_time: DateTime<Utc>) -> i64 {
    let valid_from = match memory.valid_from.as_deref() {
        Some(value) => match chrono::DateTime::parse_from_rfc3339(value) {
            Ok(parsed) => Some(parsed.with_timezone(&chrono::Utc)),
            Err(_) => return 0,
        },
        None => None,
    };
    let valid_to = match memory.valid_to.as_deref() {
        Some(value) => match chrono::DateTime::parse_from_rfc3339(value) {
            Ok(parsed) => Some(parsed.with_timezone(&chrono::Utc)),
            Err(_) => return 0,
        },
        None => None,
    };
    if valid_from.is_some_and(|start| start > reference_time)
        || valid_to.is_some_and(|end| end <= reference_time)
    {
        0
    } else {
        1
    }
}

fn memory_precedence(
    memory: &StoredMemory,
    reference_time: DateTime<Utc>,
) -> ContradictionPrecedence {
    let (recency_epoch, recency_known) = recency_rank(Some(&memory.updated_at));
    ContradictionPrecedence {
        memory_id: memory.id.clone(),
        trust_rank: i64::from(trust_class_rank(&memory.trust_class)) * 1_000,
        authority_rank: authority_subclass_rank(memory.trust_subclass.as_deref()),
        verification_rank: verification_status_rank(&memory.provenance_verification_status),
        validity_rank: memory_currentness_rank(memory, reference_time),
        confidence_milli: confidence_rank_milli(memory.confidence),
        recency_epoch,
        recency_known,
    }
}

/// Decide the preferred side using the same MEM-03 precedence as the pack
/// guard: trust, authority, verification, validity, confidence, then recency.
/// Returns `("a"|"b"|"tie", reason, a_preferred, b_preferred)`.
#[must_use]
pub fn preferred_side(
    a: &StoredMemory,
    b: &StoredMemory,
) -> (&'static str, &'static str, bool, bool) {
    preferred_side_at(a, b, Utc::now())
}

/// Decide the preferred side at a caller-supplied reference time.
#[must_use]
pub fn preferred_side_at(
    a: &StoredMemory,
    b: &StoredMemory,
    reference_time: DateTime<Utc>,
) -> (&'static str, &'static str, bool, bool) {
    let left = memory_precedence(a, reference_time);
    let right = memory_precedence(b, reference_time);
    let decision = decide_contradiction_survivor_with_precedence(&left, &right);
    if decision.basis == crate::core::contradiction_guard::SuppressionBasis::DeterministicTieBreak
        && left.trust_rank == right.trust_rank
        && left.authority_rank == right.authority_rank
        && left.verification_rank == right.verification_rank
        && left.validity_rank == right.validity_rank
        && left.confidence_milli == right.confidence_milli
        && left.recency_epoch == right.recency_epoch
        && left.recency_known == right.recency_known
    {
        return ("tie", "tie_no_signal", false, false);
    }
    let reason = match decision.basis {
        crate::core::contradiction_guard::SuppressionBasis::HigherTrust => "higher_trust",
        crate::core::contradiction_guard::SuppressionBasis::HigherAuthority => "higher_authority",
        crate::core::contradiction_guard::SuppressionBasis::HigherVerification => {
            "higher_verification"
        }
        crate::core::contradiction_guard::SuppressionBasis::CurrentValidity => "current_validity",
        crate::core::contradiction_guard::SuppressionBasis::HigherConfidence => "higher_confidence",
        crate::core::contradiction_guard::SuppressionBasis::Fresher => "fresher",
        crate::core::contradiction_guard::SuppressionBasis::DeterministicTieBreak => {
            "tie_no_signal"
        }
    };
    if decision.kept_memory_id == a.id {
        ("a", reason, true, false)
    } else {
        ("b", reason, false, true)
    }
}

/// Assemble the read-only conflict surface from the database (bd-1n0np.7.3).
///
/// Reuses [`detect_explicit_contradictions_from_connection`] (the 7.2 gather +
/// detector), then joins each canonical conflicting pair with both memory rows so
/// the surface can report both bodies, the higher-trust/fresher side, and the
/// load-bearing weight. A pair whose memory rows cannot be read is dropped with a
/// visible `degraded` note (never silent). Deterministic: pairs sort by
/// load-bearing weight desc, then `conflict_id`.
#[must_use]
pub fn assemble_conflict_surface(
    connection: &DbConnection,
    config: ContradictionDetectionConfig,
) -> ConflictSurface {
    assemble_conflict_surface_at(connection, config, Utc::now())
}

/// Assemble the read-only conflict surface at a caller-supplied reference
/// time, applying it to inferred body validity and preferred-side ranking.
#[must_use]
fn assemble_conflict_surface_components(
    connection: &DbConnection,
    config: ContradictionDetectionConfig,
    reference_time: DateTime<Utc>,
    workspace_id: Option<&str>,
) -> ConflictSurfaceComponents {
    let (report, gathered) = match workspace_id {
        Some(workspace_id) => detect_explicit_contradictions_from_connection_at_for_workspace(
            connection,
            workspace_id,
            config,
            reference_time,
        ),
        None => {
            detect_explicit_contradictions_from_connection_at(connection, config, reference_time)
        }
    };

    let mut degraded: Vec<String> = Vec::new();
    if let Some(error) = &gathered.read_error {
        degraded.push(error.clone());
    }

    // Deduplicate to canonical pairs while retaining every corroborating
    // signal kind. The ordered list supplies the complete evidence view and
    // the deterministic primary signal for existing consumers.
    let mut pair_signals: BTreeMap<(String, String), BTreeSet<ExplicitConflictSignal>> =
        BTreeMap::new();
    let all_edges = gathered.all_edges();
    for edge in &all_edges {
        if let Some(pair) = canonical_pair(edge) {
            pair_signals.entry(pair).or_default().insert(edge.signal);
        }
    }

    let mut pairs: Vec<ConflictPairViewV2> = Vec::new();
    for ((low, high), signal_set) in &pair_signals {
        let mut ordered_signals = signal_set.iter().copied().collect::<Vec<_>>();
        ordered_signals.sort_by(|left, right| {
            right
                .weight_milli()
                .cmp(&left.weight_milli())
                .then_with(|| left.cmp(right))
        });
        let Some(signal) = ordered_signals.first().copied() else {
            continue;
        };
        // A reviewed both-valid resolution settled this tension: suppress.
        if gathered
            .both_valid_resolved
            .contains(&(low.clone(), high.clone()))
            || gathered
                .scope_split_resolved
                .contains(&(low.clone(), high.clone()))
        {
            continue;
        }
        let (Ok(Some(a)), Ok(Some(b))) = (connection.get_memory(low), connection.get_memory(high))
        else {
            degraded.push(format!(
                "conflict pair {low}<->{high} skipped: a cited memory row could not be read"
            ));
            continue;
        };
        // A tombstoned side means the conflict was already resolved (superseded,
        // rejected, or expired): the pair is history, not an actionable conflict.
        // Deterministic — keyed on the persisted tombstone, never wall clock.
        if a.tombstoned_at.is_some()
            || b.tombstoned_at.is_some()
            || !body_memory_is_current(&a, reference_time)
            || !body_memory_is_current(&b, reference_time)
        {
            continue;
        }
        let (preferred, reason, a_pref, b_pref) = preferred_side_at(&a, &b, reference_time);
        pairs.push(ConflictPairViewV2 {
            conflict_id: conflict_pair_id(low, high),
            signal: signal.as_str().to_owned(),
            signals: ordered_signals
                .iter()
                .map(|signal| signal.as_str().to_owned())
                .collect(),
            load_bearing_milli: signal.weight_milli(),
            preferred_side: preferred.to_owned(),
            preferred_reason: reason.to_owned(),
            memory_a: member_view(&a, a_pref),
            memory_b: member_view(&b, b_pref),
        });
    }

    // Deterministic: heaviest load-bearing first, then stable conflict_id.
    pairs.sort_by(|left, right| {
        right
            .load_bearing_milli
            .cmp(&left.load_bearing_milli)
            .then_with(|| left.conflict_id.cmp(&right.conflict_id))
    });

    let clusters: Vec<ConflictClusterView> = report
        .clusters
        .iter()
        .map(|ranked| ConflictClusterView {
            louvain_id: ranked.cluster.louvain_id,
            size: ranked.cluster.size,
            density: ranked.cluster.density,
            severity: ranked.cluster.severity,
            member_ids: ranked.cluster.exemplar_memory_ids.clone(),
            centrality: ranked.centrality,
            load_bearing_milli: ranked.load_bearing_milli,
            rank_score: ranked.rank_score,
            suggested_action: ranked.cluster.suggested_action.to_owned(),
        })
        .collect();

    ConflictSurfaceComponents {
        pairs,
        clusters,
        explicit_edge_count: report.explicit_edge_count,
        gathered_signals: gathered
            .gathered
            .iter()
            .map(|s| s.as_str().to_owned())
            .collect(),
        deferred_signals: gathered
            .deferred
            .iter()
            .map(|s| s.as_str().to_owned())
            .collect(),
        fuzzy_near_conflict_skipped: report.fuzzy_near_conflict_skipped,
        degraded,
    }
}

/// Assemble the stable v1 read-only conflict surface.
#[must_use]
pub fn assemble_conflict_surface_at(
    connection: &DbConnection,
    config: ContradictionDetectionConfig,
    reference_time: DateTime<Utc>,
) -> ConflictSurface {
    assemble_conflict_surface_components(connection, config, reference_time, None).into_v1()
}

/// Assemble the stable v1 conflict surface for one workspace only.
#[must_use]
pub fn assemble_conflict_surface_for_workspace(
    connection: &DbConnection,
    workspace_id: &str,
    config: ContradictionDetectionConfig,
) -> ConflictSurface {
    assemble_conflict_surface_at_for_workspace(connection, workspace_id, config, Utc::now())
}

/// Assemble the stable v1 conflict surface for one workspace at a fixed time.
#[must_use]
pub fn assemble_conflict_surface_at_for_workspace(
    connection: &DbConnection,
    workspace_id: &str,
    config: ContradictionDetectionConfig,
    reference_time: DateTime<Utc>,
) -> ConflictSurface {
    assemble_conflict_surface_components(connection, config, reference_time, Some(workspace_id))
        .into_v1()
}

/// Assemble the additive v2 read-only conflict surface carrying every
/// corroborating signal kind.
#[must_use]
pub fn assemble_conflict_surface_v2(
    connection: &DbConnection,
    config: ContradictionDetectionConfig,
) -> ConflictSurfaceV2 {
    assemble_conflict_surface_v2_at(connection, config, Utc::now())
}

/// Assemble the additive v2 conflict surface at a caller-supplied reference
/// time.
#[must_use]
pub fn assemble_conflict_surface_v2_at(
    connection: &DbConnection,
    config: ContradictionDetectionConfig,
    reference_time: DateTime<Utc>,
) -> ConflictSurfaceV2 {
    assemble_conflict_surface_components(connection, config, reference_time, None).into_v2()
}

// ---------------------------------------------------------------------------
// Conflict resolution planning (bd-3a1op.4, ADR 0066)
// ---------------------------------------------------------------------------

/// Wire schema id for the `ee conflict resolve` report.
pub const CONFLICT_RESOLVE_SCHEMA_V1: &str = "ee.conflict.resolve.v1";

/// Resolution verb vocabulary (ADR 0066 verb table).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolveVerb {
    /// Keeper supersedes the loser: supersede link + validity close + decision.
    Supersede,
    /// Loser was simply wrong: expire it with the rationale on record.
    RejectOne,
    /// Both sides hold in different scopes: tag each side into its scope.
    ScopeSplit,
    /// The tension is legitimate: record a `related` link + the decision.
    BothValid,
}

impl ResolveVerb {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "supersede" => Some(Self::Supersede),
            "reject-one" => Some(Self::RejectOne),
            "scope-split" => Some(Self::ScopeSplit),
            "both-valid" => Some(Self::BothValid),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supersede => "supersede",
            Self::RejectOne => "reject-one",
            Self::ScopeSplit => "scope-split",
            Self::BothValid => "both-valid",
        }
    }
}

/// One planned mutation atom. Every atom maps 1:1 onto an EXISTING audited
/// core operation (`decide_record`, `expire_memory`, `update_memory_link`,
/// `update_memory_tags`) — the plan never introduces a novel mutation path.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum PlannedResolutionAction {
    /// `decide_record` — when `supersedes` is set the one atom also creates
    /// the supersede link and closes the loser's validity window.
    #[serde(rename_all = "camelCase")]
    RecordDecision {
        topic: String,
        chosen: String,
        alternatives: Vec<String>,
        supersedes: Option<String>,
    },
    /// `expire_memory` — audited soft expiration.
    #[serde(rename_all = "camelCase")]
    ExpireMemory { memory_id: String, reason: String },
    /// `update_memory_link` create — audited explicit typed link.
    #[serde(rename_all = "camelCase")]
    CreateLink {
        from: String,
        to: String,
        relation: String,
        /// Optional durable resolution marker carried by the link action.
        /// Plain related links remain observational and do not settle a pair.
        #[serde(default)]
        metadata_json: Option<String>,
    },
    /// `update_memory_tags` patch(add) — audited scope tagging.
    #[serde(rename_all = "camelCase")]
    AddTags {
        memory_id: String,
        tags: Vec<String>,
    },
}

/// The dry-run-visible mutation plan for one conflict pair.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictResolutionPlan {
    pub conflict_id: String,
    pub verb: ResolveVerb,
    pub memory_a: String,
    pub memory_b: String,
    pub keep: Option<String>,
    pub lose: Option<String>,
    pub actions: Vec<PlannedResolutionAction>,
}

/// Inputs to planning, already parsed by the CLI layer.
#[derive(Clone, Debug)]
pub struct ConflictResolveRequest<'a> {
    pub memory_a: &'a str,
    pub memory_b: &'a str,
    pub verb: ResolveVerb,
    pub keep: Option<&'a str>,
    pub reason: &'a str,
    pub scope_a_tags: Vec<String>,
    pub scope_b_tags: Vec<String>,
}

/// Planning outcome. Refusals are data, not errors, so the CLI can emit the
/// honest degraded/policy envelope for each case.
#[derive(Clone, Debug, PartialEq)]
pub enum ConflictResolutionOutcome {
    Plan(ConflictResolutionPlan),
    /// The pair is not on the CURRENT conflict surface (state moved since the
    /// agent ran explain). Carries the focused live view for re-orientation.
    StaleSurface {
        current_pairs: Vec<ConflictPairView>,
    },
    /// Policy refuses the mutation (exit 7): destructive verb against a
    /// human-explicit rule memory.
    PolicyDenied {
        message: String,
        repair: String,
    },
    /// The request itself is malformed (missing/invalid --keep, scopes, ...).
    InvalidRequest {
        message: String,
        repair: String,
    },
}

fn decision_topic(pair: &ConflictPairView) -> String {
    format!("conflict:{}", pair.conflict_id)
}

fn alternatives_with_fallback(
    chosen: &str,
    preferred: Option<String>,
    fallback: &str,
) -> Vec<String> {
    let mut alternatives = Vec::new();
    if let Some(preferred) = preferred
        && !preferred.trim().is_empty()
        && preferred != chosen
    {
        alternatives.push(preferred);
    }
    if alternatives.is_empty() && fallback != chosen {
        alternatives.push(fallback.to_owned());
    }
    alternatives
}

fn head(content: &str) -> String {
    const MAX: usize = 96;
    let oneline = content.replace('\n', " ");
    if oneline.chars().count() <= MAX {
        oneline
    } else {
        let truncated: String = oneline.chars().take(MAX).collect();
        format!("{truncated}…")
    }
}

/// Pure planner: re-checks the pair against the live surface, enforces verb
/// argument rules and the destructive-verb policy, then maps the verb onto
/// existing audited atoms per the ADR 0066 verb table.
#[must_use]
pub fn plan_conflict_resolution(
    surface: &ConflictSurface,
    request: &ConflictResolveRequest<'_>,
) -> ConflictResolutionOutcome {
    let pair = surface.pairs.iter().find(|pair| {
        (pair.memory_a.id == request.memory_a && pair.memory_b.id == request.memory_b)
            || (pair.memory_a.id == request.memory_b && pair.memory_b.id == request.memory_a)
    });
    let Some(pair) = pair else {
        let mut current: Vec<ConflictPairView> = surface
            .pairs
            .iter()
            .filter(|pair| {
                [request.memory_a, request.memory_b]
                    .iter()
                    .any(|id| pair.memory_a.id == *id || pair.memory_b.id == *id)
            })
            .cloned()
            .collect();
        current.truncate(8);
        return ConflictResolutionOutcome::StaleSurface {
            current_pairs: current,
        };
    };

    let needs_keep = matches!(
        request.verb,
        ResolveVerb::Supersede | ResolveVerb::RejectOne
    );
    let (keep, lose) = if needs_keep {
        let Some(keep) = request.keep else {
            return ConflictResolutionOutcome::InvalidRequest {
                message: format!(
                    "--verb {} requires --keep <memory-id> naming the surviving side.",
                    request.verb.as_str()
                ),
                repair: format!(
                    "ee conflict resolve {} {} --verb {} --keep {} --reason \"...\" --json",
                    request.memory_a,
                    request.memory_b,
                    request.verb.as_str(),
                    request.memory_a
                ),
            };
        };
        if keep != pair.memory_a.id && keep != pair.memory_b.id {
            return ConflictResolutionOutcome::InvalidRequest {
                message: format!("--keep {keep} is neither side of this conflict pair."),
                repair: format!(
                    "Pass --keep {} or --keep {}.",
                    pair.memory_a.id, pair.memory_b.id
                ),
            };
        }
        let lose = if keep == pair.memory_a.id {
            pair.memory_b.id.clone()
        } else {
            pair.memory_a.id.clone()
        };
        (Some(keep.to_owned()), Some(lose))
    } else {
        (None, None)
    };

    if let Some(lose_id) = lose.as_deref() {
        let loser = if pair.memory_a.id == lose_id {
            &pair.memory_a
        } else {
            &pair.memory_b
        };
        if request.verb == ResolveVerb::RejectOne
            && loser.kind == "rule"
            && loser.trust_class == "human_explicit"
        {
            return ConflictResolutionOutcome::PolicyDenied {
                message: format!(
                    "reject-one refuses to expire {lose_id}: it is a human-explicit rule; \
                     rejecting it outright requires a human decision."
                ),
                repair: "Use --verb supersede (records provenance + the decision) or have a \
                         human run `ee memory expire` directly."
                    .to_owned(),
            };
        }
    }

    let loser_head = lose.as_deref().map(|id| {
        if pair.memory_a.id == id {
            head(&pair.memory_a.content)
        } else {
            head(&pair.memory_b.content)
        }
    });

    let actions = match request.verb {
        ResolveVerb::Supersede => {
            // The transaction executor creates the decision, supersede link,
            // and validity close as one durable operation.
            let chosen = format!("keep {}", keep.as_deref().unwrap_or_default());
            vec![PlannedResolutionAction::RecordDecision {
                topic: decision_topic(pair),
                alternatives: alternatives_with_fallback(
                    &chosen,
                    loser_head,
                    &format!("reject {}", lose.as_deref().unwrap_or_default()),
                ),
                chosen,
                supersedes: lose.clone(),
            }]
        }
        ResolveVerb::RejectOne => {
            let chosen = format!(
                "keep {}; reject the other side",
                keep.as_deref().unwrap_or_default()
            );
            vec![
                PlannedResolutionAction::ExpireMemory {
                    memory_id: lose.clone().unwrap_or_default(),
                    reason: request.reason.to_owned(),
                },
                PlannedResolutionAction::RecordDecision {
                    topic: decision_topic(pair),
                    alternatives: alternatives_with_fallback(
                        &chosen,
                        loser_head,
                        &format!("keep only {}", keep.as_deref().unwrap_or_default()),
                    ),
                    chosen,
                    supersedes: None,
                },
            ]
        }
        ResolveVerb::ScopeSplit => {
            if request.scope_a_tags.is_empty() || request.scope_b_tags.is_empty() {
                return ConflictResolutionOutcome::InvalidRequest {
                    message: "--verb scope-split requires --scope-a-tags and --scope-b-tags \
                              (comma-separated, both non-empty)."
                        .to_owned(),
                    repair: format!(
                        "ee conflict resolve {} {} --verb scope-split --scope-a-tags rust \
                         --scope-b-tags python --reason \"...\" --json",
                        request.memory_a, request.memory_b
                    ),
                };
            }
            vec![
                PlannedResolutionAction::AddTags {
                    memory_id: pair.memory_a.id.clone(),
                    tags: request.scope_a_tags.clone(),
                },
                PlannedResolutionAction::AddTags {
                    memory_id: pair.memory_b.id.clone(),
                    tags: request.scope_b_tags.clone(),
                },
                PlannedResolutionAction::CreateLink {
                    from: pair.memory_a.id.clone(),
                    to: pair.memory_b.id.clone(),
                    relation: "related".to_owned(),
                    metadata_json: Some(
                        serde_json::json!({
                            "resolution": "scope_split",
                            "conflictId": pair.conflict_id,
                            "scopeA": request.scope_a_tags,
                            "scopeB": request.scope_b_tags,
                        })
                        .to_string(),
                    ),
                },
                PlannedResolutionAction::RecordDecision {
                    topic: decision_topic(pair),
                    chosen: format!(
                        "scope-split: {} → [{}]; {} → [{}]",
                        pair.memory_a.id,
                        request.scope_a_tags.join(","),
                        pair.memory_b.id,
                        request.scope_b_tags.join(",")
                    ),
                    alternatives: vec![
                        format!("scope A: {}", pair.memory_a.id),
                        format!("scope B: {}", pair.memory_b.id),
                    ],
                    supersedes: None,
                },
            ]
        }
        ResolveVerb::BothValid => vec![
            PlannedResolutionAction::CreateLink {
                from: pair.memory_a.id.clone(),
                to: pair.memory_b.id.clone(),
                relation: "related".to_owned(),
                metadata_json: Some(
                    serde_json::json!({
                        "resolution": "both_valid",
                        "conflictId": pair.conflict_id,
                    })
                    .to_string(),
                ),
            },
            PlannedResolutionAction::RecordDecision {
                topic: decision_topic(pair),
                chosen: "both-valid: the tension is legitimate; both memories stand".to_owned(),
                alternatives: vec![
                    format!("keep only {}", pair.memory_a.id),
                    format!("keep only {}", pair.memory_b.id),
                ],
                supersedes: None,
            },
        ],
    };

    ConflictResolutionOutcome::Plan(ConflictResolutionPlan {
        conflict_id: pair.conflict_id.clone(),
        verb: request.verb,
        memory_a: pair.memory_a.id.clone(),
        memory_b: pair.memory_b.id.clone(),
        keep,
        lose,
        actions,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        CONFLICT_SURFACE_SCHEMA_V1, CONFLICT_SURFACE_SCHEMA_V2, ConflictEdge,
        ContradictionDetectionConfig, ExplicitConflictSignal, assemble_conflict_surface,
        assemble_conflict_surface_at, assemble_conflict_surface_v2, canonical_pair,
        detect_body_contradiction_pairs, detect_body_contradiction_pairs_at,
        detect_explicit_contradictions, detect_explicit_contradictions_from_connection,
        gather_explicit_conflict_edges, gather_explicit_conflict_edges_at, preferred_side,
        trust_class_rank,
    };
    use crate::db::{
        CreateMemoryInput, CreateMemoryLinkInput, CreateWorkspaceInput, DbConnection,
        MemoryLinkRelation, MemoryLinkSource,
    };

    // ---- DB-gather test scaffolding (mirrors src/core/health.rs) ----------
    // IDs must satisfy the schema CHECK constraints: wsp_/mem_ are length 30,
    // link_ is length 31 (see src/db/mod.rs).
    const WS_ID: &str = "wsp_00000000000000000000000072";
    const MEM_A: &str = "mem_00000000000000000000000001";
    const MEM_B: &str = "mem_00000000000000000000000002";
    const MEM_C: &str = "mem_00000000000000000000000003";
    const MEM_D: &str = "mem_00000000000000000000000004";
    const LINK_1: &str = "link_00000000000000000000000001";
    const LINK_2: &str = "link_00000000000000000000000002";
    const LINK_3: &str = "link_00000000000000000000000003";

    fn open_seeded_db() -> DbConnection {
        let connection = DbConnection::open_memory().expect("open in-memory db");
        connection.migrate().expect("migrate schema");
        connection
            .insert_workspace(
                WS_ID,
                &CreateWorkspaceInput {
                    path: "/tmp/ee-contradiction-gather-fixture".to_owned(),
                    name: Some("contradiction gather".to_owned()),
                },
            )
            .expect("insert workspace");
        connection
    }

    fn seed_memory(connection: &DbConnection, memory_id: &str) {
        seed_memory_trust(connection, memory_id, "agent_assertion");
    }

    fn seed_memory_trust(connection: &DbConnection, memory_id: &str, trust_class: &str) {
        connection
            .insert_memory(
                memory_id,
                &CreateMemoryInput {
                    workspace_id: WS_ID.to_owned(),
                    level: "procedural".to_owned(),
                    kind: "rule".to_owned(),
                    content: format!("fixture {memory_id}"),
                    workflow_id: None,
                    confidence: 0.9,
                    utility: 0.8,
                    importance: 0.7,
                    provenance_uri: None,
                    trust_class: trust_class.to_owned(),
                    trust_subclass: None,
                    tags: Vec::new(),
                    valid_from: None,
                    valid_to: None,
                },
            )
            .expect("insert memory");
    }

    fn seed_claim_memory(connection: &DbConnection, memory_id: &str, content: &str) {
        connection
            .insert_memory(
                memory_id,
                &CreateMemoryInput {
                    workspace_id: WS_ID.to_owned(),
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
            .expect("insert claim memory");
    }

    fn seed_link(
        connection: &DbConnection,
        link_id: &str,
        src: &str,
        dst: &str,
        relation: MemoryLinkRelation,
    ) {
        connection
            .insert_memory_link(
                link_id,
                &CreateMemoryLinkInput {
                    src_memory_id: src.to_owned(),
                    dst_memory_id: dst.to_owned(),
                    relation,
                    weight: 1.0,
                    confidence: 1.0,
                    directed: false,
                    evidence_count: 1,
                    last_reinforced_at: None,
                    source: MemoryLinkSource::Agent,
                    created_by: Some("contradiction-gather-test".to_owned()),
                    metadata_json: None,
                },
            )
            .expect("insert link");
    }

    #[test]
    fn signal_weights_are_ordered_explicit_first() {
        // Direct contradiction links must outweigh weaker co-selection evidence.
        assert!(
            ExplicitConflictSignal::ContradictionLink.weight_milli()
                > ExplicitConflictSignal::RepeatedCoSelection.weight_milli()
        );
        assert!(
            ExplicitConflictSignal::Supersession.weight_milli()
                > ExplicitConflictSignal::TrustOutcomeSplit.weight_milli()
        );
    }

    #[test]
    fn canonical_pair_is_unordered_and_drops_blanks_and_self_loops() {
        let forward =
            ConflictEdge::new("mem_b", "mem_a", ExplicitConflictSignal::ContradictionLink);
        let reversed =
            ConflictEdge::new("  mem_a  ", "mem_b", ExplicitConflictSignal::Supersession);
        assert_eq!(canonical_pair(&forward), canonical_pair(&reversed));
        assert_eq!(
            canonical_pair(&forward),
            Some(("mem_a".to_string(), "mem_b".to_string()))
        );
        // Self-loops and blanks are unusable.
        assert_eq!(
            canonical_pair(&ConflictEdge::new(
                "x",
                "x",
                ExplicitConflictSignal::ContradictionLink
            )),
            None
        );
        assert_eq!(
            canonical_pair(&ConflictEdge::new(
                "   ",
                "y",
                ExplicitConflictSignal::ContradictionLink
            )),
            None
        );
    }

    #[test]
    fn no_edges_yields_no_clusters() {
        let report = detect_explicit_contradictions(&[], ContradictionDetectionConfig::default());
        assert!(report.clusters.is_empty());
        assert_eq!(report.explicit_edge_count, 0);
        assert!(!report.fuzzy_near_conflict_skipped);
    }

    #[test]
    fn duplicate_edges_are_canonicalized_before_counting() {
        // Same pair via two directions / two signals counts as ONE explicit edge.
        let edges = vec![
            ConflictEdge::new("mem_a", "mem_b", ExplicitConflictSignal::ContradictionLink),
            ConflictEdge::new(
                "mem_b",
                "mem_a",
                ExplicitConflictSignal::RepeatedCoSelection,
            ),
        ];
        let report =
            detect_explicit_contradictions(&edges, ContradictionDetectionConfig::default());
        assert_eq!(report.explicit_edge_count, 1);
    }

    #[test]
    fn requested_fuzzy_pass_is_reported_skipped_not_silently_run() {
        let config = ContradictionDetectionConfig {
            density_threshold: None,
            include_fuzzy_near_conflict: true,
        };
        let report = detect_explicit_contradictions(&[], config);
        // No silent widening: the deferred fuzzy pass is flagged, not performed.
        assert!(report.fuzzy_near_conflict_skipped);
    }

    #[test]
    fn dense_contradiction_clique_is_detected_and_ranked() {
        // A 3-memory contradiction triangle is a clear, dense conflict cluster.
        let edges = vec![
            ConflictEdge::new("mem_a", "mem_b", ExplicitConflictSignal::ContradictionLink),
            ConflictEdge::new("mem_b", "mem_c", ExplicitConflictSignal::ContradictionLink),
            ConflictEdge::new("mem_a", "mem_c", ExplicitConflictSignal::Supersession),
        ];
        let report =
            detect_explicit_contradictions(&edges, ContradictionDetectionConfig::default());
        assert_eq!(report.explicit_edge_count, 3);
        assert!(
            !report.clusters.is_empty(),
            "a dense contradiction triangle should surface at least one cluster"
        );
        let top = &report.clusters[0];
        assert!(top.rank_score > 0.0);
        assert!(top.load_bearing_milli > 0);
        assert!(top.centrality > 0);
    }

    #[test]
    fn ranking_is_deterministic_across_input_order() {
        let edges = vec![
            ConflictEdge::new("mem_a", "mem_b", ExplicitConflictSignal::ContradictionLink),
            ConflictEdge::new("mem_b", "mem_c", ExplicitConflictSignal::ContradictionLink),
            ConflictEdge::new("mem_a", "mem_c", ExplicitConflictSignal::ContradictionLink),
        ];
        let mut reversed = edges.clone();
        reversed.reverse();
        let first = detect_explicit_contradictions(&edges, ContradictionDetectionConfig::default());
        let second =
            detect_explicit_contradictions(&reversed, ContradictionDetectionConfig::default());
        assert_eq!(first, second, "detection is independent of input order");
    }

    #[test]
    fn gather_maps_contradicts_and_supersedes_links_to_explicit_signals() {
        let connection = open_seeded_db();
        for memory_id in [MEM_A, MEM_B, MEM_C] {
            seed_memory(&connection, memory_id);
        }
        seed_link(
            &connection,
            LINK_1,
            MEM_A,
            MEM_B,
            MemoryLinkRelation::Contradicts,
        );
        seed_link(
            &connection,
            LINK_2,
            MEM_B,
            MEM_C,
            MemoryLinkRelation::Supersedes,
        );

        let gathered = gather_explicit_conflict_edges(&connection);
        assert!(gathered.read_error.is_none(), "links read cleanly");
        assert_eq!(gathered.edges.len(), 2, "one edge per conflict link");
        assert!(gathered.edges.contains(&ConflictEdge::new(
            MEM_A,
            MEM_B,
            ExplicitConflictSignal::ContradictionLink
        )));
        assert!(gathered.edges.contains(&ConflictEdge::new(
            MEM_B,
            MEM_C,
            ExplicitConflictSignal::Supersession
        )));
    }

    #[test]
    fn gather_ignores_non_conflict_relations() {
        let connection = open_seeded_db();
        for memory_id in [MEM_A, MEM_B] {
            seed_memory(&connection, memory_id);
        }
        // Supports / Related are NOT explicit conflict evidence.
        seed_link(
            &connection,
            LINK_1,
            MEM_A,
            MEM_B,
            MemoryLinkRelation::Supports,
        );
        seed_link(
            &connection,
            LINK_2,
            MEM_A,
            MEM_B,
            MemoryLinkRelation::Related,
        );

        let gathered = gather_explicit_conflict_edges(&connection);
        assert!(
            gathered.edges.is_empty(),
            "non-conflict relations produce no conflict edges"
        );
    }

    #[test]
    fn gather_reports_deferred_signal_kinds_no_silent_omission() {
        let connection = open_seeded_db();
        let gathered = gather_explicit_conflict_edges(&connection);
        // v1 covers the link-based kinds and explicitly reports the rest as
        // deferred rather than pretending they were considered.
        assert!(
            gathered
                .gathered
                .contains(&ExplicitConflictSignal::ContradictionLink)
        );
        assert!(
            gathered
                .gathered
                .contains(&ExplicitConflictSignal::Supersession)
        );
        assert!(
            gathered
                .deferred
                .contains(&ExplicitConflictSignal::ValidityWindowOverlap),
            "an un-gathered signal kind is surfaced, never silently absent"
        );
        // Gathered and deferred kinds are disjoint and cover all six signals.
        assert_eq!(gathered.gathered.len() + gathered.deferred.len(), 6);
        for kind in &gathered.gathered {
            assert!(!gathered.deferred.contains(kind), "kinds are disjoint");
        }
    }

    #[test]
    fn gather_then_detect_surfaces_a_contradiction_cluster_end_to_end() {
        let connection = open_seeded_db();
        for memory_id in [MEM_A, MEM_B, MEM_C] {
            seed_memory(&connection, memory_id);
        }
        // A dense contradiction triangle of explicit links.
        seed_link(
            &connection,
            LINK_1,
            MEM_A,
            MEM_B,
            MemoryLinkRelation::Contradicts,
        );
        seed_link(
            &connection,
            LINK_2,
            MEM_B,
            MEM_C,
            MemoryLinkRelation::Contradicts,
        );
        seed_link(
            &connection,
            LINK_3,
            MEM_A,
            MEM_C,
            MemoryLinkRelation::Contradicts,
        );

        let (report, gathered) = detect_explicit_contradictions_from_connection(
            &connection,
            ContradictionDetectionConfig::default(),
        );
        assert_eq!(gathered.edges.len(), 3, "three explicit conflict links");
        assert_eq!(report.explicit_edge_count, 3);
        assert!(
            !report.clusters.is_empty(),
            "a dense explicit contradiction triangle surfaces a cluster"
        );
    }

    #[test]
    fn gather_on_empty_db_yields_no_edges_without_error() {
        let connection = open_seeded_db();
        let gathered = gather_explicit_conflict_edges(&connection);
        assert!(gathered.read_error.is_none());
        assert!(gathered.edges.is_empty(), "no links -> no conflict edges");
    }

    #[test]
    fn body_contradictions_pair_exact_claims_and_preserve_unrelated_evidence() {
        let connection = open_seeded_db();
        seed_claim_memory(
            &connection,
            MEM_A,
            "Entity: deployment; Claim: uses SQLite.",
        );
        seed_claim_memory(
            &connection,
            MEM_B,
            "Entity: deployment; Claim: does not use SQLite.",
        );
        seed_claim_memory(
            &connection,
            MEM_C,
            "Entity: unrelated-service; Claim: does not use SQLite.",
        );

        let gathered = gather_explicit_conflict_edges(&connection);
        assert!(gathered.read_error.is_none());
        assert!(
            gathered.edges.is_empty(),
            "the fixture has no conflict links"
        );
        assert_eq!(gathered.automatic_body_edges.len(), 1);
        assert_eq!(
            gathered.automatic_body_edges[0],
            ConflictEdge::new(MEM_A, MEM_B, ExplicitConflictSignal::BodyContradiction)
        );

        let memories = [
            connection
                .get_memory(MEM_A)
                .expect("read A")
                .expect("A exists"),
            connection
                .get_memory(MEM_B)
                .expect("read B")
                .expect("B exists"),
            connection
                .get_memory(MEM_C)
                .expect("read C")
                .expect("C exists"),
        ];
        let direct = detect_body_contradiction_pairs(&memories);
        assert_eq!(direct.len(), 1);
        assert_eq!(direct[0].memory_a, MEM_A);
        assert_eq!(direct[0].memory_b, MEM_B);

        let surface =
            assemble_conflict_surface(&connection, ContradictionDetectionConfig::default());
        assert_eq!(
            surface.pairs.len(),
            1,
            "only the identified claim is paired"
        );
        let pair = &surface.pairs[0];
        assert_eq!(pair.signal, "body_contradiction");
        assert_eq!(pair.memory_a.id, MEM_A);
        assert_eq!(pair.memory_b.id, MEM_B);
        assert!(pair.memory_a.content.contains("SQLite"));
        assert!(pair.memory_b.content.contains("not use SQLite"));
        assert!(
            connection
                .get_memory(MEM_C)
                .expect("read unrelated memory")
                .is_some(),
            "discovery must not delete unrelated evidence"
        );
    }

    #[test]
    fn direct_edges_protect_pack_when_body_inference_read_fails() {
        use std::str::FromStr;

        use crate::models::{MemoryId, ProvenanceUri, UnitScore};
        use crate::pack::{
            ContextPackProfile, PackCandidate, PackCandidateInput, PackProvenance, PackSection,
            TokenBudget, assemble_draft_with_profile,
        };

        let connection = open_seeded_db();
        seed_memory(&connection, MEM_A);
        seed_memory(&connection, MEM_B);
        seed_link(
            &connection,
            LINK_1,
            MEM_A,
            MEM_B,
            MemoryLinkRelation::Contradicts,
        );

        let id_a = MemoryId::from_str(MEM_A).expect("valid A memory id");
        let id_b = MemoryId::from_str(MEM_B).expect("valid B memory id");
        let candidate = |memory_id: MemoryId, content: &str| {
            PackCandidate::new(PackCandidateInput {
                memory_id,
                section: PackSection::Evidence,
                content: content.to_owned(),
                estimated_tokens: 4,
                relevance: UnitScore::parse(0.9).expect("relevance"),
                utility: UnitScore::parse(0.8).expect("utility"),
                provenance: vec![
                    PackProvenance::new(
                        ProvenanceUri::EeMemory(memory_id),
                        "direct conflict failure fixture",
                    )
                    .expect("provenance"),
                ],
                why: "direct conflict failure fixture".to_owned(),
            })
            .expect("candidate")
        };
        let budget = TokenBudget::new(100).expect("budget");
        let mut draft = assemble_draft_with_profile(
            ContextPackProfile::Balanced,
            "direct conflict failure",
            budget,
            vec![
                candidate(id_a, "Entity: deployment; Claim: uses SQLite."),
                candidate(id_b, "Entity: deployment; Claim: does not use SQLite."),
            ],
        )
        .expect("draft");

        // Break only the semantic body source after the durable link has been
        // read-capable. The gather must retain the direct contradiction edge.
        connection
            .execute_raw("PRAGMA foreign_keys = OFF")
            .expect("disable foreign keys for failure fixture");
        connection
            .execute_raw("ALTER TABLE memories RENAME TO memories_unavailable")
            .expect("make body source unavailable");

        let gathered = gather_explicit_conflict_edges_at(
            &connection,
            chrono::DateTime::parse_from_rfc3339("2024-06-01T00:00:00Z")
                .expect("reference time")
                .with_timezone(&chrono::Utc),
        );
        assert!(
            gathered.read_error.is_some(),
            "semantic body-read failure must be visible"
        );
        assert_eq!(
            gathered.edges,
            vec![ConflictEdge::new(
                MEM_A,
                MEM_B,
                ExplicitConflictSignal::ContradictionLink,
            )],
            "the durable direct edge survives body-read failure"
        );
        assert!(
            gathered.automatic_body_edges.is_empty(),
            "inferred edges fail closed when the body source is unreadable"
        );

        let detected = gathered
            .all_edges()
            .into_iter()
            .map(|edge| (edge.memory_a, edge.memory_b))
            .collect::<Vec<_>>();
        let unresolved =
            crate::core::contradiction_guard::unresolved_contradiction_pairs(&detected, &[]);
        assert_eq!(
            draft.apply_contradiction_guard(&unresolved, false),
            1,
            "the retained direct edge still protects the pack"
        );
        assert_eq!(draft.items.len(), 1);
        assert_eq!(draft.omitted.len(), 1);
    }

    #[test]
    fn body_contradictions_honor_caller_reference_time() {
        let connection = open_seeded_db();
        seed_claim_memory(
            &connection,
            MEM_A,
            "Entity: deployment; Claim: uses SQLite.",
        );
        seed_claim_memory(
            &connection,
            MEM_B,
            "Entity: deployment; Claim: does not use SQLite.",
        );
        connection
            .execute_raw(
                "UPDATE memories SET valid_from = '2024-01-01T00:00:00Z',                  valid_to = '2024-12-31T00:00:00Z'                  WHERE id IN ('mem_00000000000000000000000001',                               'mem_00000000000000000000000002')",
            )
            .expect("set historical validity windows");
        let memories = [
            connection
                .get_memory(MEM_A)
                .expect("read historical A")
                .expect("historical A exists"),
            connection
                .get_memory(MEM_B)
                .expect("read historical B")
                .expect("historical B exists"),
        ];
        let historical = chrono::DateTime::parse_from_rfc3339("2024-06-01T00:00:00Z")
            .expect("historical reference time")
            .with_timezone(&chrono::Utc);
        let current = chrono::DateTime::parse_from_rfc3339("2025-06-01T00:00:00Z")
            .expect("current reference time")
            .with_timezone(&chrono::Utc);

        assert_eq!(
            detect_body_contradiction_pairs_at(&memories, historical).len(),
            1,
            "the caller's historical reference time keeps both claims current"
        );
        assert!(
            detect_body_contradiction_pairs_at(&memories, current).is_empty(),
            "the same claims are expired at the later reference time"
        );

        let historical_surface = assemble_conflict_surface_at(
            &connection,
            ContradictionDetectionConfig::default(),
            historical,
        );
        assert_eq!(
            historical_surface.pairs.len(),
            1,
            "historical conflict surface uses the supplied reference time"
        );
        let current_surface = assemble_conflict_surface_at(
            &connection,
            ContradictionDetectionConfig::default(),
            current,
        );
        assert!(
            current_surface.pairs.is_empty(),
            "later conflict surface excludes the expired inferred pair"
        );
    }

    #[test]
    fn body_contradictions_require_explicit_identity_and_opposition() {
        let connection = open_seeded_db();
        seed_claim_memory(&connection, MEM_A, "deployment uses SQLite");
        seed_claim_memory(&connection, MEM_B, "deployment does not use SQLite");
        seed_claim_memory(
            &connection,
            MEM_C,
            "Entity: deployment; Claim: maybe uses SQLite.",
        );
        let memories = [
            connection
                .get_memory(MEM_A)
                .expect("read A")
                .expect("A exists"),
            connection
                .get_memory(MEM_B)
                .expect("read B")
                .expect("B exists"),
            connection
                .get_memory(MEM_C)
                .expect("read C")
                .expect("C exists"),
        ];
        assert!(
            detect_body_contradiction_pairs(&memories).is_empty(),
            "unlabeled prose and an ambiguous claim must not become inferred contradictions"
        );
    }

    #[test]
    fn preferred_side_uses_shared_precedence_facets() {
        let connection = open_seeded_db();
        seed_memory_trust(&connection, MEM_A, "agent_assertion");
        seed_memory_trust(&connection, MEM_B, "agent_assertion");
        let mut a = connection
            .get_memory(MEM_A)
            .expect("read A")
            .expect("A exists");
        let mut b = connection
            .get_memory(MEM_B)
            .expect("read B")
            .expect("B exists");
        a.confidence = 0.9;
        b.confidence = 0.2;
        a.updated_at = "2020-01-01T00:00:00Z".to_owned();
        b.updated_at = "2030-01-01T00:00:00Z".to_owned();
        let (side, reason, a_preferred, b_preferred) = preferred_side(&a, &b);
        assert_eq!(side, "a");
        assert_eq!(reason, "higher_confidence");
        assert!(a_preferred && !b_preferred);

        b.valid_to = Some("2020-01-01T00:00:00Z".to_owned());
        let (side, reason, _, _) = preferred_side(&a, &b);
        assert_eq!(side, "a");
        assert_eq!(reason, "current_validity");

        b.valid_to = None;
        b.trust_class = "human_explicit".to_owned();
        b.confidence = 0.1;
        let (side, reason, _, _) = preferred_side(&a, &b);
        assert_eq!(side, "b");
        assert_eq!(reason, "higher_trust");
    }

    #[test]
    fn trust_class_rank_follows_the_canonical_store_taxonomy() {
        assert!(trust_class_rank("human_explicit") > trust_class_rank("peer_human_attested"));
        assert!(trust_class_rank("peer_human_attested") > trust_class_rank("agent_validated"));
        assert!(trust_class_rank("agent_validated") > trust_class_rank("agent_assertion"));
        assert!(trust_class_rank("agent_assertion") > trust_class_rank("cass_evidence"));
        assert!(trust_class_rank("cass_evidence") > trust_class_rank("legacy_import"));
        // Unknown/corrupt classes rank below every valid DB trust class.
        assert!(trust_class_rank("legacy_import") > trust_class_rank("totally_unknown"));
        assert_eq!(trust_class_rank("external"), 0);
    }

    #[test]
    fn surface_pair_carries_both_bodies_and_prefers_higher_trust_side() {
        let connection = open_seeded_db();
        // MEM_A is human_explicit (higher trust), MEM_B is agent_assertion.
        seed_memory_trust(&connection, MEM_A, "human_explicit");
        seed_memory_trust(&connection, MEM_B, "agent_assertion");
        seed_link(
            &connection,
            LINK_1,
            MEM_A,
            MEM_B,
            MemoryLinkRelation::Contradicts,
        );

        let surface =
            assemble_conflict_surface(&connection, ContradictionDetectionConfig::default());
        assert_eq!(surface.schema, CONFLICT_SURFACE_SCHEMA_V1);
        assert_eq!(surface.pairs.len(), 1, "one conflicting pair");
        let pair = &surface.pairs[0];
        // Both bodies present.
        assert!(pair.memory_a.content.contains(MEM_A));
        assert!(pair.memory_b.content.contains(MEM_B));
        // The higher-trust side (canonical ordering puts MEM_A first) is preferred.
        assert_eq!(pair.preferred_side, "a");
        assert_eq!(pair.preferred_reason, "higher_trust");
        assert!(pair.memory_a.preferred && !pair.memory_b.preferred);
        assert_eq!(pair.signal, "contradiction_link");
        assert!(pair.load_bearing_milli > 0);
        assert!(surface.degraded.is_empty());
    }

    #[test]
    fn surface_preserves_all_corroborating_signals_with_deterministic_primary() {
        let connection = open_seeded_db();
        seed_memory_trust(&connection, MEM_A, "human_explicit");
        seed_memory_trust(&connection, MEM_B, "agent_assertion");
        seed_link(
            &connection,
            LINK_1,
            MEM_A,
            MEM_B,
            MemoryLinkRelation::Contradicts,
        );
        seed_link(
            &connection,
            LINK_2,
            MEM_B,
            MEM_A,
            MemoryLinkRelation::Supersedes,
        );

        let v1 = assemble_conflict_surface(&connection, ContradictionDetectionConfig::default());
        let v1_pair = v1.pairs.first().expect("multi-signal pair");
        assert_eq!(v1_pair.signal, "contradiction_link");
        let v1_json = serde_json::to_value(&v1).expect("serialize v1 surface");
        assert!(
            v1_json["pairs"][0].get("signals").is_none(),
            "v1 must retain its original pair wire shape"
        );

        let v2 = assemble_conflict_surface_v2(&connection, ContradictionDetectionConfig::default());
        assert_eq!(v2.schema, CONFLICT_SURFACE_SCHEMA_V2);
        let pair = v2.pairs.first().expect("multi-signal v2 pair");
        assert_eq!(
            pair.signal_kinds(),
            &["contradiction_link".to_owned(), "supersession".to_owned()]
        );
        assert_eq!(pair.as_v1(), v1_pair.clone());
        let v2_json = serde_json::to_value(&v2).expect("serialize v2 surface");
        assert_eq!(
            v2_json["pairs"][0]["signals"],
            serde_json::json!(["contradiction_link", "supersession"])
        );
        assert_eq!(v1.schema, CONFLICT_SURFACE_SCHEMA_V1);
    }

    #[test]
    fn surface_drops_pairs_with_a_tombstoned_side() {
        // A resolved conflict (loser expired/superseded → tombstoned) must
        // leave the actionable surface: this is what makes `ee conflict
        // resolve` terminal and its stale-surface re-run refusal real.
        let connection = open_seeded_db();
        seed_memory_trust(&connection, MEM_A, "human_explicit");
        seed_memory_trust(&connection, MEM_B, "agent_assertion");
        seed_link(
            &connection,
            LINK_1,
            MEM_A,
            MEM_B,
            MemoryLinkRelation::Contradicts,
        );
        let before =
            assemble_conflict_surface(&connection, ContradictionDetectionConfig::default());
        assert_eq!(before.pairs.len(), 1, "live pair surfaces first");

        assert!(connection.tombstone_memory(MEM_B).expect("tombstone loser"));
        let after = assemble_conflict_surface(&connection, ContradictionDetectionConfig::default());
        assert!(
            after.pairs.is_empty(),
            "tombstoned side must drop the pair from the actionable surface"
        );
    }

    #[test]
    fn surface_drops_pairs_with_an_expired_validity_side() {
        let connection = open_seeded_db();
        seed_memory(&connection, MEM_A);
        seed_memory(&connection, MEM_B);
        seed_link(
            &connection,
            LINK_1,
            MEM_A,
            MEM_B,
            MemoryLinkRelation::Contradicts,
        );
        connection
            .expire_memory_valid_to(MEM_B, "2020-01-01T00:00:00Z")
            .expect("expire loser validity");
        let reference_time = chrono::DateTime::parse_from_rfc3339("2024-06-01T00:00:00Z")
            .expect("reference time")
            .with_timezone(&chrono::Utc);
        let surface = assemble_conflict_surface_at(
            &connection,
            ContradictionDetectionConfig::default(),
            reference_time,
        );
        assert!(
            surface.pairs.is_empty(),
            "expired validity side must leave the actionable surface"
        );
    }

    #[test]
    fn surface_suppresses_scope_split_resolved_pairs() {
        let connection = open_seeded_db();
        seed_memory(&connection, MEM_A);
        seed_memory(&connection, MEM_B);
        seed_link(
            &connection,
            LINK_1,
            MEM_A,
            MEM_B,
            MemoryLinkRelation::Contradicts,
        );
        connection
            .insert_memory_link(
                LINK_2,
                &CreateMemoryLinkInput {
                    src_memory_id: MEM_A.to_owned(),
                    dst_memory_id: MEM_B.to_owned(),
                    relation: MemoryLinkRelation::Related,
                    weight: 1.0,
                    confidence: 1.0,
                    directed: false,
                    evidence_count: 1,
                    last_reinforced_at: None,
                    source: MemoryLinkSource::Agent,
                    created_by: Some("conflict-resolve-test".to_owned()),
                    metadata_json: Some(
                        r#"{"resolution":"scope_split","conflictId":"cfl_x"}"#.to_owned(),
                    ),
                },
            )
            .expect("insert scope split marker");
        let surface =
            assemble_conflict_surface(&connection, ContradictionDetectionConfig::default());
        assert!(surface.pairs.is_empty());
    }

    #[test]
    fn surface_suppresses_both_valid_resolved_pairs() {
        // `ee conflict resolve --verb both-valid` records a related link with
        // resolution metadata; the settled pair must stop being re-flagged.
        let connection = open_seeded_db();
        seed_memory(&connection, MEM_A);
        seed_memory(&connection, MEM_B);
        seed_link(
            &connection,
            LINK_1,
            MEM_A,
            MEM_B,
            MemoryLinkRelation::Contradicts,
        );
        connection
            .insert_memory_link(
                LINK_2,
                &CreateMemoryLinkInput {
                    src_memory_id: MEM_A.to_owned(),
                    dst_memory_id: MEM_B.to_owned(),
                    relation: MemoryLinkRelation::Related,
                    weight: 1.0,
                    confidence: 1.0,
                    directed: false,
                    evidence_count: 1,
                    last_reinforced_at: None,
                    source: MemoryLinkSource::Agent,
                    created_by: Some("conflict-resolve-test".to_owned()),
                    metadata_json: Some(
                        "{\"resolution\":\"both_valid\",\"conflictId\":\"cfl_x\"}".to_owned(),
                    ),
                },
            )
            .expect("insert resolution link");

        let surface =
            assemble_conflict_surface(&connection, ContradictionDetectionConfig::default());
        assert!(
            surface.pairs.is_empty(),
            "both-valid-resolved pair must be suppressed: {:?}",
            surface.pairs
        );

        // A plain related link WITHOUT the resolution marker must not suppress.
        let connection = open_seeded_db();
        seed_memory(&connection, MEM_A);
        seed_memory(&connection, MEM_B);
        seed_link(
            &connection,
            LINK_1,
            MEM_A,
            MEM_B,
            MemoryLinkRelation::Contradicts,
        );
        seed_link(
            &connection,
            LINK_2,
            MEM_A,
            MEM_B,
            MemoryLinkRelation::Related,
        );
        let surface =
            assemble_conflict_surface(&connection, ContradictionDetectionConfig::default());
        assert_eq!(
            surface.pairs.len(),
            1,
            "plain related link is not a resolution"
        );
    }

    #[test]
    fn surface_reports_clusters_and_deferred_signals() {
        let connection = open_seeded_db();
        for memory_id in [MEM_A, MEM_B, MEM_C] {
            seed_memory(&connection, memory_id);
        }
        seed_link(
            &connection,
            LINK_1,
            MEM_A,
            MEM_B,
            MemoryLinkRelation::Contradicts,
        );
        seed_link(
            &connection,
            LINK_2,
            MEM_B,
            MEM_C,
            MemoryLinkRelation::Contradicts,
        );
        seed_link(
            &connection,
            LINK_3,
            MEM_A,
            MEM_C,
            MemoryLinkRelation::Contradicts,
        );

        let surface =
            assemble_conflict_surface(&connection, ContradictionDetectionConfig::default());
        assert_eq!(surface.pairs.len(), 3);
        assert!(
            !surface.clusters.is_empty(),
            "dense triangle surfaces a cluster"
        );
        // Deferred signal kinds are reported, never silently absent.
        assert!(
            surface
                .deferred_signals
                .iter()
                .any(|s| s == "validity_window_overlap")
        );
        assert!(
            surface
                .gathered_signals
                .iter()
                .any(|s| s == "contradiction_link")
        );
    }

    #[test]
    fn surface_focused_on_filters_to_the_named_memory() {
        let connection = open_seeded_db();
        for memory_id in [MEM_A, MEM_B, MEM_C, MEM_D] {
            seed_memory(&connection, memory_id);
        }
        // MEM_A<->MEM_B and MEM_B<->MEM_C are conflicts; MEM_D is unrelated.
        seed_link(
            &connection,
            LINK_1,
            MEM_A,
            MEM_B,
            MemoryLinkRelation::Contradicts,
        );
        seed_link(
            &connection,
            LINK_2,
            MEM_B,
            MEM_C,
            MemoryLinkRelation::Contradicts,
        );

        let surface =
            assemble_conflict_surface(&connection, ContradictionDetectionConfig::default());
        assert_eq!(surface.explicit_edge_count, 2);
        let focused = surface.focused_on(MEM_D);
        assert!(
            focused.pairs.is_empty(),
            "MEM_D participates in no conflict pair"
        );
        assert_eq!(
            focused.explicit_edge_count, 2,
            "focused views retain the full detector edge count"
        );
        let focused_a = surface.focused_on(MEM_A);
        assert_eq!(focused_a.pairs.len(), 1, "MEM_A is in exactly one pair");
        assert_eq!(focused_a.explicit_edge_count, 2);
    }

    #[test]
    fn surface_is_deterministic_across_runs() {
        let connection = open_seeded_db();
        for memory_id in [MEM_A, MEM_B, MEM_C] {
            seed_memory(&connection, memory_id);
        }
        seed_link(
            &connection,
            LINK_1,
            MEM_A,
            MEM_B,
            MemoryLinkRelation::Contradicts,
        );
        seed_link(
            &connection,
            LINK_2,
            MEM_B,
            MEM_C,
            MemoryLinkRelation::Supersedes,
        );

        let first = assemble_conflict_surface(&connection, ContradictionDetectionConfig::default());
        let second =
            assemble_conflict_surface(&connection, ContradictionDetectionConfig::default());
        assert_eq!(first, second, "conflict surface is deterministic");
    }

    // ---- resolution planner (bd-3a1op.4) ---------------------------------

    use super::{
        ConflictMemberView, ConflictPairView, ConflictResolutionOutcome, ConflictResolveRequest,
        ConflictSurface, PlannedResolutionAction, ResolveVerb, plan_conflict_resolution,
    };

    fn member(id: &str, kind: &str, trust_class: &str) -> ConflictMemberView {
        ConflictMemberView {
            id: id.to_owned(),
            content: format!("content of {id}"),
            level: "semantic".to_owned(),
            kind: kind.to_owned(),
            trust_class: trust_class.to_owned(),
            trust_rank: 2,
            confidence: 0.8,
            importance: 0.5,
            valid_from: None,
            valid_to: None,
            updated_at: "2026-08-10T00:00:00Z".to_owned(),
            preferred: false,
        }
    }

    fn fixture_surface() -> ConflictSurface {
        ConflictSurface {
            schema: CONFLICT_SURFACE_SCHEMA_V1,
            pairs: vec![ConflictPairView {
                conflict_id: "cfl_fixture_pair".to_owned(),
                signal: "polarity_opposition".to_owned(),
                load_bearing_milli: 500,
                preferred_side: "a".to_owned(),
                preferred_reason: "higher_trust".to_owned(),
                memory_a: member(MEM_A, "fact", "agent_inferred"),
                memory_b: member(MEM_B, "fact", "agent_inferred"),
            }],
            clusters: Vec::new(),
            explicit_edge_count: 1,
            gathered_signals: Vec::new(),
            deferred_signals: Vec::new(),
            fuzzy_near_conflict_skipped: false,
            degraded: Vec::new(),
        }
    }

    fn request<'a>(verb: ResolveVerb, keep: Option<&'a str>) -> ConflictResolveRequest<'a> {
        ConflictResolveRequest {
            memory_a: MEM_A,
            memory_b: MEM_B,
            verb,
            keep,
            reason: "test rationale",
            scope_a_tags: Vec::new(),
            scope_b_tags: Vec::new(),
        }
    }

    #[test]
    fn supersede_plans_the_single_decide_record_atom() {
        let outcome = plan_conflict_resolution(
            &fixture_surface(),
            &request(ResolveVerb::Supersede, Some(MEM_A)),
        );
        let ConflictResolutionOutcome::Plan(plan) = outcome else {
            panic!("expected a plan, got {outcome:?}");
        };
        assert_eq!(plan.keep.as_deref(), Some(MEM_A));
        assert_eq!(plan.lose.as_deref(), Some(MEM_B));
        assert_eq!(plan.actions.len(), 1, "supersede is ONE decide_record atom");
        let PlannedResolutionAction::RecordDecision { supersedes, .. } = &plan.actions[0] else {
            panic!("expected RecordDecision, got {:?}", plan.actions[0]);
        };
        assert_eq!(supersedes.as_deref(), Some(MEM_B));
    }

    #[test]
    fn reject_one_plans_expire_then_decision_and_reversed_keep_resolves_loser() {
        // keep=b exercises the orientation-independent keep/lose resolution.
        let outcome = plan_conflict_resolution(
            &fixture_surface(),
            &request(ResolveVerb::RejectOne, Some(MEM_B)),
        );
        let ConflictResolutionOutcome::Plan(plan) = outcome else {
            panic!("expected a plan, got {outcome:?}");
        };
        assert_eq!(plan.lose.as_deref(), Some(MEM_A));
        assert!(matches!(
            &plan.actions[0],
            PlannedResolutionAction::ExpireMemory { memory_id, reason }
                if memory_id == MEM_A && reason == "test rationale"
        ));
        assert!(matches!(
            &plan.actions[1],
            PlannedResolutionAction::RecordDecision {
                supersedes: None,
                ..
            }
        ));
    }

    #[test]
    fn keep_required_verbs_refuse_without_keep() {
        for verb in [ResolveVerb::Supersede, ResolveVerb::RejectOne] {
            let outcome = plan_conflict_resolution(&fixture_surface(), &request(verb, None));
            assert!(
                matches!(outcome, ConflictResolutionOutcome::InvalidRequest { .. }),
                "{} without --keep must refuse",
                verb.as_str()
            );
        }
        let outcome = plan_conflict_resolution(
            &fixture_surface(),
            &request(ResolveVerb::Supersede, Some(MEM_C)),
        );
        assert!(
            matches!(outcome, ConflictResolutionOutcome::InvalidRequest { .. }),
            "--keep naming a non-member must refuse"
        );
    }

    #[test]
    fn stale_pair_refuses_with_focused_current_state() {
        let outcome = plan_conflict_resolution(
            &fixture_surface(),
            &ConflictResolveRequest {
                memory_a: MEM_A,
                memory_b: MEM_C, // (a,c) is NOT a live pair; (a,b) is
                verb: ResolveVerb::BothValid,
                keep: None,
                reason: "r",
                scope_a_tags: Vec::new(),
                scope_b_tags: Vec::new(),
            },
        );
        let ConflictResolutionOutcome::StaleSurface { current_pairs } = outcome else {
            panic!("expected StaleSurface, got {outcome:?}");
        };
        assert_eq!(
            current_pairs.len(),
            1,
            "focused view carries the live (a,b) pair"
        );
        assert_eq!(current_pairs[0].memory_a.id, MEM_A);
    }

    #[test]
    fn reject_one_of_human_explicit_rule_is_policy_denied() {
        let mut surface = fixture_surface();
        surface.pairs[0].memory_b = member(MEM_B, "rule", "human_explicit");
        let outcome =
            plan_conflict_resolution(&surface, &request(ResolveVerb::RejectOne, Some(MEM_A)));
        assert!(
            matches!(outcome, ConflictResolutionOutcome::PolicyDenied { .. }),
            "expiring a human-explicit rule via reject-one must be policy-denied, got {outcome:?}"
        );
        // supersede of the same memory stays allowed (records provenance).
        let outcome =
            plan_conflict_resolution(&surface, &request(ResolveVerb::Supersede, Some(MEM_A)));
        assert!(matches!(outcome, ConflictResolutionOutcome::Plan(_)));
    }

    #[test]
    fn scope_split_requires_both_scopes_and_plans_tags_then_decision() {
        let outcome =
            plan_conflict_resolution(&fixture_surface(), &request(ResolveVerb::ScopeSplit, None));
        assert!(matches!(
            outcome,
            ConflictResolutionOutcome::InvalidRequest { .. }
        ));

        let mut req = request(ResolveVerb::ScopeSplit, None);
        req.scope_a_tags = vec!["rust".to_owned()];
        req.scope_b_tags = vec!["python".to_owned()];
        let outcome = plan_conflict_resolution(&fixture_surface(), &req);
        let ConflictResolutionOutcome::Plan(plan) = outcome else {
            panic!("expected a plan, got {outcome:?}");
        };
        assert_eq!(plan.actions.len(), 4);
        assert!(matches!(
            &plan.actions[0],
            PlannedResolutionAction::AddTags { memory_id, tags }
                if memory_id == MEM_A && tags == &vec!["rust".to_owned()]
        ));
        assert!(matches!(
            &plan.actions[2],
            PlannedResolutionAction::CreateLink {
                relation,
                metadata_json: Some(metadata),
                ..
            } if relation == "related" && metadata.contains("scope_split")
        ));
        assert!(matches!(
            &plan.actions[3],
            PlannedResolutionAction::RecordDecision { alternatives, .. }
                if !alternatives.is_empty()
        ));
    }

    #[test]
    fn scope_split_and_both_valid_decisions_have_alternatives() {
        for (verb, scope_a_tags, scope_b_tags) in [
            (
                ResolveVerb::ScopeSplit,
                vec!["rust".to_owned()],
                vec!["python".to_owned()],
            ),
            (ResolveVerb::BothValid, Vec::new(), Vec::new()),
        ] {
            let request = ConflictResolveRequest {
                memory_a: MEM_A,
                memory_b: MEM_B,
                verb,
                keep: None,
                reason: "test rationale",
                scope_a_tags,
                scope_b_tags,
            };
            let ConflictResolutionOutcome::Plan(plan) =
                plan_conflict_resolution(&fixture_surface(), &request)
            else {
                panic!("expected a plan for {}", verb.as_str());
            };
            assert!(plan.actions.iter().any(|action| matches!(
                action,
                PlannedResolutionAction::RecordDecision { alternatives, .. }
                    if !alternatives.is_empty()
            )));
        }
    }

    #[test]
    fn both_valid_plans_related_link_then_decision() {
        let outcome =
            plan_conflict_resolution(&fixture_surface(), &request(ResolveVerb::BothValid, None));
        let ConflictResolutionOutcome::Plan(plan) = outcome else {
            panic!("expected a plan, got {outcome:?}");
        };
        assert_eq!(plan.keep, None);
        assert!(matches!(
            &plan.actions[0],
            PlannedResolutionAction::CreateLink { relation, .. } if relation == "related"
        ));
        assert!(matches!(
            &plan.actions[1],
            PlannedResolutionAction::RecordDecision {
                supersedes: None,
                ..
            }
        ));
    }
}
