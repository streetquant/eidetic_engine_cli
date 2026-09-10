//! bd-1n0np.7.5 — pack-time contradiction guard: decision core.
//!
//! The pack guard must never include both sides of an *unresolved hard
//! contradiction* in a context pack: it keeps the higher-trust / fresher side
//! and flags the other `contradiction_suppressed`. An opt-in `forced` mode
//! instead surfaces both sides under a `## Contradictions` header, ranked + capped.
//!
//! This module is the pure decision core (the proven decision-core-vs-I/O split,
//! mirroring `models::memory_sentinel::SentinelObservation`): it answers "which
//! contradiction pairs are still unresolved?" and "given two contradicting
//! memories, which one survives and why?" without touching the DB or the pack
//! pipeline. The caller resolves the unresolved set from the 7.2 detector
//! (`core::contradiction_detect::detect_explicit_contradictions_from_connection`)
//! minus recorded resolutions (7.4), then applies these decisions during pack
//! assembly. Deterministic and panic-free.

use std::cmp::Ordering;
use std::collections::BTreeSet;

/// Default cap on how many contradiction sides `forced` mode surfaces under the
/// `## Contradictions` header (the rest are summarized as a count — never a
/// silent drop).
pub const DEFAULT_FORCED_CONTRADICTION_CAP: usize = 8;

/// A memory's standing used to choose which side of a contradiction survives.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardedMemory {
    pub memory_id: String,
    /// Higher = more trusted (milli-units, so callers can pass fixed-point trust).
    pub trust_milli: i64,
    /// Higher = fresher (e.g. updated-at epoch seconds).
    pub freshness_epoch: i64,
}

/// Ordered standing used by every contradiction survivor decision.
///
/// The fields are explicit so MEM-03 preference is shared by the conflict
/// surface and pack guard: trust class, authority source, verification posture,
/// temporal validity, confidence, recency, and finally memory id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContradictionPrecedence {
    pub memory_id: String,
    /// Higher = stronger native trust class, in milli-units.
    pub trust_rank: i64,
    /// Higher = stronger authority source within a trust class.
    pub authority_rank: i64,
    /// Higher = stronger provenance verification posture.
    pub verification_rank: i64,
    /// Higher = currently valid at the caller's reference time.
    pub validity_rank: i64,
    /// Confidence in milli-units, normally 0..=1000.
    pub confidence_milli: i64,
    /// Higher = more recent.
    pub recency_epoch: i64,
    /// Whether `recency_epoch` is a parsed/known value.
    pub recency_known: bool,
}

/// Rank an optional authority subtype without allowing arbitrary text to
/// outrank a known trust class. Empty/unknown subtypes remain neutral.
#[must_use]
pub fn authority_subclass_rank(subclass: Option<&str>) -> i64 {
    let Some(subclass) = subclass.map(str::trim).filter(|value| !value.is_empty()) else {
        return 0;
    };
    let normalized = subclass.to_ascii_lowercase();
    if normalized.contains("human")
        || normalized.contains("signed")
        || normalized.contains("attested")
        || normalized.contains("manual")
    {
        3
    } else if normalized.contains("verified") || normalized.contains("validated") {
        2
    } else {
        1
    }
}

/// Rank the native provenance verification status. A failed verification must
/// not outrank an unverified claim merely because it is newer.
#[must_use]
pub fn verification_status_rank(status: &str) -> i64 {
    match status.trim().to_ascii_lowercase().as_str() {
        "verified" => 3,
        "unverified" | "unchecked" | "pending" | "skipped" => 1,
        "missing" | "mismatch" | "failed" | "" => 0,
        _ => 0,
    }
}

/// Convert a unit confidence value to a bounded fixed-point rank.
#[must_use]
pub fn confidence_rank_milli(confidence: f32) -> i64 {
    let confidence = if confidence.is_finite() {
        confidence.clamp(0.0, 1.0)
    } else {
        0.0
    };
    f64::from(confidence * 1_000.0).round() as i64
}

/// Parse an RFC3339 timestamp for the shared recency comparator.
#[must_use]
pub fn recency_rank(raw: Option<&str>) -> (i64, bool) {
    let Some(raw) = raw else {
        return (0, false);
    };
    match raw.parse::<chrono::DateTime<chrono::FixedOffset>>() {
        Ok(value) => (value.timestamp(), true),
        Err(_) => (0, false),
    }
}

/// Rank the lifecycle status used by pack items. Unknown and malformed rows are
/// lower-standing than a currently-valid row.
#[must_use]
pub fn validity_status_rank(status: &str) -> i64 {
    match status.trim().to_ascii_lowercase().as_str() {
        "active" | "current" | "valid" => 1,
        "" | "unknown" | "future" | "expired" | "malformed" | "invalid" => 0,
        _ => 0,
    }
}

/// Why one side of a contradiction was kept over the other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuppressionBasis {
    /// The kept side had strictly higher native trust.
    HigherTrust,
    /// Trust tied; the kept side had stronger authority.
    HigherAuthority,
    /// Trust and authority tied; the kept side had stronger verification.
    HigherVerification,
    /// Trust, authority, and verification tied; the kept side is current.
    CurrentValidity,
    /// Standing and validity tied; the kept side had higher confidence.
    HigherConfidence,
    /// All standing facets tied; the kept side was fresher.
    Fresher,
    /// All standing facets tied; broken deterministically by memory id.
    DeterministicTieBreak,
}

impl SuppressionBasis {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HigherTrust => "higher_trust",
            Self::HigherAuthority => "higher_authority",
            Self::HigherVerification => "higher_verification",
            Self::CurrentValidity => "current_validity",
            Self::HigherConfidence => "higher_confidence",
            Self::Fresher => "fresher",
            Self::DeterministicTieBreak => "deterministic_tie_break",
        }
    }
}

/// The pack-guard decision for one unresolved hard-contradiction pair: keep one
/// side, suppress the other. Never drops both.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContradictionSuppression {
    pub kept_memory_id: String,
    pub suppressed_memory_id: String,
    pub basis: SuppressionBasis,
}

/// Compare two contradiction standings. `Greater` means the left side has the
/// stronger shared trust -> authority -> verification -> validity -> confidence
/// -> recency standing. Pure.
fn compare_precedence(left: &ContradictionPrecedence, right: &ContradictionPrecedence) -> Ordering {
    left.trust_rank
        .cmp(&right.trust_rank)
        .then(left.authority_rank.cmp(&right.authority_rank))
        .then(left.verification_rank.cmp(&right.verification_rank))
        .then(left.validity_rank.cmp(&right.validity_rank))
        .then(left.confidence_milli.cmp(&right.confidence_milli))
        .then_with(|| match (left.recency_known, right.recency_known) {
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            _ => left.recency_epoch.cmp(&right.recency_epoch),
        })
}

fn basis_for_non_tied_precedence(
    left: &ContradictionPrecedence,
    right: &ContradictionPrecedence,
) -> SuppressionBasis {
    if left.trust_rank != right.trust_rank {
        SuppressionBasis::HigherTrust
    } else if left.authority_rank != right.authority_rank {
        SuppressionBasis::HigherAuthority
    } else if left.verification_rank != right.verification_rank {
        SuppressionBasis::HigherVerification
    } else if left.validity_rank != right.validity_rank {
        SuppressionBasis::CurrentValidity
    } else if left.confidence_milli != right.confidence_milli {
        SuppressionBasis::HigherConfidence
    } else {
        SuppressionBasis::Fresher
    }
}

/// Decide which side of a contradiction to keep using the native MEM-03
/// precedence: trust, authority, verification, validity, confidence, recency,
/// then the lexically-smaller memory id. Pure and never-both-dropped.
#[must_use]
pub fn decide_contradiction_survivor_with_precedence(
    left: &ContradictionPrecedence,
    right: &ContradictionPrecedence,
) -> ContradictionSuppression {
    let standing = compare_precedence(left, right);
    let (keep, suppress, basis) = match standing {
        Ordering::Greater => (left, right, basis_for_non_tied_precedence(left, right)),
        Ordering::Less => (right, left, basis_for_non_tied_precedence(right, left)),
        Ordering::Equal => {
            if left.memory_id <= right.memory_id {
                (left, right, SuppressionBasis::DeterministicTieBreak)
            } else {
                (right, left, SuppressionBasis::DeterministicTieBreak)
            }
        }
    };
    ContradictionSuppression {
        kept_memory_id: keep.memory_id.clone(),
        suppressed_memory_id: suppress.memory_id.clone(),
        basis,
    }
}

fn precedence_from_guarded(memory: &GuardedMemory) -> ContradictionPrecedence {
    ContradictionPrecedence {
        memory_id: memory.memory_id.clone(),
        trust_rank: memory.trust_milli,
        authority_rank: 0,
        verification_rank: 0,
        validity_rank: 1,
        confidence_milli: 0,
        recency_epoch: memory.freshness_epoch,
        recency_known: true,
    }
}

/// Compatibility wrapper for callers that only have trust and freshness. It
/// uses the shared comparator with neutral authority, verification, and
/// confidence dimensions.
#[must_use]
pub fn decide_contradiction_survivor(
    left: &GuardedMemory,
    right: &GuardedMemory,
) -> ContradictionSuppression {
    let left = precedence_from_guarded(left);
    let right = precedence_from_guarded(right);
    decide_contradiction_survivor_with_precedence(&left, &right)
}

/// Canonicalize a pair to an unordered, trimmed `(low, high)`, dropping blanks
/// and self-loops.
fn canonical_pair(a: &str, b: &str) -> Option<(String, String)> {
    let a = a.trim();
    let b = b.trim();
    if a.is_empty() || b.is_empty() || a == b {
        return None;
    }
    if a <= b {
        Some((a.to_string(), b.to_string()))
    } else {
        Some((b.to_string(), a.to_string()))
    }
}

/// The unresolved hard-contradiction set: detected contradiction pairs (from the
/// 7.2 detector) minus pairs that already carry a recorded resolution (7.4).
/// Deterministic: canonicalized, deduplicated, sorted.
#[must_use]
pub fn unresolved_contradiction_pairs(
    detected: &[(String, String)],
    resolved: &[(String, String)],
) -> Vec<(String, String)> {
    let resolved_set: BTreeSet<(String, String)> = resolved
        .iter()
        .filter_map(|(a, b)| canonical_pair(a, b))
        .collect();
    let mut unresolved: BTreeSet<(String, String)> = BTreeSet::new();
    for (a, b) in detected {
        if let Some(pair) = canonical_pair(a, b)
            && !resolved_set.contains(&pair)
        {
            unresolved.insert(pair);
        }
    }
    unresolved.into_iter().collect()
}

/// Whether a memory id participates in any unresolved contradiction.
#[must_use]
pub fn is_in_unresolved_contradiction(memory_id: &str, unresolved: &[(String, String)]) -> bool {
    let id = memory_id.trim();
    !id.is_empty() && unresolved.iter().any(|(a, b)| a == id || b == id)
}

/// `forced`-mode view of one contradiction's members: ranked with the shared
/// trust -> authority -> verification -> validity -> confidence -> recency
/// comparator, then id, capped to `cap`. `total` is always the full count so
/// the cap is never a silent drop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForcedContradictionView {
    /// Ranked memory ids, capped to `cap`.
    pub shown: Vec<String>,
    /// Total members before the cap.
    pub total: usize,
}

/// Rank + cap contradiction members for `forced` mode. Deterministic.
#[must_use]
pub fn forced_contradiction_view(members: &[GuardedMemory], cap: usize) -> ForcedContradictionView {
    let mut ranked: Vec<&GuardedMemory> = members.iter().collect();
    ranked.sort_by(|a, b| {
        let left = precedence_from_guarded(a);
        let right = precedence_from_guarded(b);
        compare_precedence(&right, &left).then_with(|| a.memory_id.cmp(&b.memory_id))
    });
    let total = ranked.len();
    let shown = ranked
        .into_iter()
        .take(cap)
        .map(|memory| memory.memory_id.clone())
        .collect();
    ForcedContradictionView { shown, total }
}

#[cfg(test)]
mod tests {
    use super::{
        ContradictionPrecedence, DEFAULT_FORCED_CONTRADICTION_CAP, GuardedMemory, SuppressionBasis,
        decide_contradiction_survivor, decide_contradiction_survivor_with_precedence,
        forced_contradiction_view, is_in_unresolved_contradiction, unresolved_contradiction_pairs,
    };

    fn mem(id: &str, trust_milli: i64, freshness_epoch: i64) -> GuardedMemory {
        GuardedMemory {
            memory_id: id.to_string(),
            trust_milli,
            freshness_epoch,
        }
    }

    #[test]
    fn survivor_prefers_higher_trust_then_fresher_then_id() {
        // Higher trust wins regardless of freshness.
        let d = decide_contradiction_survivor(&mem("a", 900, 1), &mem("b", 100, 999));
        assert_eq!(d.kept_memory_id, "a");
        assert_eq!(d.suppressed_memory_id, "b");
        assert_eq!(d.basis, SuppressionBasis::HigherTrust);

        // Trust tie -> fresher wins.
        let d = decide_contradiction_survivor(&mem("a", 500, 10), &mem("b", 500, 20));
        assert_eq!(d.kept_memory_id, "b");
        assert_eq!(d.basis, SuppressionBasis::Fresher);

        // Full tie -> deterministic by id (lexically smaller kept).
        let d = decide_contradiction_survivor(&mem("z", 500, 10), &mem("a", 500, 10));
        assert_eq!(d.kept_memory_id, "a");
        assert_eq!(d.basis, SuppressionBasis::DeterministicTieBreak);
    }

    #[test]
    fn survivor_decision_is_symmetric_in_argument_order() {
        let forward = decide_contradiction_survivor(&mem("a", 500, 20), &mem("b", 700, 10));
        let reversed = decide_contradiction_survivor(&mem("b", 700, 10), &mem("a", 500, 20));
        assert_eq!(
            forward, reversed,
            "the survivor must not depend on arg order"
        );
        assert_eq!(forward.kept_memory_id, "b");
    }

    #[test]
    fn shared_precedence_covers_authority_verification_validity_confidence_and_recency() {
        let standing = |id: &str,
                        trust_rank: i64,
                        authority_rank: i64,
                        verification_rank: i64,
                        validity_rank: i64,
                        confidence_milli: i64,
                        recency_epoch: i64| ContradictionPrecedence {
            memory_id: id.to_owned(),
            trust_rank,
            authority_rank,
            verification_rank,
            validity_rank,
            confidence_milli,
            recency_epoch,
            recency_known: true,
        };

        let decision = decide_contradiction_survivor_with_precedence(
            &standing("current", 3_000, 0, 1, 1, 500, 1),
            &standing("expired", 3_000, 0, 1, 0, 1_000, 999),
        );
        assert_eq!(decision.kept_memory_id, "current");
        assert_eq!(decision.basis, SuppressionBasis::CurrentValidity);

        let decision = decide_contradiction_survivor_with_precedence(
            &standing("unchecked", 3_000, 0, 1, 1, 500, 1),
            &standing("verified", 3_000, 0, 3, 1, 100, 999),
        );
        assert_eq!(decision.kept_memory_id, "verified");
        assert_eq!(decision.basis, SuppressionBasis::HigherVerification);

        let decision = decide_contradiction_survivor_with_precedence(
            &standing("low", 3_000, 0, 1, 1, 500, 1),
            &standing("high", 3_000, 0, 1, 1, 900, 1),
        );
        assert_eq!(decision.kept_memory_id, "high");
        assert_eq!(decision.basis, SuppressionBasis::HigherConfidence);
    }

    #[test]
    fn unresolved_set_is_detected_minus_resolved() {
        let detected = vec![
            ("mem_a".to_string(), "mem_b".to_string()),
            ("mem_c".to_string(), "mem_d".to_string()),
            // duplicate in the other order — must collapse.
            ("mem_b".to_string(), "mem_a".to_string()),
        ];
        // Resolved pair given in the opposite order — canonicalization must match.
        let resolved = vec![("mem_b".to_string(), "mem_a".to_string())];
        let unresolved = unresolved_contradiction_pairs(&detected, &resolved);
        assert_eq!(
            unresolved,
            vec![("mem_c".to_string(), "mem_d".to_string())],
            "a->b is resolved and dedups; only c-d remains unresolved"
        );
        assert!(is_in_unresolved_contradiction("mem_c", &unresolved));
        assert!(!is_in_unresolved_contradiction("mem_a", &unresolved));
        assert!(!is_in_unresolved_contradiction("", &unresolved));
    }

    #[test]
    fn forced_view_ranks_caps_and_reports_total_no_silent_drop() {
        let members = vec![mem("low", 100, 1), mem("high", 900, 1), mem("mid", 500, 1)];
        let view = forced_contradiction_view(&members, 2);
        assert_eq!(
            view.total, 3,
            "total must reflect all members despite the cap"
        );
        assert_eq!(view.shown, vec!["high".to_string(), "mid".to_string()]);
        // A generous cap shows everyone.
        let full = forced_contradiction_view(&members, DEFAULT_FORCED_CONTRADICTION_CAP);
        assert_eq!(full.shown.len(), 3);
    }
}
