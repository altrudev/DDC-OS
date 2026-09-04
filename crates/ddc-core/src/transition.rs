use crate::{
    evaluate_dimensional_closure, ComputeId, Dimension, DimensionalClosure, DimensionalSnapshot,
    RadialDisposition, RadialEvidence,
};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionDisposition {
    Baseline,
    ShadowEligible,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionReason {
    StalePredecessor,
    RadialSubjectMismatch,
    RadialInsufficient,
    RadialUnresolved,
    RadialContradiction,
    DimensionalClosureViolation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionProposal {
    pub predecessor: ComputeId,
    pub successor_candidate: ComputeId,
    pub before: DimensionalSnapshot,
    pub after: DimensionalSnapshot,
    pub permitted_changes: BTreeSet<Dimension>,
    pub radial: RadialEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionDecision {
    pub disposition: TransitionDisposition,
    pub reason: Option<TransitionReason>,
    pub closure: DimensionalClosure,
}

fn baseline_decision(closure: &DimensionalClosure, reason: TransitionReason) -> TransitionDecision {
    TransitionDecision {
        disposition: TransitionDisposition::Baseline,
        reason: Some(reason),
        closure: closure.clone(),
    }
}

/// Evaluate only whether a proposal may advance to bounded shadow execution.
///
/// A successful result is deliberately `ShadowEligible`, never `Authorized`.
/// Actual execution authority remains outside this public Radial/closure layer
/// and must come from the normal DDC authority and admission boundary.
pub fn evaluate_transition(
    expected_predecessor: ComputeId,
    proposal: &TransitionProposal,
) -> TransitionDecision {
    let closure = evaluate_dimensional_closure(
        &proposal.before,
        &proposal.after,
        &proposal.permitted_changes,
    );

    if proposal.predecessor != expected_predecessor {
        return baseline_decision(&closure, TransitionReason::StalePredecessor);
    }
    if proposal.radial.subject != proposal.successor_candidate {
        return baseline_decision(&closure, TransitionReason::RadialSubjectMismatch);
    }
    if !closure.is_closed() {
        return baseline_decision(&closure, TransitionReason::DimensionalClosureViolation);
    }

    match proposal.radial.disposition() {
        RadialDisposition::Insufficient => {
            baseline_decision(&closure, TransitionReason::RadialInsufficient)
        }
        RadialDisposition::Unresolved => {
            baseline_decision(&closure, TransitionReason::RadialUnresolved)
        }
        RadialDisposition::Contradictory => {
            baseline_decision(&closure, TransitionReason::RadialContradiction)
        }
        RadialDisposition::Consistent => TransitionDecision {
            disposition: TransitionDisposition::ShadowEligible,
            reason: None,
            closure,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FrequencyObservation, RadialFinding, RadialSignal, ResourceVector};

    fn id(label: &str) -> ComputeId {
        ComputeId::derive("transition-test", &[label.as_bytes()])
    }

    fn snapshot() -> DimensionalSnapshot {
        DimensionalSnapshot {
            semantic: id("semantic"),
            authority: id("authority"),
            state: id("state"),
            resource: ResourceVector::default(),
            security: id("security"),
            physical: id("physical"),
            frequency: FrequencyObservation::default(),
            lineage: id("lineage"),
        }
    }

    fn consistent_radial(subject: ComputeId) -> RadialEvidence {
        let mut radial = RadialEvidence::new(subject);
        radial.push(RadialFinding {
            lens: Dimension::Semantic,
            evidence: id("semantic-evidence"),
            signal: RadialSignal::Supports,
        });
        radial.push(RadialFinding {
            lens: Dimension::Frequency,
            evidence: id("frequency-evidence"),
            signal: RadialSignal::Supports,
        });
        radial
    }

    #[test]
    fn stale_predecessor_falls_back() {
        let successor = id("successor");
        let proposal = TransitionProposal {
            predecessor: id("old"),
            successor_candidate: successor,
            before: snapshot(),
            after: snapshot(),
            permitted_changes: BTreeSet::new(),
            radial: consistent_radial(successor),
        };
        let decision = evaluate_transition(id("expected"), &proposal);
        assert_eq!(decision.disposition, TransitionDisposition::Baseline);
        assert_eq!(decision.reason, Some(TransitionReason::StalePredecessor));
    }

    #[test]
    fn radial_contradiction_falls_back() {
        let successor = id("successor");
        let mut radial = consistent_radial(successor);
        radial.push(RadialFinding {
            lens: Dimension::Physical,
            evidence: id("contradiction"),
            signal: RadialSignal::Contradicts,
        });
        let predecessor = id("predecessor");
        let proposal = TransitionProposal {
            predecessor,
            successor_candidate: successor,
            before: snapshot(),
            after: snapshot(),
            permitted_changes: BTreeSet::new(),
            radial,
        };
        let decision = evaluate_transition(predecessor, &proposal);
        assert_eq!(decision.disposition, TransitionDisposition::Baseline);
        assert_eq!(decision.reason, Some(TransitionReason::RadialContradiction));
    }

    #[test]
    fn consistent_closed_proposal_is_only_shadow_eligible() {
        let predecessor = id("predecessor");
        let successor = id("successor");
        let before = snapshot();
        let mut after = before;
        after.frequency.event_count = 2;
        let proposal = TransitionProposal {
            predecessor,
            successor_candidate: successor,
            before,
            after,
            permitted_changes: BTreeSet::from([Dimension::Frequency]),
            radial: consistent_radial(successor),
        };
        let decision = evaluate_transition(predecessor, &proposal);
        assert_eq!(decision.disposition, TransitionDisposition::ShadowEligible);
        assert_eq!(decision.reason, None);
        assert!(!proposal.radial.authorizes_execution());
    }
}
