use crate::ResourceVector;
use std::collections::BTreeSet;

/// Named capabilities visible at the public DDC-OS boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthoritySet(BTreeSet<String>);

impl AuthoritySet {
    pub fn new<I, S>(items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(items.into_iter().map(Into::into).collect())
    }

    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.0.is_subset(&other.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationEvidence {
    pub semantic_equivalent: bool,
    pub exact_state_bound: bool,
    pub uncommitted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionInput {
    pub baseline_authority: AuthoritySet,
    pub candidate_authority: AuthoritySet,
    pub candidate_resources: ResourceVector,
    pub resource_caps: ResourceVector,
    pub evidence: VerificationEvidence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    SemanticMismatch,
    StateNotBound,
    AuthorityExpansion,
    ResourceCapExceeded,
    AlreadyCommitted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionDecision {
    Accept,
    Reject(RejectReason),
}

/// Public fail-closed gate. Passing this gate means only that a candidate is
/// eligible for later performance selection; it is not a performance score.
pub fn assess(input: &AdmissionInput) -> AdmissionDecision {
    if !input.evidence.semantic_equivalent {
        return AdmissionDecision::Reject(RejectReason::SemanticMismatch);
    }
    if !input.evidence.exact_state_bound {
        return AdmissionDecision::Reject(RejectReason::StateNotBound);
    }
    if !input.evidence.uncommitted {
        return AdmissionDecision::Reject(RejectReason::AlreadyCommitted);
    }
    if !input.candidate_authority.is_subset_of(&input.baseline_authority) {
        return AdmissionDecision::Reject(RejectReason::AuthorityExpansion);
    }
    if !input.candidate_resources.within(input.resource_caps) {
        return AdmissionDecision::Reject(RejectReason::ResourceCapExceeded);
    }
    AdmissionDecision::Accept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> AdmissionInput {
        AdmissionInput {
            baseline_authority: AuthoritySet::new(["capability-a"]),
            candidate_authority: AuthoritySet::new(["capability-a"]),
            candidate_resources: ResourceVector {
                cpu_work_units: 10,
                memory_bytes: 10,
                io_bytes: 10,
                transport_bytes: 10,
            },
            resource_caps: ResourceVector {
                cpu_work_units: 20,
                memory_bytes: 20,
                io_bytes: 20,
                transport_bytes: 20,
            },
            evidence: VerificationEvidence {
                semantic_equivalent: true,
                exact_state_bound: true,
                uncommitted: true,
            },
        }
    }

    #[test]
    fn accepts_valid_candidate() {
        assert_eq!(assess(&valid()), AdmissionDecision::Accept);
    }

    #[test]
    fn rejects_capability_expansion() {
        let mut input = valid();
        input.candidate_authority = AuthoritySet::new(["capability-a", "capability-b"]);
        assert_eq!(
            assess(&input),
            AdmissionDecision::Reject(RejectReason::AuthorityExpansion)
        );
    }

    #[test]
    fn rejects_semantic_mismatch() {
        let mut input = valid();
        input.evidence.semantic_equivalent = false;
        assert_eq!(
            assess(&input),
            AdmissionDecision::Reject(RejectReason::SemanticMismatch)
        );
    }
}
