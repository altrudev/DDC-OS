//! Public primitives for DDC-OS.
//! Proprietary DDC internals are intentionally out of scope.

mod admission;
mod channels;
mod closure;
mod dimensions;
mod os_policy;
mod radial;
mod sha256;
mod store;
mod transition;

pub use admission::{
    admit_exact, dependency_state_id, AdmissionInput, AdmissionPermit, AuthoritySet, RejectReason,
};
pub use channels::{
    estimate_shared_delta_work, group_by_shared_state, ChannelDescriptor, WorkEstimate,
};
pub use closure::{evaluate_dimensional_closure, DimensionalClosure};
pub use dimensions::{Dimension, DimensionalSnapshot, FrequencyObservation};
pub use os_policy::{
    propose_shared_delta, BaselineReason, BaselineTask, EffectClass, ExecutionDescriptor,
    PolicyCaps, PolicyProposal, PolicyRejectReason, SecurityContext, SharedDeltaCandidate,
    ABSOLUTE_MAX_GROUP_MEMBERS,
};
pub use radial::{RadialDisposition, RadialEvidence, RadialFinding, RadialSignal};
pub use store::{StoreRejectReason, VerifiedStore};
pub use transition::{
    evaluate_transition, TransitionDecision, TransitionDisposition, TransitionProposal,
    TransitionReason,
};

use sha256::Sha256;

/// Stable identity for a computation or dependency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComputeId([u8; 32]);

impl ComputeId {
    /// Derive a domain-separated identity from length-prefixed byte parts.
    /// Length prefixes prevent ambiguous concatenations.
    pub fn derive(domain: &str, parts: &[&[u8]]) -> Self {
        let mut hasher = Sha256::new();
        hash_part(&mut hasher, b"DDC-OS-CID-v0.1");
        hash_part(&mut hasher, domain.as_bytes());
        for part in parts {
            hash_part(&mut hasher, part);
        }
        Self(hasher.finalize())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn hash_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Explicit resource dimensions for optimization admission and planning.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourceVector {
    pub cpu_work_units: u64,
    pub memory_bytes: u64,
    pub io_bytes: u64,
    pub transport_bytes: u64,
}

impl ResourceVector {
    pub fn within(self, caps: Self) -> bool {
        self.cpu_work_units <= caps.cpu_work_units
            && self.memory_bytes <= caps.memory_bytes
            && self.io_bytes <= caps.io_bytes
            && self.transport_bytes <= caps.transport_bytes
    }

    /// Overflow-safe aggregation for group planning.
    pub fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            cpu_work_units: self.cpu_work_units.checked_add(other.cpu_work_units)?,
            memory_bytes: self.memory_bytes.checked_add(other.memory_bytes)?,
            io_bytes: self.io_bytes.checked_add(other.io_bytes)?,
            transport_bytes: self.transport_bytes.checked_add(other.transport_bytes)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_not_ambiguous_concatenation() {
        let a = ComputeId::derive("test", &[b"ab", b"c"]);
        let b = ComputeId::derive("test", &[b"a", b"bc"]);
        assert_ne!(a, b);
    }

    #[test]
    fn internal_hash_preserves_v01_compute_identity_bytes() {
        let expected = [
            0x08, 0x27, 0x2e, 0x03, 0x16, 0x18, 0xf3, 0xd4, 0xfd, 0xb0, 0xee, 0x90, 0x6e, 0x5d,
            0xd8, 0x62, 0x06, 0x6b, 0x77, 0x3e, 0xfb, 0xde, 0x2a, 0x20, 0x41, 0x50, 0xce, 0x0e,
            0x18, 0x5e, 0xfb, 0x0d,
        ];
        assert_eq!(
            ComputeId::derive("test", &[b"ab", b"c"]).as_bytes(),
            &expected
        );
    }

    #[test]
    fn resource_caps_are_fail_closed() {
        let caps = ResourceVector {
            cpu_work_units: 10,
            memory_bytes: 20,
            io_bytes: 30,
            transport_bytes: 40,
        };
        assert!(caps.within(caps));
        assert!(!ResourceVector {
            memory_bytes: 21,
            ..caps
        }
        .within(caps));
    }

    #[test]
    fn resource_aggregation_detects_overflow() {
        let maxed = ResourceVector {
            cpu_work_units: u64::MAX,
            memory_bytes: 0,
            io_bytes: 0,
            transport_bytes: 0,
        };
        let one = ResourceVector {
            cpu_work_units: 1,
            ..ResourceVector::default()
        };
        assert_eq!(maxed.checked_add(one), None);
    }
}
