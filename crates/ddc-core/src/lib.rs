//! Public primitives for DDC-OS v0.1.
//! Proprietary DDC internals are intentionally out of scope.

mod admission;

pub use admission::{
    assess, AdmissionDecision, AdmissionInput, AuthoritySet, RejectReason,
    VerificationEvidence,
};

use sha2::{Digest, Sha256};

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
        Self(hasher.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn hash_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Explicit resource dimensions for optimization admission.
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
    fn resource_caps_are_fail_closed() {
        let caps = ResourceVector {
            cpu_work_units: 10,
            memory_bytes: 20,
            io_bytes: 30,
            transport_bytes: 40,
        };
        assert!(caps.within(caps));
        assert!(!ResourceVector { memory_bytes: 21, ..caps }.within(caps));
    }
}
