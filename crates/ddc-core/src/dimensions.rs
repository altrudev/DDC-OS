use crate::{ComputeId, ResourceVector};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dimension {
    Semantic,
    Authority,
    State,
    Resource,
    Security,
    Physical,
    Frequency,
    Lineage,
}

impl Dimension {
    pub const ALL: [Dimension; 8] = [
        Dimension::Semantic,
        Dimension::Authority,
        Dimension::State,
        Dimension::Resource,
        Dimension::Security,
        Dimension::Physical,
        Dimension::Frequency,
        Dimension::Lineage,
    ];
}

/// Frequency is intentionally observational in DDC-OS v0.3.
/// It may influence evidence and profitability analysis, but it cannot create
/// identity, equivalence, integrity, or execution authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrequencyObservation {
    pub sample_window_ns: u64,
    pub event_count: u64,
    pub recurrence_count: u64,
}

impl FrequencyObservation {
    pub const fn is_authoritative(self) -> bool {
        false
    }
}

/// Public eight-dimensional snapshot compatible with the current DDC boundary.
///
/// This is a public contract only. It does not expose private DDC scoring,
/// heuristics, or Crystalline implementation details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DimensionalSnapshot {
    pub semantic: ComputeId,
    pub authority: ComputeId,
    pub state: ComputeId,
    pub resource: ResourceVector,
    pub security: ComputeId,
    pub physical: ComputeId,
    pub frequency: FrequencyObservation,
    pub lineage: ComputeId,
}

impl DimensionalSnapshot {
    pub fn changed_dimensions(&self, other: &Self) -> BTreeSet<Dimension> {
        let mut changed = BTreeSet::new();
        if self.semantic != other.semantic {
            changed.insert(Dimension::Semantic);
        }
        if self.authority != other.authority {
            changed.insert(Dimension::Authority);
        }
        if self.state != other.state {
            changed.insert(Dimension::State);
        }
        if self.resource != other.resource {
            changed.insert(Dimension::Resource);
        }
        if self.security != other.security {
            changed.insert(Dimension::Security);
        }
        if self.physical != other.physical {
            changed.insert(Dimension::Physical);
        }
        if self.frequency != other.frequency {
            changed.insert(Dimension::Frequency);
        }
        if self.lineage != other.lineage {
            changed.insert(Dimension::Lineage);
        }
        changed
    }

    /// Structural boundary identity excluding Frequency by design.
    ///
    /// This makes the non-authoritative status of Frequency testable: changing
    /// only an observation cadence cannot silently manufacture a new execution
    /// identity or authorization boundary.
    pub fn non_frequency_boundary_id(&self) -> ComputeId {
        let cpu = self.resource.cpu_work_units.to_le_bytes();
        let memory = self.resource.memory_bytes.to_le_bytes();
        let io = self.resource.io_bytes.to_le_bytes();
        let transport = self.resource.transport_bytes.to_le_bytes();
        ComputeId::derive(
            "ddc-os-dimensional-boundary-v0.3",
            &[
                self.semantic.as_bytes(),
                self.authority.as_bytes(),
                self.state.as_bytes(),
                &cpu,
                &memory,
                &io,
                &transport,
                self.security.as_bytes(),
                self.physical.as_bytes(),
                self.lineage.as_bytes(),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(label: &str) -> ComputeId {
        ComputeId::derive("dimensions-test", &[label.as_bytes()])
    }

    fn snapshot() -> DimensionalSnapshot {
        DimensionalSnapshot {
            semantic: id("semantic"),
            authority: id("authority"),
            state: id("state"),
            resource: ResourceVector {
                cpu_work_units: 1,
                memory_bytes: 2,
                io_bytes: 3,
                transport_bytes: 4,
            },
            security: id("security"),
            physical: id("physical"),
            frequency: FrequencyObservation {
                sample_window_ns: 1_000,
                event_count: 10,
                recurrence_count: 4,
            },
            lineage: id("lineage"),
        }
    }

    #[test]
    fn all_eight_dimensions_are_present() {
        assert_eq!(Dimension::ALL.len(), 8);
        assert_eq!(Dimension::ALL[6], Dimension::Frequency);
    }

    #[test]
    fn frequency_is_observational_only() {
        assert!(!snapshot().frequency.is_authoritative());
    }

    #[test]
    fn frequency_change_is_observed_but_does_not_change_boundary_identity() {
        let before = snapshot();
        let mut after = before;
        after.frequency.event_count += 1;
        assert_eq!(
            before.non_frequency_boundary_id(),
            after.non_frequency_boundary_id()
        );
        assert_eq!(
            before.changed_dimensions(&after),
            BTreeSet::from([Dimension::Frequency])
        );
    }
}
