use crate::{Dimension, DimensionalSnapshot};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DimensionalClosure {
    pub changed: BTreeSet<Dimension>,
    pub permitted: BTreeSet<Dimension>,
    pub violations: BTreeSet<Dimension>,
}

impl DimensionalClosure {
    pub fn is_closed(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Public closure check for DDC-OS transition proposals.
///
/// This does not replicate private Crystalline DTC internals. It exposes the
/// testable public invariant that every observed dimensional change must be
/// inside the explicitly permitted transition envelope before a candidate can
/// advance even to shadow execution.
pub fn evaluate_dimensional_closure(
    before: &DimensionalSnapshot,
    after: &DimensionalSnapshot,
    permitted: &BTreeSet<Dimension>,
) -> DimensionalClosure {
    let changed = before.changed_dimensions(after);
    let violations = changed.difference(permitted).copied().collect();
    DimensionalClosure {
        changed,
        permitted: permitted.clone(),
        violations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ComputeId, FrequencyObservation, ResourceVector};

    fn id(label: &str) -> ComputeId {
        ComputeId::derive("closure-test", &[label.as_bytes()])
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

    #[test]
    fn unconserved_dimension_blocks_closure() {
        let before = snapshot();
        let mut after = before;
        after.physical = id("different-physical");
        let closure = evaluate_dimensional_closure(&before, &after, &BTreeSet::new());
        assert!(!closure.is_closed());
        assert_eq!(closure.violations, BTreeSet::from([Dimension::Physical]));
    }

    #[test]
    fn explicitly_permitted_observation_change_closes() {
        let before = snapshot();
        let mut after = before;
        after.frequency.event_count = 1;
        let permitted = BTreeSet::from([Dimension::Frequency]);
        let closure = evaluate_dimensional_closure(&before, &after, &permitted);
        assert!(closure.is_closed());
        assert_eq!(closure.changed, permitted);
    }
}
