use crate::{ComputeId, Dimension};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RadialSignal {
    Supports,
    Contradicts,
    Unresolved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RadialFinding {
    pub lens: Dimension,
    pub evidence: ComputeId,
    pub signal: RadialSignal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RadialDisposition {
    Insufficient,
    Consistent,
    Contradictory,
    Unresolved,
}

/// Radial is an evidence-generation fabric, never an authority source.
///
/// Findings preserve the lens that produced them so disagreement is retained
/// rather than averaged away. Distinct lenses are not automatically independent
/// failure paths; independence remains a separate assurance question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RadialEvidence {
    pub subject: ComputeId,
    findings: Vec<RadialFinding>,
}

impl RadialEvidence {
    pub fn new(subject: ComputeId) -> Self {
        Self {
            subject,
            findings: Vec::new(),
        }
    }

    pub fn push(&mut self, finding: RadialFinding) {
        self.findings.push(finding);
    }

    pub fn findings(&self) -> &[RadialFinding] {
        &self.findings
    }

    pub fn disposition(&self) -> RadialDisposition {
        if self
            .findings
            .iter()
            .any(|finding| finding.signal == RadialSignal::Contradicts)
        {
            return RadialDisposition::Contradictory;
        }
        if self
            .findings
            .iter()
            .any(|finding| finding.signal == RadialSignal::Unresolved)
        {
            return RadialDisposition::Unresolved;
        }

        let lenses: BTreeSet<Dimension> =
            self.findings.iter().map(|finding| finding.lens).collect();
        if !self.findings.is_empty() && lenses.len() >= 2 {
            RadialDisposition::Consistent
        } else {
            RadialDisposition::Insufficient
        }
    }

    /// Explicit negative authority contract. Radial evidence can support a
    /// later DDC gate but can never itself authorize execution.
    pub const fn authorizes_execution(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(label: &str) -> ComputeId {
        ComputeId::derive("radial-test", &[label.as_bytes()])
    }

    #[test]
    fn one_lens_is_insufficient() {
        let mut radial = RadialEvidence::new(id("subject"));
        radial.push(RadialFinding {
            lens: Dimension::Semantic,
            evidence: id("semantic-evidence"),
            signal: RadialSignal::Supports,
        });
        assert_eq!(radial.disposition(), RadialDisposition::Insufficient);
    }

    #[test]
    fn distinct_lenses_can_be_consistent_but_never_create_authority() {
        let mut radial = RadialEvidence::new(id("subject"));
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
        assert_eq!(radial.disposition(), RadialDisposition::Consistent);
        assert!(!radial.authorizes_execution());
    }

    #[test]
    fn contradiction_is_preserved() {
        let mut radial = RadialEvidence::new(id("subject"));
        radial.push(RadialFinding {
            lens: Dimension::Semantic,
            evidence: id("supports"),
            signal: RadialSignal::Supports,
        });
        radial.push(RadialFinding {
            lens: Dimension::Physical,
            evidence: id("contradicts"),
            signal: RadialSignal::Contradicts,
        });
        assert_eq!(radial.disposition(), RadialDisposition::Contradictory);
    }
}
