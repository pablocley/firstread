//! Typed decisions: the JEV-shaped contract shared by every model tier.
//!
//! A question has one of three types. Every answer is a calibrated probability distribution,
//! so each action can have its own threshold. Tier 1 heads and the tier 2 decision model return
//! the same types; swapping a model is a configuration change.

use crate::tier::Tier;

/// Stable identifier of a question, e.g. `asks_payment_or_bank_change` or a user rule id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QuestionId(pub String);

/// What kind of answer a question expects.
#[derive(Debug, Clone, PartialEq)]
pub enum QuestionKind {
    /// Is the statement true? Answer: P(false), P(true).
    Noul,
    /// Which of these options? Options are named; order is the order of the answer.
    Choice {
        /// Option names, at least two.
        options: Vec<String>,
    },
    /// Where on this ordered scale? Level 0 first.
    Score {
        /// Level descriptions, at least two.
        levels: Vec<String>,
    },
}

/// A typed question about a message.
#[derive(Debug, Clone, PartialEq)]
pub struct Question {
    /// Stable id, used for heads, labels and calibration files.
    pub id: QuestionId,
    /// The question or statement in natural language (what a decision model reads).
    pub text: String,
    /// The answer type.
    pub kind: QuestionKind,
}

/// Why a distribution was rejected.
#[derive(Debug, Clone, PartialEq)]
pub enum DistributionError {
    /// No probabilities, or fewer than two outcomes.
    TooFewOutcomes,
    /// A probability outside 0..=1 or not finite.
    OutOfRange,
    /// Probabilities do not sum to 1 within tolerance.
    NotNormalised,
    /// Number of probabilities does not match the question's outcomes.
    ShapeMismatch,
}

/// A validated probability distribution over a question's outcomes.
#[derive(Debug, Clone, PartialEq)]
pub struct Distribution(Vec<f32>);

impl Distribution {
    /// Tolerance for the sum of probabilities.
    pub const SUM_TOLERANCE: f32 = 1e-3;

    /// Validate and wrap probabilities.
    pub fn new(p: Vec<f32>) -> Result<Self, DistributionError> {
        if p.len() < 2 {
            return Err(DistributionError::TooFewOutcomes);
        }
        if p.iter().any(|x| !x.is_finite() || *x < 0.0 || *x > 1.0) {
            return Err(DistributionError::OutOfRange);
        }
        let sum: f32 = p.iter().sum();
        if (sum - 1.0).abs() > Self::SUM_TOLERANCE {
            return Err(DistributionError::NotNormalised);
        }
        Ok(Self(p))
    }

    /// Softmax of logits divided by a calibration temperature.
    pub fn from_logits(logits: &[f32], temperature: f32) -> Result<Self, DistributionError> {
        if logits.len() < 2 {
            return Err(DistributionError::TooFewOutcomes);
        }
        if !temperature.is_finite() || temperature <= 0.0 || logits.iter().any(|x| !x.is_finite()) {
            return Err(DistributionError::OutOfRange);
        }
        let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let exps: Vec<f32> = logits
            .iter()
            .map(|z| ((z - max) / temperature).exp())
            .collect();
        let sum: f32 = exps.iter().sum();
        Self::new(exps.into_iter().map(|e| e / sum).collect())
    }

    /// The probabilities, in outcome order.
    pub fn probabilities(&self) -> &[f32] {
        &self.0
    }

    /// Index and probability of the most likely outcome.
    pub fn top(&self) -> (usize, f32) {
        self.0
            .iter()
            .copied()
            .enumerate()
            .fold(
                (0, f32::MIN),
                |best, (i, p)| if p > best.1 { (i, p) } else { best },
            )
    }

    /// Expected level for score questions (0-based).
    pub fn expected_level(&self) -> f32 {
        self.0.iter().enumerate().map(|(i, p)| i as f32 * p).sum()
    }
}

/// Which model release produced an answer, recorded in every stamp.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModelRelease(pub String);

/// A calibrated answer to one question.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    /// The question answered.
    pub question: QuestionId,
    /// The calibrated distribution over the question's outcomes.
    pub distribution: Distribution,
    /// Tier that produced it.
    pub tier: Tier,
    /// Model release that produced it.
    pub model: ModelRelease,
}

impl Decision {
    /// Check the distribution matches the question's number of outcomes.
    pub fn validate_against(&self, q: &Question) -> Result<(), DistributionError> {
        let expected = match &q.kind {
            QuestionKind::Noul => 2,
            QuestionKind::Choice { options } => options.len(),
            QuestionKind::Score { levels } => levels.len(),
        };
        if self.distribution.probabilities().len() == expected {
            Ok(())
        } else {
            Err(DistributionError::ShapeMismatch)
        }
    }

    /// P(true) for a `noul` question (outcome order: false, true).
    pub fn p_true(&self) -> Option<f32> {
        match self.distribution.probabilities() {
            [_, t] => Some(*t),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unnormalised() {
        assert_eq!(
            Distribution::new(vec![0.5, 0.6]),
            Err(DistributionError::NotNormalised)
        );
    }

    #[test]
    fn rejects_single_outcome() {
        assert_eq!(
            Distribution::new(vec![1.0]),
            Err(DistributionError::TooFewOutcomes)
        );
    }

    #[test]
    fn softmax_with_temperature() {
        let d = Distribution::from_logits(&[0.0, 0.0], 1.0).unwrap();
        assert!((d.probabilities()[0] - 0.5).abs() < 1e-6);
        let sharp = Distribution::from_logits(&[0.0, 1.0], 0.5).unwrap();
        let soft = Distribution::from_logits(&[0.0, 1.0], 2.0).unwrap();
        assert!(sharp.probabilities()[1] > soft.probabilities()[1]);
    }

    #[test]
    fn expected_level() {
        let d = Distribution::new(vec![0.0, 0.5, 0.5]).unwrap();
        assert!((d.expected_level() - 1.5).abs() < 1e-6);
    }

    #[test]
    fn shape_checked_against_question() {
        let q = Question {
            id: QuestionId("kind".into()),
            text: "What kind of email is this?".into(),
            kind: QuestionKind::Choice {
                options: vec!["a".into(), "b".into(), "c".into()],
            },
        };
        let d = Decision {
            question: q.id.clone(),
            distribution: Distribution::new(vec![0.5, 0.5]).unwrap(),
            tier: Tier::SmallModels,
            model: ModelRelease("test".into()),
        };
        assert_eq!(
            d.validate_against(&q),
            Err(DistributionError::ShapeMismatch)
        );
    }
}
