//! Reputation counters: the fastest learner. A Beta-binomial posterior per key, with exponential
//! decay so old behaviour fades. Reports a mean *and* how much evidence backs it, so a sender seen
//! once is not treated like a sender seen ten thousand times.

/// Posterior over "this key's mail is bad", from weighted good / bad observations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BetaCounter {
    bad: f64,
    good: f64,
    prior_bad: f64,
    prior_good: f64,
}

impl BetaCounter {
    /// A counter with a Beta(prior_bad, prior_good) prior.
    pub fn new(prior_bad: f64, prior_good: f64) -> Self {
        Self {
            bad: 0.0,
            good: 0.0,
            prior_bad,
            prior_good,
        }
    }

    /// Add one observation with a weight (label strength times account trust).
    pub fn observe(&mut self, bad: bool, weight: f64) {
        if bad {
            self.bad += weight;
        } else {
            self.good += weight;
        }
    }

    /// Multiply all evidence by `factor` (0..=1), e.g. once per day for decay.
    pub fn decay(&mut self, factor: f64) {
        let f = factor.clamp(0.0, 1.0);
        self.bad *= f;
        self.good *= f;
    }

    /// Posterior mean probability of "bad".
    pub fn mean_bad(&self) -> f64 {
        let a = self.bad + self.prior_bad;
        let b = self.good + self.prior_good;
        a / (a + b)
    }

    /// Weighted evidence observed (excluding the prior).
    pub fn evidence(&self) -> f64 {
        self.bad + self.good
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prior_dominates_until_evidence_arrives() {
        let mut c = BetaCounter::new(1.0, 9.0);
        assert!((c.mean_bad() - 0.1).abs() < 1e-9);
        for _ in 0..90 {
            c.observe(true, 1.0);
        }
        assert!(c.mean_bad() > 0.9);
        assert!((c.evidence() - 90.0).abs() < 1e-9);
    }

    #[test]
    fn decay_returns_towards_prior() {
        let mut c = BetaCounter::new(1.0, 1.0);
        for _ in 0..100 {
            c.observe(true, 1.0);
        }
        let before = c.mean_bad();
        c.decay(0.01);
        assert!(c.mean_bad() < before);
        assert!(c.mean_bad() > 0.5);
    }
}
