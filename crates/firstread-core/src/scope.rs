//! Scopes and the rules for what may cross between them (docs/08-learning.md).
//!
//! The gate functions here are the single place that decides whether something learned in one
//! scope may influence another. Everything that moves data between scopes must go through them.

/// How much of the platform a piece of knowledge comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    /// The message alone.
    Message,
    /// This mailbox's history and behaviour.
    Mailbox,
    /// The mailboxes of one customer, when its admin enabled sharing.
    Organisation,
    /// Every mailbox on this deployment, as aggregates over infrastructure and bulk content.
    Platform,
    /// Other deployments, through a commons hub: bad-only, gated indicators.
    Commons,
}

/// Direction of a label as far as propagation is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polarity {
    /// Evidence that something is bad (junk, scam, malicious).
    Bad,
    /// Evidence that something is fine or wanted.
    Good,
}

/// Inputs to the platform gate for one aggregate key.
#[derive(Debug, Clone, Copy)]
pub struct AggregateEvidence {
    /// Distinct established mailboxes that contributed.
    pub distinct_mailboxes: u64,
    /// Polarity of the evidence.
    pub polarity: Polarity,
}

/// Deployment-configured thresholds.
#[derive(Debug, Clone, Copy)]
pub struct Gates {
    /// Minimum distinct mailboxes before an aggregate may influence other mailboxes.
    pub k_platform: u64,
    /// Minimum distinct mailboxes before content counts as bulk.
    pub k_bulk: u64,
}

impl Gates {
    /// May this evidence influence mailboxes other than its contributors?
    ///
    /// "Good" evidence never leaves the mailbox / organisation: a few accounts must not be able to
    /// whitelist a campaign for everyone.
    pub fn allows_platform(&self, e: AggregateEvidence) -> bool {
        e.polarity == Polarity::Bad && e.distinct_mailboxes >= self.k_platform
    }

    /// Is this content bulk, and therefore allowed to teach beyond one mailbox?
    pub fn is_bulk(&self, distinct_mailboxes: u64) -> bool {
        distinct_mailboxes >= self.k_bulk
    }

    /// May this evidence be offered to the commons? Same as the platform gate; the commons client
    /// applies its own additional checks (confirmation, indicator type).
    pub fn allows_commons(&self, e: AggregateEvidence) -> bool {
        self.allows_platform(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: Gates = Gates {
        k_platform: 5,
        k_bulk: 20,
    };

    #[test]
    fn good_evidence_never_crosses() {
        let e = AggregateEvidence {
            distinct_mailboxes: 1_000_000,
            polarity: Polarity::Good,
        };
        assert!(!G.allows_platform(e));
        assert!(!G.allows_commons(e));
    }

    #[test]
    fn bad_evidence_needs_k() {
        let few = AggregateEvidence {
            distinct_mailboxes: 4,
            polarity: Polarity::Bad,
        };
        let enough = AggregateEvidence {
            distinct_mailboxes: 5,
            polarity: Polarity::Bad,
        };
        assert!(!G.allows_platform(few));
        assert!(G.allows_platform(enough));
    }

    #[test]
    fn personal_mail_is_not_bulk() {
        assert!(!G.is_bulk(1));
        assert!(G.is_bulk(20));
    }
}
