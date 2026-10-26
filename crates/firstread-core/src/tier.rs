//! Cost tiers. Work runs cheapest first; a tier only runs if it can change the answer.

use std::time::{Duration, Instant};

/// Which tier produced a signal or decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// Deterministic checks, extractors and static embeddings. Every message, inline.
    Deterministic = 0,
    /// One contextual embedding plus small calibrated heads. Inline with a deadline, else async.
    SmallModels = 1,
    /// A full typed-decision model. Asynchronous only.
    DecisionModel = 2,
}

impl Tier {
    /// Numeric form used in the `tiers=` field of the stamp.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A hard deadline for inline work. When it expires, the caller delivers with what it has.
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    at: Instant,
}

impl Deadline {
    /// A deadline `budget` from now.
    pub fn after(budget: Duration) -> Self {
        Self {
            at: Instant::now() + budget,
        }
    }

    /// Time left, or zero.
    pub fn remaining(&self) -> Duration {
        self.at.saturating_duration_since(Instant::now())
    }

    /// Whether the deadline has passed.
    pub fn expired(&self) -> bool {
        self.remaining().is_zero()
    }
}
