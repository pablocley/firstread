//! Verdicts: the few conclusions users and clients act on.

use crate::signal::ReasonKey;

/// The user-facing conclusions. Each maps to keywords, a folder key, a Subject prefix or a
/// webmail banner by threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerdictKind {
    /// Credential harvesting, fake login, fake payment page.
    Phishing,
    /// Business email compromise, invoice or bank-detail fraud.
    Fraud,
    /// Unwanted bulk mail.
    Junk,
    /// Worth the user's attention soon.
    Important,
    /// Expects an action or reply from the user.
    NeedsAction,
    /// Wanted bulk mail this person rarely reads: a quiet folder, an unsubscribe suggestion.
    BulkLowInterest,
}

impl VerdictKind {
    /// Name used in the stamp.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Phishing => "phishing",
            Self::Fraud => "fraud",
            Self::Junk => "junk",
            Self::Important => "important",
            Self::NeedsAction => "needs_action",
            Self::BulkLowInterest => "bulk_low_interest",
        }
    }

    /// Safety-floor verdicts: users can correct them per message, but cannot disable them for
    /// unauthenticated or lookalike senders (docs/02-signals.md).
    pub fn has_safety_floor(self) -> bool {
        matches!(self, Self::Phishing | Self::Fraud)
    }
}

/// A calibrated verdict with the reasons that contributed most.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    /// Which conclusion.
    pub kind: VerdictKind,
    /// Calibrated probability.
    pub p: f32,
    /// Top contributing reasons, most important first.
    pub reasons: Vec<ReasonKey>,
}
