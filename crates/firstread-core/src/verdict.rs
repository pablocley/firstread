//! Verdicts: the few conclusions users and clients act on.

use crate::signal::ReasonKey;

/// The user-facing conclusions. Each maps to keywords, a folder key, a Subject prefix or a
/// webmail banner by threshold.
///
/// The order of the variants is the order of precedence: the first verdict that holds is the one
/// the stamp names (`verdict=`), so a phish that is also bulk mail is called phishing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VerdictKind {
    /// Credential harvesting, fake login, fake payment page.
    Phishing,
    /// Business email compromise, invoice or bank-detail fraud.
    Fraud,
    /// Unwanted bulk mail.
    Junk,
    /// Expects an action or reply from the user.
    NeedsAction,
    /// Worth the user's attention soon.
    Important,
    /// Wanted bulk mail this person rarely reads: a quiet folder, an unsubscribe suggestion.
    BulkLowInterest,
}

impl VerdictKind {
    /// Every verdict, in order of precedence.
    pub const ALL: [Self; 6] = [
        Self::Phishing,
        Self::Fraud,
        Self::Junk,
        Self::NeedsAction,
        Self::Important,
        Self::BulkLowInterest,
    ];

    /// The verdict a stamp name stands for.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == name)
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_and_safety_comes_first() {
        for k in VerdictKind::ALL {
            assert_eq!(VerdictKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(VerdictKind::parse("spam"), None);
        let mut sorted = VerdictKind::ALL;
        sorted.sort();
        assert_eq!(sorted, VerdictKind::ALL);
        assert!(
            VerdictKind::Phishing < VerdictKind::Junk && VerdictKind::Junk < VerdictKind::Important
        );
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
