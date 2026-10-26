//! Feedback: what people do with their mail, turned into labels (docs/08-learning.md).
//!
//! firstread learns mostly from behaviour people show anyway. Weak signals never act alone; their
//! weights are learned against strong labels. Clicks, read receipts and reading time are not
//! collected, so they have no variant here.

use crate::verdict::VerdictKind;

/// Something a person (or ground truth) did that teaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Moved into Junk.
    MovedToJunk,
    /// Moved out of Junk.
    MovedFromJunk,
    /// Moved into one of the user's own folders.
    MovedToFolder(String),
    /// The client set `$Junk` or `$NotJunk`.
    MarkedJunk(bool),
    /// A firstread tag was removed (false) or added (true) by the user.
    TagEdited {
        /// Tag id without prefix.
        tag: String,
        /// Added (true) or removed (false).
        added: bool,
    },
    /// Replied to the message.
    Replied,
    /// Forwarded the message.
    Forwarded,
    /// Flagged the message.
    Flagged,
    /// Read the message.
    Read,
    /// Deleted without reading.
    DeletedUnread,
    /// One-tap verdict from a webmail banner or the digest.
    Verdict {
        /// Which verdict the user judged.
        kind: VerdictKind,
        /// The user says the verdict applies (true) or does not (false).
        applies: bool,
    },
    /// A campaign this message belongs to was confirmed bad on the platform or commons.
    CampaignConfirmedBad,
    /// Support or abuse staff labelled the message.
    StaffLabel(VerdictKind),
}

/// Where the feedback came from, which bounds how far it may propagate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The mailbox owner's own action.
    User,
    /// An organisation admin.
    OrganisationAdmin,
    /// Platform ground truth (campaign confirmation, staff).
    Platform,
    /// A commons indicator.
    Commons,
}

/// How much a feedback event says. Defaults; learned weights replace them per mailbox type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    /// Never acts alone; aggregated and weighted against strong labels.
    Weak,
    /// Acts in combination.
    Medium,
    /// Acts on its own.
    Strong,
}

impl Action {
    /// Default strength before learned weights exist.
    pub fn default_strength(&self) -> Strength {
        match self {
            Self::Read | Self::DeletedUnread => Strength::Weak,
            Self::Replied | Self::Forwarded | Self::Flagged => Strength::Medium,
            _ => Strength::Strong,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behaviour_without_intent_is_weak() {
        assert_eq!(Action::DeletedUnread.default_strength(), Strength::Weak);
        assert_eq!(Action::Read.default_strength(), Strength::Weak);
        assert_eq!(Action::MovedFromJunk.default_strength(), Strength::Strong);
    }
}
