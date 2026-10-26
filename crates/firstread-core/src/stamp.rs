//! The stamp: what is written into the message (headers), set on it (keywords), and kept
//! for the API. See docs/03-client-contract.md.

use crate::decision::ModelRelease;
use crate::tier::Tier;
use crate::verdict::Verdict;

/// IMAP / JMAP keywords firstread may set. Registered keywords first; our own use a fixed prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Keyword {
    /// `$Phishing` (IANA registry).
    Phishing,
    /// `$Junk` (IANA registry).
    Junk,
    /// `$Important` (RFC 8457).
    Important,
    /// `$CanUnsubscribe` (RFC 9979).
    CanUnsubscribe,
    /// `$Unsubscribed` (RFC 9979).
    Unsubscribed,
    /// `$Autosent` (RFC 9979).
    Autosent,
    /// `$HasAttachment` (RFC 9979).
    HasAttachment,
    /// `$HasNoAttachment` (RFC 9979).
    HasNoAttachment,
    /// `$IsTrusted` (RFC 9979).
    IsTrusted,
    /// A firstread tag, written as `fr-<id>`; `id` is a stable lowercase identifier.
    Tag(String),
}

/// Prefix for firstread's own keywords.
pub const TAG_PREFIX: &str = "fr-";

impl Keyword {
    /// The keyword as sent to the IMAP server.
    pub fn as_imap(&self) -> String {
        match self {
            Self::Phishing => "$Phishing".into(),
            Self::Junk => "$Junk".into(),
            Self::Important => "$Important".into(),
            Self::CanUnsubscribe => "$CanUnsubscribe".into(),
            Self::Unsubscribed => "$Unsubscribed".into(),
            Self::Autosent => "$Autosent".into(),
            Self::HasAttachment => "$HasAttachment".into(),
            Self::HasNoAttachment => "$HasNoAttachment".into(),
            Self::IsTrusted => "$IsTrusted".into(),
            Self::Tag(id) => format!("{TAG_PREFIX}{id}"),
        }
    }
}

/// Opaque id linking a stamped message to its full record in the API.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StampId(pub String);

/// Everything decided about one message for one mailbox.
#[derive(Debug, Clone, PartialEq)]
pub struct Stamp {
    /// API lookup id.
    pub id: StampId,
    /// Tiers that completed before delivery.
    pub tiers: Vec<Tier>,
    /// Model releases involved.
    pub models: Vec<ModelRelease>,
    /// Verdicts with probabilities and reasons.
    pub verdicts: Vec<Verdict>,
    /// Keywords to set.
    pub keywords: Vec<Keyword>,
    /// Campaign cluster id and size, when part of one.
    pub campaign: Option<(String, u32)>,
}

impl Stamp {
    /// The `tiers=` field, e.g. `0,1`.
    pub fn tiers_field(&self) -> String {
        let mut t: Vec<u8> = self.tiers.iter().map(|t| t.as_u8()).collect();
        t.sort_unstable();
        t.dedup();
        t.iter().map(u8::to_string).collect::<Vec<_>>().join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_keyword_spelling() {
        assert_eq!(Keyword::Phishing.as_imap(), "$Phishing");
        assert_eq!(Keyword::CanUnsubscribe.as_imap(), "$CanUnsubscribe");
        assert_eq!(Keyword::Tag("invoice".into()).as_imap(), "fr-invoice");
    }

    #[test]
    fn tiers_field_sorted_unique() {
        let s = Stamp {
            id: StampId("x".into()),
            tiers: vec![Tier::SmallModels, Tier::Deterministic, Tier::SmallModels],
            models: vec![],
            verdicts: vec![],
            keywords: vec![],
            campaign: None,
        };
        assert_eq!(s.tiers_field(), "0,1");
    }
}
