//! Signals: single facts about a message, the inputs to the verdicts.

use crate::decision::Decision;
use crate::scope::Scope;
use crate::tier::Tier;

/// Stable identifier of a signal, e.g. `dmarc`, `reply_to_mismatch`, `vendor_iban_changed`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SignalId(pub String);

/// Stable key of a human-readable reason; texts per language live in data files.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReasonKey(pub String);

/// The value a signal carries.
#[derive(Debug, Clone, PartialEq)]
pub enum SignalValue {
    /// A yes / no fact.
    Flag(bool),
    /// A measured quantity (domain age in days, link count, campaign size).
    Number(f64),
    /// A categorical or textual fact (authentication result, language).
    Text(String),
    /// A calibrated model answer.
    Decision(Decision),
    /// The check could not run (timeout, missing data). Never silently treated as "fine".
    Unavailable,
}

/// One fact about a message.
#[derive(Debug, Clone, PartialEq)]
pub struct Signal {
    /// Which signal.
    pub id: SignalId,
    /// Scope it needed.
    pub scope: Scope,
    /// Tier that produced it.
    pub tier: Tier,
    /// The value.
    pub value: SignalValue,
    /// A reason to show users when this signal contributes to a verdict.
    pub reason: Option<ReasonKey>,
}
