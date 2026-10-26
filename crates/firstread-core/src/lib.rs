//! The shared contract every other firstread crate speaks.
//!
//! - [`context`]: the delivery context from the host (who it is for, how it arrived).
//! - [`mail`]: the normalised view of one message as delivered to one mailbox.
//! - [`decision`]: typed questions and calibrated answers (`noul`, `choice`, `score`), the same
//!   contract for every model tier.
//! - [`directive`]: the only synchronous output: validated header edits, keywords, folder.
//! - [`provider`]: the plug-in contract for System 1 models: deciders, embedders, calibration,
//!   data rules.
//! - [`scope`]: mailbox, organisation, platform, commons, and what may cross between them.
//! - [`signal`]: one fact about a message, with its scope and the tier that produced it.
//! - [`verdict`]: the few user-facing conclusions, each a probability with reasons.
//! - [`feedback`]: what people do with their mail, as labels with a strength.
//! - [`event`]: the append-only event log every learner consumes and every replay re-runs.
//! - [`stamp`]: what gets written into and onto the message, and keyed for the API.
//! - [`tier`]: cost tiers and deadlines.
//! - [`wire`]: the frames between the delivery filter and the daemon.

pub mod context;
pub mod decision;
pub mod directive;
pub mod event;
pub mod feedback;
pub mod mail;
pub mod provider;
pub mod scope;
pub mod signal;
pub mod stamp;
pub mod tier;
pub mod verdict;
pub mod wire;
