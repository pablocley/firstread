//! The shared contract every other firstread crate speaks.
//!
//! - [`mail`]: the normalised view of one message as delivered to one mailbox.
//! - [`decision`]: typed questions and calibrated answers (`noul`, `choice`, `score`), the same
//!   contract for every model tier.
//! - [`scope`]: mailbox, organisation, platform, commons, and what may cross between them.
//! - [`signal`]: one fact about a message, with its scope and the tier that produced it.
//! - [`verdict`]: the few user-facing conclusions, each a probability with reasons.
//! - [`feedback`]: what people do with their mail, as labels with a strength.
//! - [`event`]: the append-only event log every learner consumes and every replay re-runs.
//! - [`stamp`]: what gets written into and onto the message, and keyed for the API.
//! - [`tier`]: cost tiers and deadlines.

pub mod decision;
pub mod event;
pub mod feedback;
pub mod mail;
pub mod scope;
pub mod signal;
pub mod stamp;
pub mod tier;
pub mod verdict;
