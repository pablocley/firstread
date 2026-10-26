//! The event log: every delivery, feedback event and release, append-only and replayable.
//!
//! Events carry identifiers, features, decisions and versions. Message content stays in the
//! mailbox; embeddings live per content key under the scope rules.

use crate::decision::ModelRelease;
use crate::feedback::{Action, Source};
use crate::stamp::StampId;

/// Identifies one mailbox across the platform (opaque, stable).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MailboxId(pub String);

/// Identifies one organisation (customer / tenant).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OrganisationId(pub String);

/// Normalised content key: copies of the same bulk message share it (ADR-0010).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentKey(pub [u8; 32]);

/// Which learner state made a decision, so it can be replayed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SnapshotId(pub String);

/// Locates a message inside a mailbox (IMAP identity).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MessageRef {
    /// Mailbox (account) the message belongs to.
    pub mailbox: MailboxId,
    /// Folder GUID.
    pub folder_guid: String,
    /// IMAP UIDVALIDITY of the folder.
    pub uid_validity: u32,
    /// IMAP UID.
    pub uid: u32,
}

/// One entry in the event log.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// A message was stamped and delivered.
    Delivered {
        /// The stamp written.
        stamp: StampId,
        /// Mailbox it went to.
        mailbox: MailboxId,
        /// Organisation, if any.
        organisation: Option<OrganisationId>,
        /// Content key for caching, bulk detection and clustering.
        content: ContentKey,
        /// Model release that decided.
        model: ModelRelease,
        /// Learner snapshot that decided.
        snapshot: SnapshotId,
    },
    /// Something happened to a delivered message that teaches.
    Feedback {
        /// The stamp the feedback refers to.
        stamp: StampId,
        /// Where the message is now.
        message: MessageRef,
        /// What happened.
        action: Action,
        /// Who did it.
        source: Source,
    },
    /// A model release or learner snapshot was promoted.
    Promoted {
        /// The new snapshot.
        snapshot: SnapshotId,
        /// The release it uses.
        model: ModelRelease,
    },
    /// A promotion was rolled back.
    RolledBack {
        /// The snapshot restored.
        to: SnapshotId,
    },
}
