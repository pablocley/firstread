//! The normalised view of one message as delivered to one mailbox.
//!
//! Produced by `firstread-parse`; read by every signal. Holds metadata and extracted text, never
//! the raw bytes' interpretation decisions: anything uncertain is left empty, not guessed.
//!
//! Envelope and transport facts are not here: they come from the host, in
//! [`crate::context::DeliveryContext`], because the message cannot be trusted to state them.

/// An address with its display name, as written in the header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamedAddress {
    /// Display name, decoded.
    pub name: Option<String>,
    /// The address itself.
    pub address: String,
}

/// A link found in the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// The target URL as written (never fetched).
    pub href: String,
    /// The visible text, when the link came from HTML.
    pub text: Option<String>,
}

/// Facts about one attachment, from structure and content sniffing (never executed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// Declared file name.
    pub filename: Option<String>,
    /// Declared content type.
    pub declared_type: String,
    /// Type detected from content.
    pub sniffed_type: Option<String>,
    /// Size in bytes after transfer decoding.
    pub size: u64,
}

/// One message, for one mailbox.
#[derive(Debug, Clone, Default)]
pub struct MailState {
    /// From header.
    pub from: Option<NamedAddress>,
    /// Reply-To header.
    pub reply_to: Vec<NamedAddress>,
    /// Subject, decoded.
    pub subject: Option<String>,
    /// Message-ID.
    pub message_id: Option<String>,
    /// Plain text: the text part, or text extracted from HTML; quoted replies marked separately.
    pub text: String,
    /// Text of quoted earlier messages, kept apart so checks can ignore it.
    pub quoted_text: String,
    /// Links, in document order.
    pub links: Vec<Link>,
    /// Attachments (not inline images).
    pub attachments: Vec<Attachment>,
    /// Detected language (BCP 47), if confident.
    pub language: Option<String>,
    /// Raw size in bytes.
    pub size: u64,
}
