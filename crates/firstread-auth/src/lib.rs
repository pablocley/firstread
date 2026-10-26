//! Message authentication.
//!
//! Responsibilities:
//! - SPF (MAIL FROM and HELO), DKIM (v1 and v2), DMARC with alignment, ARC chain validation
//! - remove `Authentication-Results` that claim our authserv-id but were not added inside our
//!   trust boundary (RFC 8601 section 5: MUST delete, unless received directly from another
//!   trusted MTA); results added by our own MTA or Rspamd are kept and used
//! - produce our own `Authentication-Results` header
//! - parse DMARC aggregate reports addressed to the platform (outbound domain health)
//!
//! Identity is decided here, deterministically. No model output may override it.
//! Intended dependency: `mail-auth` (Stalwart Labs), 0.11.x at the time of design.
//! Status: not implemented.
