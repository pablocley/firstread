//! The delivery context: what the host knows about a message that the message itself cannot be
//! trusted to say (docs/12-interfaces.md section 3.2, ADR-0012).

use std::net::IpAddr;

/// How the message reached this mailbox. Derived and recorded, never read from the message alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Not yet classified.
    Unclassified,
    /// From the internet through our border MTA.
    InboundInternet,
    /// From another mailbox on the same platform.
    Internal,
    /// Forwarded to this mailbox from elsewhere (alias, forwarder).
    Forwarded,
    /// A delivery status notification or other bounce.
    Bounce,
}

/// Why a context could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextError {
    /// A required variable is missing or empty.
    Missing(&'static str),
}

/// Everything about one delivery that comes from the host, not from the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryContext {
    /// Mailbox user (`USER`).
    pub user: String,
    /// Envelope sender (`SENDER`); empty for bounces.
    pub sender: String,
    /// Envelope recipient of this delivery (`RECIPIENT`).
    pub recipient: String,
    /// Original recipient before aliasing or forwarding (`ORIG_RECIPIENT`), when different.
    pub orig_recipient: Option<String>,
    /// How the message arrived.
    pub direction: Direction,
    /// Client IP from our own border MTA's `Received` line.
    pub client_ip: Option<IpAddr>,
    /// HELO / EHLO from the same line.
    pub helo: Option<String>,
    /// TLS version on the last external hop, from the same line.
    pub tls: Option<String>,
}

impl DeliveryContext {
    /// Build from the environment Dovecot gives extprograms (`USER`, `SENDER`, `RECIPIENT`,
    /// `ORIG_RECIPIENT`). Transport facts are filled in later from the trusted `Received` line.
    pub fn from_dovecot_env<F>(get: F) -> Result<Self, ContextError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let nonempty = |k: &'static str| get(k).filter(|v| !v.is_empty());
        let user = nonempty("USER").ok_or(ContextError::Missing("USER"))?;
        let recipient = nonempty("RECIPIENT").ok_or(ContextError::Missing("RECIPIENT"))?;
        let sender = get("SENDER").unwrap_or_default();
        let orig_recipient =
            nonempty("ORIG_RECIPIENT").filter(|o| !o.eq_ignore_ascii_case(&recipient));
        Ok(Self {
            user,
            sender,
            recipient,
            orig_recipient,
            direction: Direction::Unclassified,
            client_ip: None,
            helo: None,
            tls: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn reads_dovecot_variables() {
        let c = DeliveryContext::from_dovecot_env(env(&[
            ("USER", "jan@example.nl"),
            ("SENDER", "billing@supplier.example"),
            ("RECIPIENT", "jan@example.nl"),
            ("ORIG_RECIPIENT", "info@example.nl"),
        ]))
        .unwrap();
        assert_eq!(c.user, "jan@example.nl");
        assert_eq!(c.orig_recipient.as_deref(), Some("info@example.nl"));
        assert_eq!(c.direction, Direction::Unclassified);
    }

    #[test]
    fn bounce_has_empty_sender_and_same_orig_is_dropped() {
        let c = DeliveryContext::from_dovecot_env(env(&[
            ("USER", "jan"),
            ("SENDER", ""),
            ("RECIPIENT", "jan@example.nl"),
            ("ORIG_RECIPIENT", "JAN@example.nl"),
        ]))
        .unwrap();
        assert_eq!(c.sender, "");
        assert_eq!(c.orig_recipient, None);
    }

    #[test]
    fn missing_recipient_is_an_error() {
        assert_eq!(
            DeliveryContext::from_dovecot_env(env(&[("USER", "jan")])),
            Err(ContextError::Missing("RECIPIENT"))
        );
    }
}
