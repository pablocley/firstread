//! Per-mailbox memory (docs/02-signals.md "Per mailbox", docs/08-learning.md).
//!
//! What one mailbox has seen and what its owner did, folded from three kinds of event:
//! - [`MemoryEvent::Delivered`]: a message reached the mailbox. A fact, independent of
//!   firstread's verdict: mail filed into Junk was delivered too.
//! - [`MemoryEvent::Label`]: the owner judged a message junk or not junk (moved it into or out of
//!   Junk, filed it in a folder, set `$Junk` or `$NotJunk`).
//! - [`MemoryEvent::Sent`]: the owner sent a message (its copy reached Sent).
//!
//! No event carries a firstread verdict, so memory cannot learn from firstread itself; dropping
//! the echoes of firstread's own moves happens where events are received (the daemon).
//!
//! Format 2 (ADR-0019), after mox's reputation analysis (`smtpserver/reputation.go`):
//! - **History is split by authentication.** A sender's and a domain's record is kept twice: for
//!   mail whose From domain was verified (an aligned DKIM pass, or DMARC pass inside our
//!   boundary) and for mail where it was not. A forger reads and writes only the unverified
//!   record, so it inherits nothing and an owner junking a forgery does not junk the real sender.
//!   Unverified mail from an address that normally authenticates is itself a fact, and gets none
//!   of the unverified record's trust (no rescues, no correspondence, no reply): whoever the
//!   owner trusted at that address authenticates, so this is not them.
//! - **Only the owner writes trust.** Deliveries are counted, but no fact rises with them: a
//!   sender cannot become known by sending more. Facts come from the owner's labels and Sent mail.
//! - **Threads are the owner's.** A reply is recognised only when it references a Message-ID the
//!   mailbox sent and comes from one of that message's recipients (after Rspamd's `replies`).
//! - **No domain facts for free-mail domains** (`data/free-mail-domains.txt`): one Gmail user
//!   says nothing about another.
//! - **Every fact has a direction** (`data/fact-directions.txt`, [`direction`]): it can only raise
//!   or only lower P(junk). A combiner whose weight points the other way is refused.
//!
//! Identifiers are kept as keyed hashes (HMAC-SHA256 under a deployment key): the facts only need
//! equality, so the state holds no address, Message-ID or IBAN in the clear. Every table is
//! bounded; the oldest entries the owner never labelled go first. Facts are read from the state
//! before a message is applied, so a record names exactly the state that decided it
//! ([`MailboxMemory::snapshot`]).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use firstread_parse::Parsed;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Version of the stored format.
pub const FORMAT: u32 = 2;
/// Most Message-IDs remembered (sent threads, seen messages), oldest dropped first.
pub const MAX_IDS: usize = 50_000;
/// Most senders and most domains remembered.
pub const MAX_SENDERS: usize = 20_000;
/// Most owner labels remembered (for undoing a label the owner reverses).
pub const MAX_LABELS: usize = 20_000;
/// Most IBANs remembered per sender domain.
pub const MAX_IBANS_PER_DOMAIN: usize = 8;
/// Most recipients remembered per sent Message-ID.
pub const MAX_RECIPIENTS_PER_SENT: usize = 20;
/// Deliveries before an unknown thread counts as suspicious: a new mailbox knows no threads.
pub const MIN_HISTORY_FOR_THREADS: u64 = 200;
/// Verified deliveries from an address before unverified mail claiming it is a spoof signal.
pub const MIN_VERIFIED_FOR_SPOOF: u32 = 2;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Keyed hashing of identifiers.
#[derive(Clone)]
pub struct Hasher {
    key: Vec<u8>,
}

impl Hasher {
    /// A hasher under `key` (the deployment's memory key).
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// The hash of `value` as an identifier of `kind` (96 bits, hex).
    pub fn id(&self, kind: &str, value: &str) -> String {
        let mut m =
            <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key).expect("HMAC takes any key");
        m.update(kind.as_bytes());
        m.update(&[0]);
        m.update(value.as_bytes());
        hex(&m.finalize().into_bytes()[..12])
    }
}

fn free_mail() -> &'static HashSet<String> {
    static SET: OnceLock<HashSet<String>> = OnceLock::new();
    SET.get_or_init(|| {
        include_str!("../data/free-mail-domains.txt")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_ascii_lowercase)
            .collect()
    })
}

/// Whether anyone can get an address at `registrable` (a free-mail provider).
pub fn is_free_mail(registrable: &str) -> bool {
    free_mail().contains(&registrable.to_ascii_lowercase())
}

/// Which way a fact may push P(junk).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Its weight must be >= 0.
    Raises,
    /// Its weight must be <= 0.
    Lowers,
}

fn directions() -> &'static HashMap<String, Direction> {
    static MAP: OnceLock<HashMap<String, Direction>> = OnceLock::new();
    MAP.get_or_init(|| {
        include_str!("../data/fact-directions.txt")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| {
                let (name, d) = l
                    .split_once(' ')
                    .expect("fact-directions: NAME raises|lowers");
                let d = match d.trim() {
                    "raises" => Direction::Raises,
                    "lowers" => Direction::Lowers,
                    other => panic!("fact-directions: unknown direction {other}"),
                };
                (name.to_string(), d)
            })
            .collect()
    })
}

/// The direction of a mailbox fact (`mailbox.*`), `None` for any other name.
pub fn direction(fact: &str) -> Option<Direction> {
    directions().get(fact).copied()
}

/// Whether `weight` respects the direction of `fact`. A name without a direction never does,
/// so a new fact cannot reach a combiner before its direction is written down.
pub fn weight_allowed(fact: &str, weight: f64) -> bool {
    match direction(fact) {
        Some(Direction::Raises) => weight >= 0.0,
        Some(Direction::Lowers) => weight <= 0.0,
        None => false,
    }
}

/// The identifiers of one received message that memory reads and learns from, hashed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageKeys {
    /// The message: its Message-ID, or, without one, its sender, subject, date and text. The same
    /// for the copy delivered and the copy the owner later moves (headers firstread adds differ).
    pub message: String,
    /// The From address, as the owner would write to it (matches Sent recipients).
    pub address: Option<String>,
    /// The From address's record for this message's authentication state.
    pub sender: Option<String>,
    /// The From address's verified record (to see whether the address normally authenticates).
    pub verified_sender: Option<String>,
    /// The From domain's record for this message's authentication state; none for free-mail.
    pub domain: Option<String>,
    /// The From domain as the owner would write to it; none for free-mail.
    pub address_domain: Option<String>,
    /// The From domain's verified record, where IBANs are kept; none for free-mail.
    pub verified_domain: Option<String>,
    /// The Message-ID.
    pub message_id: Option<String>,
    /// Message-IDs in `In-Reply-To` and `References`.
    pub thread: Vec<String>,
    /// Mailing-list mail (`List-Id` present).
    pub list: bool,
    /// IBANs in the visible text.
    pub ibans: Vec<String>,
    /// The From domain was verified (aligned DKIM pass, or DMARC pass inside our boundary).
    pub identity_verified: bool,
}

fn domain_of(address: &str) -> Option<String> {
    address
        .rsplit_once('@')
        .map(|(_, d)| firstread_links::registrable(d))
        .filter(|d| !d.is_empty())
}

impl MessageKeys {
    /// The keys of a parsed message. `identity_verified`: the From domain was verified.
    pub fn from_parsed(h: &Hasher, p: &Parsed, identity_verified: bool) -> Self {
        let s = &p.state;
        let from = s.from.as_ref().map(|f| f.address.as_str()).unwrap_or("");
        let message = match s.message_id.as_deref() {
            Some(m) if !m.is_empty() => h.id("mid", m),
            _ => h.id(
                "nomid",
                &format!(
                    "{from}\n{}\n{:?}\n{}",
                    s.subject.as_deref().unwrap_or(""),
                    p.date,
                    s.text.chars().take(2000).collect::<String>()
                ),
            ),
        };
        let state = if identity_verified { "v" } else { "u" };
        let has = !from.is_empty();
        let dom = domain_of(from).filter(|d| !is_free_mail(d));
        Self {
            message,
            address: has.then(|| h.id("addr", from)),
            sender: has.then(|| h.id(&format!("addr.{state}"), from)),
            verified_sender: has.then(|| h.id("addr.v", from)),
            domain: dom.as_ref().map(|d| h.id(&format!("domain.{state}"), d)),
            address_domain: dom.as_ref().map(|d| h.id("domain", d)),
            verified_domain: dom.as_ref().map(|d| h.id("domain.v", d)),
            message_id: s
                .message_id
                .as_deref()
                .filter(|m| !m.is_empty())
                .map(|m| h.id("mid", m)),
            thread: p.thread_ids.iter().map(|m| h.id("mid", m)).collect(),
            list: p.list_id.is_some(),
            ibans: firstread_links::ibans(&s.text)
                .iter()
                .map(|i| h.id("iban", i))
                .collect(),
            identity_verified,
        }
    }
}

/// The identifiers of a message the owner sent, hashed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentKeys {
    /// The message (as in [`MessageKeys::message`]).
    pub message: String,
    /// The Message-ID.
    pub message_id: Option<String>,
    /// Message-IDs it replies to or references.
    pub thread: Vec<String>,
    /// Recipient addresses.
    pub recipients: Vec<String>,
    /// Registrable domains of the recipients, without free-mail domains.
    pub domains: Vec<String>,
}

impl SentKeys {
    /// The keys of a parsed Sent copy.
    pub fn from_parsed(h: &Hasher, p: &Parsed) -> Self {
        let received = MessageKeys::from_parsed(h, p, false);
        let mut domains: Vec<String> = p
            .recipients
            .iter()
            .filter_map(|r| domain_of(&r.address))
            .filter(|d| !is_free_mail(d))
            .map(|d| h.id("domain", &d))
            .collect();
        domains.sort();
        domains.dedup();
        Self {
            message: received.message,
            message_id: received.message_id,
            thread: received.thread,
            recipients: p
                .recipients
                .iter()
                .map(|r| h.id("addr", &r.address))
                .collect(),
            domains,
        }
    }
}

/// One thing that happened to a mailbox.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MemoryEvent {
    /// A message was delivered (whatever firstread decided about it).
    Delivered {
        /// Unix seconds.
        at: i64,
        /// Its keys.
        keys: MessageKeys,
    },
    /// The owner judged a message.
    Label {
        /// Unix seconds.
        at: i64,
        /// Its keys.
        keys: MessageKeys,
        /// Junk (true) or not junk (false).
        junk: bool,
    },
    /// The owner sent a message.
    Sent {
        /// Unix seconds.
        at: i64,
        /// Its keys.
        keys: SentKeys,
    },
}

/// Whether an event changed the memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// It did.
    Applied,
    /// The same event was applied before (a redelivery, a repeated label); nothing changed.
    Duplicate,
}

/// Counts for one sender or domain record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    /// Messages delivered.
    pub delivered: u32,
    /// Messages the owner judged junk.
    pub junk: u32,
    /// Messages the owner judged not junk.
    pub ok: u32,
    /// Last event, Unix seconds.
    pub last: i64,
}

/// A bounded set of ids, oldest dropped first.
#[derive(Debug, Clone, Default)]
struct IdSet<const CAP: usize> {
    order: VecDeque<String>,
    set: HashSet<String>,
}

impl<const CAP: usize> IdSet<CAP> {
    #[cfg(test)]
    fn contains(&self, k: &str) -> bool {
        self.set.contains(k)
    }
    fn insert(&mut self, k: String) -> bool {
        if self.set.contains(&k) {
            return false;
        }
        self.set.insert(k.clone());
        self.order.push_back(k);
        while self.order.len() > CAP {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
    fn len(&self) -> usize {
        self.order.len()
    }
}

impl<const CAP: usize> Serialize for IdSet<CAP> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.order.serialize(s)
    }
}

impl<'de, const CAP: usize> Deserialize<'de> for IdSet<CAP> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Vec::<String>::deserialize(d)?;
        let mut out = Self::default();
        for k in v {
            out.insert(k);
        }
        Ok(out)
    }
}

/// Message-IDs the owner sent (and the ones their mail replied to), with the recipients, bounded,
/// oldest dropped first.
#[derive(Debug, Clone, Default)]
struct SentThreads {
    order: VecDeque<String>,
    map: HashMap<String, Vec<String>>,
}

impl SentThreads {
    fn add(&mut self, mid: &str, recipients: &[String]) {
        let entry = self.map.entry(mid.to_string()).or_insert_with(|| {
            self.order.push_back(mid.to_string());
            Vec::new()
        });
        for r in recipients {
            if entry.len() < MAX_RECIPIENTS_PER_SENT && !entry.contains(r) {
                entry.push(r.clone());
            }
        }
        while self.order.len() > MAX_IDS {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }
    fn recipients(&self, mid: &str) -> Option<&Vec<String>> {
        self.map.get(mid)
    }
}

impl Serialize for SentThreads {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let v: Vec<(&String, &Vec<String>)> =
            self.order.iter().map(|k| (k, &self.map[k])).collect();
        v.serialize(s)
    }
}

impl<'de> Deserialize<'de> for SentThreads {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Vec::<(String, Vec<String>)>::deserialize(d)?;
        let mut out = Self::default();
        for (k, r) in v {
            out.add(&k, &r);
        }
        Ok(out)
    }
}

/// Under which records each delivered message was counted, so the owner's label later lands on
/// the same records: a label is reported from the stored copy, without the delivery's
/// authentication result. Bounded, oldest dropped first.
#[derive(Debug, Clone, Default)]
struct DeliveredAs {
    order: VecDeque<String>,
    map: HashMap<String, Buckets>,
}

/// The sender and domain record keys a delivery was counted under.
type Buckets = (Option<String>, Option<String>);

impl DeliveredAs {
    fn set(&mut self, message: &str, sender: Option<String>, domain: Option<String>) {
        if self
            .map
            .insert(message.to_string(), (sender, domain))
            .is_none()
        {
            self.order.push_back(message.to_string());
        }
        while self.order.len() > MAX_IDS {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }
}

impl Serialize for DeliveredAs {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let v: Vec<(&String, &Buckets)> = self.order.iter().map(|k| (k, &self.map[k])).collect();
        v.serialize(s)
    }
}

impl<'de> Deserialize<'de> for DeliveredAs {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Vec::<(String, Buckets)>::deserialize(d)?;
        let mut out = Self::default();
        for (k, (s, dm)) in v {
            out.set(&k, s, dm);
        }
        Ok(out)
    }
}

/// The owner's labels, bounded, oldest dropped first.
#[derive(Debug, Clone, Default)]
struct Labels {
    order: VecDeque<String>,
    map: BTreeMap<String, bool>,
}

impl Labels {
    fn get(&self, k: &str) -> Option<bool> {
        self.map.get(k).copied()
    }
    fn set(&mut self, k: &str, junk: bool) {
        if self.map.insert(k.to_string(), junk).is_none() {
            self.order.push_back(k.to_string());
        }
        while self.order.len() > MAX_LABELS {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }
}

impl Serialize for Labels {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let v: Vec<(&String, bool)> = self.order.iter().map(|k| (k, self.map[k])).collect();
        v.serialize(s)
    }
}

impl<'de> Deserialize<'de> for Labels {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Vec::<(String, bool)>::deserialize(d)?;
        let mut out = Self::default();
        for (k, j) in v {
            out.set(&k, j);
        }
        Ok(out)
    }
}

/// Everything one mailbox remembers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxMemory {
    /// Stored format, [`FORMAT`].
    pub format: u32,
    /// Events applied: the snapshot of this state.
    pub events: u64,
    /// Messages delivered.
    pub delivered_total: u64,
    senders: BTreeMap<String, Stats>,
    domains: BTreeMap<String, Stats>,
    wrote: BTreeMap<String, u32>,
    wrote_domains: BTreeMap<String, u32>,
    sent_threads: SentThreads,
    seen_messages: IdSet<MAX_IDS>,
    delivered_as: DeliveredAs,
    labels: Labels,
    ibans: BTreeMap<String, Vec<String>>,
}

impl Default for MailboxMemory {
    fn default() -> Self {
        Self {
            format: FORMAT,
            events: 0,
            delivered_total: 0,
            senders: BTreeMap::new(),
            domains: BTreeMap::new(),
            wrote: BTreeMap::new(),
            wrote_domains: BTreeMap::new(),
            sent_threads: SentThreads::default(),
            seen_messages: IdSet::default(),
            delivered_as: DeliveredAs::default(),
            labels: Labels::default(),
            ibans: BTreeMap::new(),
        }
    }
}

fn flag(b: bool) -> f64 {
    if b { 1.0 } else { 0.0 }
}

fn ln1p(x: u32) -> f64 {
    f64::from(x).ln_1p()
}

fn relabel(
    map: &mut BTreeMap<String, Stats>,
    key: Option<&String>,
    prev: Option<bool>,
    junk: bool,
    at: i64,
) {
    let Some(k) = key else { return };
    let s = map.entry(k.clone()).or_default();
    match prev {
        Some(true) => s.junk = s.junk.saturating_sub(1),
        Some(false) => s.ok = s.ok.saturating_sub(1),
        None => {}
    }
    if junk {
        s.junk += 1;
    } else {
        s.ok += 1;
    }
    s.last = s.last.max(at);
}

fn prune(map: &mut BTreeMap<String, Stats>) {
    if map.len() <= MAX_SENDERS {
        return;
    }
    let mut unlabelled: Vec<(i64, String)> = map
        .iter()
        .filter(|(_, s)| s.junk == 0 && s.ok == 0)
        .map(|(k, s)| (s.last, k.clone()))
        .collect();
    unlabelled.sort();
    let excess = map.len() - MAX_SENDERS * 9 / 10;
    for (_, k) in unlabelled.into_iter().take(excess) {
        map.remove(&k);
    }
}

impl MailboxMemory {
    /// An empty memory.
    pub fn new() -> Self {
        Self::default()
    }

    /// The snapshot id of this state, recorded with every decision made from it.
    pub fn snapshot(&self) -> String {
        format!("mem/{}", self.events)
    }

    /// Apply one event.
    pub fn apply(&mut self, e: &MemoryEvent) -> Applied {
        match e {
            MemoryEvent::Delivered { at, keys } => {
                if !self.seen_messages.insert(format!("d:{}", keys.message)) {
                    return Applied::Duplicate;
                }
                self.delivered_as
                    .set(&keys.message, keys.sender.clone(), keys.domain.clone());
                for (map, key) in [
                    (&mut self.senders, &keys.sender),
                    (&mut self.domains, &keys.domain),
                ] {
                    if let Some(k) = key {
                        let s = map.entry(k.clone()).or_default();
                        s.delivered += 1;
                        s.last = s.last.max(*at);
                    }
                }
                if keys.identity_verified
                    && let Some(d) = &keys.verified_domain
                    && !keys.ibans.is_empty()
                {
                    let v = self.ibans.entry(d.clone()).or_default();
                    for i in &keys.ibans {
                        if !v.contains(i) {
                            v.push(i.clone());
                        }
                    }
                    while v.len() > MAX_IBANS_PER_DOMAIN {
                        v.remove(0);
                    }
                }
                self.delivered_total += 1;
            }
            MemoryEvent::Label { at, keys, junk } => {
                let prev = self.labels.get(&keys.message);
                if prev == Some(*junk) {
                    return Applied::Duplicate;
                }
                // The records the delivery was counted under; a message delivered before memory
                // existed falls back to the records of the reported copy.
                let (sender, domain) = self
                    .delivered_as
                    .map
                    .get(&keys.message)
                    .cloned()
                    .unwrap_or_else(|| (keys.sender.clone(), keys.domain.clone()));
                relabel(&mut self.senders, sender.as_ref(), prev, *junk, *at);
                relabel(&mut self.domains, domain.as_ref(), prev, *junk, *at);
                self.labels.set(&keys.message, *junk);
            }
            MemoryEvent::Sent { keys, .. } => {
                if !self.seen_messages.insert(format!("s:{}", keys.message)) {
                    return Applied::Duplicate;
                }
                for r in &keys.recipients {
                    *self.wrote.entry(r.clone()).or_default() += 1;
                }
                for d in &keys.domains {
                    *self.wrote_domains.entry(d.clone()).or_default() += 1;
                }
                for m in keys.message_id.iter().chain(&keys.thread) {
                    self.sent_threads.add(m, &keys.recipients);
                }
                for w in [&mut self.wrote, &mut self.wrote_domains] {
                    if w.len() > MAX_SENDERS {
                        w.retain(|_, n| *n > 1);
                    }
                }
            }
        }
        prune(&mut self.senders);
        prune(&mut self.domains);
        self.events += 1;
        Applied::Applied
    }

    /// The facts memory adds to a message's inputs (`mailbox.*`), from the state before it.
    /// Every fact but `first_contact` and `unknown_thread` is 0 for a sender, domain and thread
    /// the owner never labelled, wrote to or sent in.
    pub fn facts(&self, keys: &MessageKeys) -> BTreeMap<String, f64> {
        let none = Stats::default();
        let get = |map: &BTreeMap<String, Stats>, k: &Option<String>| -> Stats {
            k.as_ref().and_then(|k| map.get(k)).copied().unwrap_or(none)
        };
        let s = get(&self.senders, &keys.sender);
        let d = get(&self.domains, &keys.domain);
        let verified_history = get(&self.senders, &keys.verified_sender);
        let wrote_sender = keys
            .address
            .as_ref()
            .is_some_and(|k| self.wrote.contains_key(k));
        let wrote_domain = keys
            .address_domain
            .as_ref()
            .is_some_and(|k| self.wrote_domains.contains_key(k));
        let sent_ref = keys
            .thread
            .iter()
            .filter_map(|m| self.sent_threads.recipients(m))
            .collect::<Vec<_>>();
        let reply_to_sent = keys
            .address
            .as_ref()
            .is_some_and(|a| sent_ref.iter().any(|r| r.contains(a)));
        let stored = keys
            .verified_domain
            .as_ref()
            .and_then(|k| self.ibans.get(k));
        let iban_known = stored.is_some_and(|v| keys.ibans.iter().any(|i| v.contains(i)));
        let iban_new = stored.is_some_and(|v| keys.ibans.iter().any(|i| !v.contains(i)));
        let v = keys.identity_verified;
        // After mox's "unvalidated message with validated historic messages": the address does
        // authenticate, this message does not, so it is not whoever the owner trusted there.
        // Stricter than mox, which reads unvalidated history first and calls it inconclusive.
        let impersonation = !v && verified_history.delivered >= MIN_VERIFIED_FOR_SPOOF;
        let trust = !impersonation;
        let mut f = BTreeMap::new();
        let mut put = |k: &str, x: f64| {
            f.insert(format!("mailbox.{k}"), x);
        };
        put("sender_junk_log", ln1p(s.junk));
        put("sender_ok_log", if trust { ln1p(s.ok) } else { 0.0 });
        put("domain_junk_log", ln1p(d.junk));
        put("domain_ok_log", if trust { ln1p(d.ok) } else { 0.0 });
        put("wrote_to_sender", flag(v && wrote_sender));
        put(
            "wrote_to_sender_unverified",
            flag(!v && trust && wrote_sender),
        );
        put("wrote_to_domain", flag(v && wrote_domain));
        put("reply_to_sent", flag(trust && reply_to_sent));
        put("spoof_of_verified", flag(impersonation));
        put(
            "first_contact",
            flag(s.delivered == 0 && d.delivered == 0 && !wrote_sender && !wrote_domain),
        );
        put(
            "unknown_thread",
            flag(
                !keys.thread.is_empty()
                    && !keys.list
                    && sent_ref.is_empty()
                    && self.delivered_total >= MIN_HISTORY_FOR_THREADS,
            ),
        );
        put("iban_known_for_domain", flag(iban_known));
        put("iban_new_for_domain", flag(iban_new));
        f
    }

    /// Sizes of the tables, for metrics and tests.
    pub fn sizes(&self) -> BTreeMap<&'static str, usize> {
        [
            ("senders", self.senders.len()),
            ("domains", self.domains.len()),
            ("wrote", self.wrote.len()),
            ("wrote_domains", self.wrote_domains.len()),
            ("sent_threads", self.sent_threads.order.len()),
            ("seen_messages", self.seen_messages.len()),
            ("delivered_as", self.delivered_as.order.len()),
            ("labels", self.labels.order.len()),
            ("iban_domains", self.ibans.len()),
        ]
        .into_iter()
        .collect()
    }
}

/// Where mailbox memories live. The store decision is open (docs/decisions/0006-central-store.md);
/// everything else sees only this trait.
pub trait MemoryStore: Send + Sync {
    /// The memory of `mailbox`, empty if it has none.
    fn load(&self, mailbox: &str) -> io::Result<MailboxMemory>;
    /// Store the memory of `mailbox`.
    fn save(&self, mailbox: &str, m: &MailboxMemory) -> io::Result<()>;
    /// Append an applied event to the mailbox's event log.
    fn append(&self, mailbox: &str, e: &MemoryEvent) -> io::Result<()>;
    /// The memory rebuilt from the mailbox's event log alone (replay, audit, recovery).
    fn replay(&self, mailbox: &str) -> io::Result<MailboxMemory>;
    /// Erase everything remembered about `mailbox`, state and event log (docs/06-security-privacy.md:
    /// deletion follows the mailbox).
    fn forget(&self, mailbox: &str) -> io::Result<()>;
}

/// Per mailbox, in one directory and named by the keyed hash of the mailbox: the state as one
/// JSON file (written to a temporary file and renamed, so a crash leaves the old state or the
/// new one) and the event log as JSON lines. Events hold hashes, never content.
pub struct FileStore {
    dir: PathBuf,
    hasher: Hasher,
}

impl FileStore {
    /// A store in `dir` (created if missing).
    pub fn new(dir: &Path, hasher: Hasher) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            hasher,
        })
    }

    fn path(&self, mailbox: &str) -> PathBuf {
        self.dir.join(format!(
            "{}.json",
            self.hasher.id("mailbox", &mailbox.to_ascii_lowercase())
        ))
    }

    fn log_path(&self, mailbox: &str) -> PathBuf {
        self.path(mailbox).with_extension("events.jsonl")
    }
}

impl MemoryStore for FileStore {
    /// The saved state plus the events logged after it was saved, so a state saved only now and
    /// then loses nothing.
    fn load(&self, mailbox: &str) -> io::Result<MailboxMemory> {
        let mut m = match std::fs::read(self.path(mailbox)) {
            Ok(b) => {
                let m: MailboxMemory = serde_json::from_slice(&b).map_err(io::Error::other)?;
                if m.format != FORMAT {
                    return Err(io::Error::other(format!(
                        "memory format {} (expected {FORMAT})",
                        m.format
                    )));
                }
                m
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => MailboxMemory::new(),
            Err(e) => return Err(e),
        };
        match std::fs::read_to_string(self.log_path(mailbox)) {
            Ok(text) => {
                let saved = m.events;
                for line in text
                    .lines()
                    .filter(|l| !l.is_empty())
                    .skip(usize::try_from(saved).unwrap_or(usize::MAX))
                {
                    let e: MemoryEvent = serde_json::from_str(line).map_err(io::Error::other)?;
                    m.apply(&e);
                }
                Ok(m)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(m),
            Err(e) => Err(e),
        }
    }

    fn save(&self, mailbox: &str, m: &MailboxMemory) -> io::Result<()> {
        let path = self.path(mailbox);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(m).map_err(io::Error::other)?)?;
        std::fs::rename(tmp, path)
    }

    fn append(&self, mailbox: &str, e: &MemoryEvent) -> io::Result<()> {
        use std::io::Write;
        let mut line = serde_json::to_vec(e).map_err(io::Error::other)?;
        line.push(b'\n');
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_path(mailbox))?
            .write_all(&line)
    }

    fn replay(&self, mailbox: &str) -> io::Result<MailboxMemory> {
        let mut m = MailboxMemory::new();
        let text = match std::fs::read_to_string(self.log_path(mailbox)) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(m),
            Err(e) => return Err(e),
        };
        for line in text.lines().filter(|l| !l.is_empty()) {
            let e: MemoryEvent = serde_json::from_str(line).map_err(io::Error::other)?;
            m.apply(&e);
        }
        Ok(m)
    }

    fn forget(&self, mailbox: &str) -> io::Result<()> {
        for p in [self.path(mailbox), self.log_path(mailbox)] {
            match std::fs::remove_file(p) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h() -> Hasher {
        Hasher::new(b"test-memory-key")
    }

    fn keys(raw: &str, verified: bool) -> MessageKeys {
        let p = firstread_parse::parse(raw.as_bytes()).unwrap();
        MessageKeys::from_parsed(&h(), &p, verified)
    }

    fn sent(raw: &str) -> SentKeys {
        SentKeys::from_parsed(&h(), &firstread_parse::parse(raw.as_bytes()).unwrap())
    }

    fn deliver(m: &mut MailboxMemory, k: MessageKeys) {
        m.apply(&MemoryEvent::Delivered { at: 1, keys: k });
    }

    const NEWS1: &str = "From: News <news@shop.example>\r\nMessage-ID: <n1@shop.example>\r\nSubject: Week 1\r\n\r\nAanbiedingen\r\n";
    const NEWS2: &str = "From: News <news@shop.example>\r\nMessage-ID: <n2@shop.example>\r\nSubject: Week 2\r\n\r\nAanbiedingen\r\n";
    const NEWS3: &str = "From: News <news@shop.example>\r\nMessage-ID: <n3@shop.example>\r\nSubject: Week 3\r\n\r\nAanbiedingen\r\n";

    #[test]
    fn deliveries_are_counted_but_never_raise_a_fact() {
        let mut m = MailboxMemory::new();
        let k1 = keys(NEWS1, false);
        assert_eq!(m.facts(&k1)["mailbox.first_contact"], 1.0);
        let e = MemoryEvent::Delivered { at: 1, keys: k1 };
        assert_eq!(m.apply(&e), Applied::Applied);
        assert_eq!(m.apply(&e), Applied::Duplicate, "a redelivery counts once");
        for i in 0..50 {
            deliver(
                &mut m,
                keys(&NEWS2.replace("n2@", &format!("x{i}@")), false),
            );
        }
        let f = m.facts(&keys(NEWS3, false));
        assert_eq!(f["mailbox.first_contact"], 0.0);
        for (k, v) in &f {
            if k != "mailbox.first_contact" {
                assert_eq!(*v, 0.0, "{k}: sending more must not make a sender known");
            }
        }
        assert!(!f.contains_key("mailbox.sender_seen_log"));
        assert_eq!(m.snapshot(), "mem/51");
    }

    #[test]
    fn labels_count_once_and_a_reversal_moves_the_count() {
        let mut m = MailboxMemory::new();
        let k = keys(NEWS1, false);
        let junk = MemoryEvent::Label {
            at: 2,
            keys: k.clone(),
            junk: true,
        };
        assert_eq!(m.apply(&junk), Applied::Applied);
        assert_eq!(m.apply(&junk), Applied::Duplicate);
        let f = m.facts(&keys(NEWS2, false));
        assert!(f["mailbox.sender_junk_log"] > 0.0 && f["mailbox.sender_ok_log"] == 0.0);
        m.apply(&MemoryEvent::Label {
            at: 3,
            keys: k,
            junk: false,
        });
        let g = m.facts(&keys(NEWS2, false));
        assert_eq!(g["mailbox.sender_junk_log"], 0.0);
        assert!(g["mailbox.sender_ok_log"] > 0.0);
        assert!(g["mailbox.domain_ok_log"] > 0.0);
    }

    #[test]
    fn verified_and_unverified_history_are_kept_apart() {
        let mut m = MailboxMemory::new();
        // The owner rescues a verified newsletter.
        m.apply(&MemoryEvent::Label {
            at: 1,
            keys: keys(NEWS1, true),
            junk: false,
        });
        assert!(m.facts(&keys(NEWS2, true))["mailbox.sender_ok_log"] > 0.0);
        let forged = m.facts(&keys(NEWS2, false));
        assert_eq!(
            forged["mailbox.sender_ok_log"], 0.0,
            "a forger inherits nothing"
        );
        assert_eq!(forged["mailbox.domain_ok_log"], 0.0);
        // The owner junks a forgery: the real sender's record is untouched.
        m.apply(&MemoryEvent::Label {
            at: 2,
            keys: keys(NEWS3, false),
            junk: true,
        });
        let real = m.facts(&keys(NEWS2, true));
        assert_eq!(real["mailbox.sender_junk_log"], 0.0);
        assert!(real["mailbox.sender_ok_log"] > 0.0);
        assert!(m.facts(&keys(NEWS2, false))["mailbox.sender_junk_log"] > 0.0);
    }

    #[test]
    fn a_label_lands_on_the_record_the_delivery_was_counted_under() {
        let mut m = MailboxMemory::new();
        // Delivered verified; the owner's move is reported from the stored copy, unverified.
        deliver(&mut m, keys(NEWS1, true));
        m.apply(&MemoryEvent::Label {
            at: 2,
            keys: keys(NEWS1, false),
            junk: false,
        });
        assert!(m.facts(&keys(NEWS2, true))["mailbox.sender_ok_log"] > 0.0);
        assert_eq!(m.facts(&keys(NEWS2, false))["mailbox.sender_ok_log"], 0.0);
    }

    #[test]
    fn unverified_mail_from_an_address_that_authenticates_is_a_spoof_signal() {
        let mut m = MailboxMemory::new();
        let n1 = keys(NEWS1, true);
        deliver(&mut m, n1);
        assert_eq!(
            m.facts(&keys(NEWS3, false))["mailbox.spoof_of_verified"],
            0.0,
            "once"
        );
        deliver(&mut m, keys(NEWS2, true));
        assert_eq!(
            m.facts(&keys(NEWS3, false))["mailbox.spoof_of_verified"],
            1.0
        );
        assert_eq!(
            m.facts(&keys(NEWS3, true))["mailbox.spoof_of_verified"],
            0.0
        );
    }

    #[test]
    fn unverified_mail_from_an_address_that_authenticates_gets_none_of_its_trust() {
        let mut m = MailboxMemory::new();
        // The owner writes to the vendor and rescues one of its unverified mails; the vendor's
        // mail then starts authenticating.
        m.apply(&MemoryEvent::Sent {
            at: 1,
            keys: sent("From: me@mine.example\r\nTo: news@shop.example\r\nMessage-ID: <s9@mine.example>\r\n\r\nHoi\r\n"),
        });
        let old = keys(NEWS1, false);
        deliver(&mut m, old.clone());
        m.apply(&MemoryEvent::Label {
            at: 2,
            keys: old,
            junk: false,
        });
        let forged = "From: News <news@shop.example>\r\nIn-Reply-To: <s9@mine.example>\r\nMessage-ID: <f1@evil.example>\r\nSubject: Nieuw rekeningnummer\r\n\r\nBetaal op NL91ABNA0417164300\r\n";
        let before = m.facts(&keys(forged, false));
        assert!(before["mailbox.sender_ok_log"] > 0.0);
        assert_eq!(before["mailbox.wrote_to_sender_unverified"], 1.0);
        assert_eq!(before["mailbox.reply_to_sent"], 1.0);
        deliver(&mut m, keys(NEWS2, true));
        deliver(&mut m, keys(NEWS3, true));
        let f = m.facts(&keys(forged, false));
        assert_eq!(f["mailbox.spoof_of_verified"], 1.0);
        for k in [
            "sender_ok_log",
            "domain_ok_log",
            "wrote_to_sender_unverified",
            "reply_to_sent",
        ] {
            assert_eq!(f[&format!("mailbox.{k}")], 0.0, "{k}");
        }
        // The real, authenticated sender keeps its correspondent trust.
        let real = m.facts(&keys(
            "From: News <news@shop.example>\r\nIn-Reply-To: <s9@mine.example>\r\nMessage-ID: <n4@shop.example>\r\n\r\nx\r\n",
            true,
        ));
        assert_eq!(real["mailbox.wrote_to_sender"], 1.0);
        assert_eq!(real["mailbox.reply_to_sent"], 1.0);
        assert_eq!(real["mailbox.spoof_of_verified"], 0.0);
    }

    #[test]
    fn every_fact_has_a_direction_and_weights_must_follow_it() {
        let m = MailboxMemory::new();
        for name in m.facts(&keys(NEWS1, false)).keys() {
            assert!(direction(name).is_some(), "{name} has no direction");
        }
        assert!(weight_allowed("mailbox.iban_new_for_domain", 2.0));
        assert!(!weight_allowed("mailbox.iban_new_for_domain", -0.1));
        assert!(weight_allowed("mailbox.sender_ok_log", -5.0));
        assert!(!weight_allowed("mailbox.sender_ok_log", 0.5));
        assert!(weight_allowed("mailbox.domain_junk_log", 0.0));
        assert!(!weight_allowed("mailbox.no_such_fact", 0.0));
        assert_eq!(direction("links.count"), None);
    }

    const SENT: &str = "From: me@mine.example\r\nTo: Jan <jan@Acme.example>\r\nCc: list@lists.example\r\nMessage-ID: <s1@mine.example>\r\nSubject: Offerte\r\n\r\nHoi\r\n";

    #[test]
    fn sent_mail_makes_correspondents_and_only_their_replies_known() {
        let mut m = MailboxMemory::new();
        m.apply(&MemoryEvent::Sent {
            at: 1,
            keys: sent(SENT),
        });
        let reply = "From: jan@acme.example\r\nIn-Reply-To: <s1@mine.example>\r\nMessage-ID: <r1@acme.example>\r\nSubject: Re: Offerte\r\n\r\nPrima\r\n";
        let f = m.facts(&keys(reply, true));
        assert_eq!(f["mailbox.wrote_to_sender"], 1.0);
        assert_eq!(f["mailbox.wrote_to_sender_unverified"], 0.0);
        assert_eq!(f["mailbox.wrote_to_domain"], 1.0);
        assert_eq!(f["mailbox.reply_to_sent"], 1.0);
        assert_eq!(f["mailbox.first_contact"], 0.0);
        let g = m.facts(&keys(reply, false));
        assert_eq!(
            g["mailbox.wrote_to_sender"], 0.0,
            "unverified: no correspondent trust"
        );
        assert_eq!(g["mailbox.wrote_to_sender_unverified"], 1.0);
        assert_eq!(g["mailbox.wrote_to_domain"], 0.0);
        // Someone who saw the Message-ID (a list reader) replying is not a known thread.
        let stranger = "From: x@evil.example\r\nIn-Reply-To: <s1@mine.example>\r\nSubject: Re: Offerte\r\n\r\nKlik\r\n";
        assert_eq!(m.facts(&keys(stranger, true))["mailbox.reply_to_sent"], 0.0);
        // A reference to mail the mailbox only received is not a known thread either.
        deliver(
            &mut m,
            keys(
                "From: a@b.example\r\nMessage-ID: <got@b.example>\r\n\r\nx\r\n",
                true,
            ),
        );
        let fake = "From: a@b.example\r\nIn-Reply-To: <got@b.example>\r\nSubject: Re\r\n\r\nx\r\n";
        assert_eq!(m.facts(&keys(fake, true))["mailbox.reply_to_sent"], 0.0);
    }

    #[test]
    fn free_mail_domains_get_no_domain_facts() {
        assert!(is_free_mail("gmail.com") && is_free_mail("Ziggo.nl"));
        assert!(!is_free_mail("acme.example"));
        let mut m = MailboxMemory::new();
        let a = "From: a@gmail.com\r\nMessage-ID: <g1@x>\r\n\r\nx\r\n";
        let b = "From: b@gmail.com\r\nMessage-ID: <g2@x>\r\n\r\nx\r\n";
        let ka = keys(a, true);
        assert!(ka.domain.is_none() && ka.address_domain.is_none());
        m.apply(&MemoryEvent::Label {
            at: 1,
            keys: ka,
            junk: true,
        });
        let f = m.facts(&keys(b, true));
        assert_eq!(
            f["mailbox.domain_junk_log"], 0.0,
            "one Gmail user says nothing of another"
        );
        assert!(m.facts(&keys(a, true))["mailbox.sender_junk_log"] > 0.0);
        m.apply(&MemoryEvent::Sent {
            at: 1,
            keys: sent("From: me@mine.example\r\nTo: a@gmail.com\r\nMessage-ID: <s9@mine.example>\r\n\r\nx\r\n"),
        });
        assert_eq!(m.facts(&keys(b, true))["mailbox.wrote_to_domain"], 0.0);
        assert_eq!(m.facts(&keys(a, true))["mailbox.wrote_to_sender"], 1.0);
    }

    #[test]
    fn unknown_thread_needs_history_and_skips_lists() {
        let fake = keys(
            "From: ceo@evil.example\r\nIn-Reply-To: <never@mine.example>\r\nSubject: Re: betaling\r\n\r\nGraag vandaag\r\n",
            false,
        );
        let mut m = MailboxMemory::new();
        assert_eq!(m.facts(&fake)["mailbox.unknown_thread"], 0.0, "new mailbox");
        for i in 0..MIN_HISTORY_FOR_THREADS {
            deliver(
                &mut m,
                keys(
                    &format!("From: x{i}@a.example\r\nMessage-ID: <h{i}@a.example>\r\n\r\nx\r\n"),
                    false,
                ),
            );
        }
        assert_eq!(m.facts(&fake)["mailbox.unknown_thread"], 1.0);
        let list = keys(
            "From: dev@lists.example\r\nList-Id: <dev.lists.example>\r\nIn-Reply-To: <never@x>\r\nSubject: Re: patch\r\n\r\nok\r\n",
            false,
        );
        assert_eq!(m.facts(&list)["mailbox.unknown_thread"], 0.0);
    }

    const INV_A: &str = "From: facturen@leverancier.example\r\nMessage-ID: <i1@leverancier.example>\r\nSubject: Factuur 1\r\n\r\nGraag betalen op NL91ABNA0417164300.\r\n";
    const INV_B: &str = "From: facturen@leverancier.example\r\nMessage-ID: <i2@leverancier.example>\r\nSubject: Factuur 2\r\n\r\nNieuw rekeningnummer: NL20INGB0001234567.\r\n";

    #[test]
    fn a_changed_iban_for_a_known_domain_is_noticed_only_after_verified_mail() {
        let mut m = MailboxMemory::new();
        deliver(&mut m, keys(INV_A, false));
        assert_eq!(
            m.facts(&keys(INV_B, false))["mailbox.iban_new_for_domain"],
            0.0,
            "unverified mail teaches no IBAN"
        );
        let mut v = MailboxMemory::new();
        deliver(&mut v, keys(INV_A, true));
        let f = v.facts(&keys(INV_B, false));
        assert_eq!(
            f["mailbox.iban_new_for_domain"], 1.0,
            "also for a forged invoice"
        );
        assert_eq!(f["mailbox.iban_known_for_domain"], 0.0);
        let mut again = keys(INV_A, false);
        again.message = "other".into();
        assert_eq!(v.facts(&again)["mailbox.iban_known_for_domain"], 1.0);
    }

    #[test]
    fn stored_state_holds_no_identifier_in_the_clear() {
        let mut m = MailboxMemory::new();
        deliver(&mut m, keys(INV_A, true));
        m.apply(&MemoryEvent::Sent {
            at: 1,
            keys: sent("From: me@mine.example\r\nTo: jan@acme.example\r\nMessage-ID: <s1@mine.example>\r\n\r\nx\r\n"),
        });
        let json = serde_json::to_string(&m).unwrap();
        for clear in [
            "leverancier",
            "facturen",
            "NL91ABNA",
            "acme",
            "jan@",
            "i1@",
            "s1@",
        ] {
            assert!(!json.contains(clear), "{clear} stored in the clear");
        }
        let back: MailboxMemory = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.facts(&keys(INV_B, false)),
            m.facts(&keys(INV_B, false))
        );
    }

    #[test]
    fn id_sets_are_bounded_and_drop_the_oldest() {
        let mut s: IdSet<3> = IdSet::default();
        for k in ["a", "b", "c", "d"] {
            s.insert(k.into());
        }
        assert_eq!(s.len(), 3);
        assert!(!s.contains("a") && s.contains("d"));
        let back: IdSet<3> = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert!(back.contains("b") && !back.contains("a"));
    }

    #[test]
    fn file_store_keeps_mailboxes_apart_and_forgets() {
        let dir = std::env::temp_dir().join(format!("fr-graph-test-{}", std::process::id()));
        let st = FileStore::new(&dir, h()).unwrap();
        let mut a = st.load("alice@x.example").unwrap();
        a.apply(&MemoryEvent::Label {
            at: 1,
            keys: keys(NEWS1, false),
            junk: true,
        });
        st.save("alice@x.example", &a).unwrap();
        let b = st.load("bob@x.example").unwrap();
        assert_eq!(b.events, 0, "bob's memory is untouched by alice's label");
        assert_eq!(b.facts(&keys(NEWS2, false))["mailbox.sender_junk_log"], 0.0);
        let a2 = st.load("Alice@X.example").unwrap();
        assert_eq!(a2.events, 1);
        for entry in std::fs::read_dir(&dir).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            assert!(!name.contains("alice"), "file named in the clear: {name}");
        }
        let e = MemoryEvent::Delivered {
            at: 5,
            keys: keys(NEWS2, false),
        };
        a.apply(&e);
        st.append(
            "alice@x.example",
            &MemoryEvent::Label {
                at: 1,
                keys: keys(NEWS1, false),
                junk: true,
            },
        )
        .unwrap();
        st.append("alice@x.example", &e).unwrap();
        let loaded = st.load("alice@x.example").unwrap();
        assert_eq!(
            loaded.events, a.events,
            "state saved at 1 event plus the logged tail"
        );
        let replayed = st.replay("alice@x.example").unwrap();
        assert_eq!(replayed.events, a.events);
        assert_eq!(
            replayed.facts(&keys(NEWS2, false)),
            a.facts(&keys(NEWS2, false)),
            "the event log rebuilds the same memory"
        );
        st.forget("alice@x.example").unwrap();
        assert_eq!(st.load("alice@x.example").unwrap().events, 0);
        assert_eq!(st.replay("alice@x.example").unwrap().events, 0);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
