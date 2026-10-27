//! Per-mailbox memory (docs/02-signals.md "Per mailbox", docs/08-learning.md).
//!
//! What one mailbox has seen and what its owner did, folded from three kinds of event:
//! - [`MemoryEvent::Delivered`]: a message reached the mailbox. A fact, independent of
//!   firstread's verdict: mail filed into Junk was delivered too.
//! - [`MemoryEvent::Label`]: the owner judged a message junk or not junk (moved it into or out of
//!   Junk, set `$Junk` or `$NotJunk`).
//! - [`MemoryEvent::Sent`]: the owner sent a message (its copy reached Sent).
//!
//! No event carries a firstread verdict, so memory cannot learn from firstread itself; dropping
//! the echoes of firstread's own moves happens where events are received (the daemon).
//!
//! Identifiers are kept as keyed hashes (HMAC-SHA256 under a deployment key): the facts only need
//! equality, so the state holds no address, Message-ID or IBAN in the clear. Every table is
//! bounded; the oldest entries the owner never labelled go first. Facts are read from the state
//! before a message is applied, so a record names exactly the state that decided it
//! ([`MailboxMemory::snapshot`]).

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};

use firstread_parse::Parsed;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Version of the stored format.
pub const FORMAT: u32 = 1;
/// Most Message-IDs remembered (received and sent), oldest dropped first.
pub const MAX_IDS: usize = 50_000;
/// Most senders and most domains remembered.
pub const MAX_SENDERS: usize = 20_000;
/// Most owner labels remembered (for undoing a label the owner reverses).
pub const MAX_LABELS: usize = 20_000;
/// Most IBANs remembered per sender domain.
pub const MAX_IBANS_PER_DOMAIN: usize = 8;
/// Deliveries before an unknown thread counts as suspicious: a new mailbox knows no threads.
pub const MIN_HISTORY_FOR_THREADS: u64 = 200;

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

/// The identifiers of one received message that memory reads and learns from, hashed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageKeys {
    /// The message: its Message-ID, or, without one, its sender, subject, date and text. The same
    /// for the copy delivered and the copy the owner later moves (headers firstread adds differ).
    pub message: String,
    /// The From address.
    pub sender: Option<String>,
    /// The registrable domain of the From address.
    pub domain: Option<String>,
    /// The Message-ID.
    pub message_id: Option<String>,
    /// Message-IDs in `In-Reply-To` and `References`.
    pub thread: Vec<String>,
    /// Mailing-list mail (`List-Id` present).
    pub list: bool,
    /// IBANs in the visible text.
    pub ibans: Vec<String>,
    /// The From domain passed DMARC in `Authentication-Results` from inside our boundary.
    pub identity_verified: bool,
}

fn domain_of(address: &str) -> Option<String> {
    address
        .rsplit_once('@')
        .map(|(_, d)| firstread_links::registrable(d))
        .filter(|d| !d.is_empty())
}

impl MessageKeys {
    /// The keys of a parsed message. `identity_verified`: DMARC passed for the From domain.
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
        Self {
            message,
            sender: (!from.is_empty()).then(|| h.id("addr", from)),
            domain: domain_of(from).map(|d| h.id("domain", &d)),
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
    /// Registrable domains of the recipients.
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

/// Counts for one sender or domain.
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
    known_ids: IdSet<MAX_IDS>,
    seen_messages: IdSet<MAX_IDS>,
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
            known_ids: IdSet::default(),
            seen_messages: IdSet::default(),
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
                if let Some(m) = &keys.message_id {
                    self.known_ids.insert(m.clone());
                }
                if keys.identity_verified
                    && let Some(d) = &keys.domain
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
                relabel(&mut self.senders, keys.sender.as_ref(), prev, *junk, *at);
                relabel(&mut self.domains, keys.domain.as_ref(), prev, *junk, *at);
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
                    self.known_ids.insert(m.clone());
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
    pub fn facts(&self, keys: &MessageKeys) -> BTreeMap<String, f64> {
        let none = Stats::default();
        let s = keys
            .sender
            .as_ref()
            .and_then(|k| self.senders.get(k))
            .unwrap_or(&none);
        let d = keys
            .domain
            .as_ref()
            .and_then(|k| self.domains.get(k))
            .unwrap_or(&none);
        let wrote_sender = keys
            .sender
            .as_ref()
            .is_some_and(|k| self.wrote.contains_key(k));
        let wrote_domain = keys
            .domain
            .as_ref()
            .is_some_and(|k| self.wrote_domains.contains_key(k));
        let known_thread = keys.thread.iter().any(|m| self.known_ids.contains(m));
        let stored = keys.domain.as_ref().and_then(|k| self.ibans.get(k));
        let iban_known = stored.is_some_and(|v| keys.ibans.iter().any(|i| v.contains(i)));
        let iban_new = stored.is_some_and(|v| keys.ibans.iter().any(|i| !v.contains(i)));
        let mut f = BTreeMap::new();
        let mut put = |k: &str, v: f64| {
            f.insert(format!("mailbox.{k}"), v);
        };
        put("sender_seen_log", ln1p(s.delivered));
        put("domain_seen_log", ln1p(d.delivered));
        put("sender_junk_log", ln1p(s.junk));
        put("sender_ok_log", ln1p(s.ok));
        put("domain_junk_log", ln1p(d.junk));
        put("domain_ok_log", ln1p(d.ok));
        put("wrote_to_sender", flag(wrote_sender));
        put("wrote_to_domain", flag(wrote_domain));
        put(
            "first_contact",
            flag(s.delivered == 0 && d.delivered == 0 && !wrote_sender && !wrote_domain),
        );
        put("known_thread", flag(known_thread));
        put(
            "unknown_thread",
            flag(
                !keys.thread.is_empty()
                    && !keys.list
                    && !known_thread
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
            ("known_ids", self.known_ids.len()),
            ("seen_messages", self.seen_messages.len()),
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

    const NEWS1: &str = "From: News <news@shop.example>\r\nMessage-ID: <n1@shop.example>\r\nSubject: Week 1\r\n\r\nAanbiedingen\r\n";
    const NEWS2: &str = "From: News <news@shop.example>\r\nMessage-ID: <n2@shop.example>\r\nSubject: Week 2\r\n\r\nAanbiedingen\r\n";

    #[test]
    fn delivery_makes_a_sender_known_once() {
        let mut m = MailboxMemory::new();
        let k1 = keys(NEWS1, false);
        assert_eq!(m.facts(&k1)["mailbox.first_contact"], 1.0);
        let e = MemoryEvent::Delivered { at: 1, keys: k1 };
        assert_eq!(m.apply(&e), Applied::Applied);
        assert_eq!(m.apply(&e), Applied::Duplicate, "a redelivery counts once");
        let f = m.facts(&keys(NEWS2, false));
        assert_eq!(f["mailbox.first_contact"], 0.0);
        assert!((f["mailbox.sender_seen_log"] - 2f64.ln()).abs() < 1e-9);
        assert_eq!(m.snapshot(), "mem/1");
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
    fn sent_mail_makes_correspondents_and_threads() {
        let mut m = MailboxMemory::new();
        m.apply(&MemoryEvent::Sent {
            at: 1,
            keys: sent(
                "From: me@mine.example\r\nTo: Jan <jan@Acme.example>\r\nMessage-ID: <s1@mine.example>\r\nSubject: Offerte\r\n\r\nHoi\r\n",
            ),
        });
        let reply = keys(
            "From: jan@acme.example\r\nIn-Reply-To: <s1@mine.example>\r\nMessage-ID: <r1@acme.example>\r\nSubject: Re: Offerte\r\n\r\nPrima\r\n",
            false,
        );
        let f = m.facts(&reply);
        assert_eq!(f["mailbox.wrote_to_sender"], 1.0);
        assert_eq!(f["mailbox.wrote_to_domain"], 1.0);
        assert_eq!(f["mailbox.known_thread"], 1.0);
        assert_eq!(f["mailbox.first_contact"], 0.0);
        let colleague = keys(
            "From: piet@acme.example\r\nSubject: hallo\r\n\r\nx\r\n",
            false,
        );
        let g = m.facts(&colleague);
        assert_eq!(g["mailbox.wrote_to_sender"], 0.0);
        assert_eq!(g["mailbox.wrote_to_domain"], 1.0);
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
            m.apply(&MemoryEvent::Delivered {
                at: 1,
                keys: keys(
                    &format!("From: x{i}@a.example\r\nMessage-ID: <h{i}@a.example>\r\n\r\nx\r\n"),
                    false,
                ),
            });
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
        m.apply(&MemoryEvent::Delivered {
            at: 1,
            keys: keys(INV_A, false),
        });
        assert_eq!(
            m.facts(&keys(INV_B, false))["mailbox.iban_new_for_domain"],
            0.0,
            "unverified mail teaches no IBAN"
        );
        let mut v = MailboxMemory::new();
        v.apply(&MemoryEvent::Delivered {
            at: 1,
            keys: keys(INV_A, true),
        });
        let f = v.facts(&keys(INV_B, false));
        assert_eq!(f["mailbox.iban_new_for_domain"], 1.0);
        assert_eq!(f["mailbox.iban_known_for_domain"], 0.0);
        let mut again = keys(INV_A, false);
        again.message = "other".into();
        assert_eq!(v.facts(&again)["mailbox.iban_known_for_domain"], 1.0);
    }

    #[test]
    fn stored_state_holds_no_identifier_in_the_clear() {
        let mut m = MailboxMemory::new();
        m.apply(&MemoryEvent::Delivered {
            at: 1,
            keys: keys(INV_A, true),
        });
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
