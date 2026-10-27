//! Network facts about senders and recipients.
//!
//! Built: the DNS contract the rest of firstread uses ([`Dns`]), answers recorded per decision
//! ([`Logged`], [`Lookup`]) so every decision can be replayed, a replaying resolver
//! ([`RecordedDns`]) that never touches the network (a name it has no answer for is a
//! `TempError`, never "no record") and stands only for the period it was recorded for, and a live
//! stub resolver ([`LiveDns`]): UDP with EDNS0 to the
//! configured recursive resolvers, TCP when the answer is truncated, a deadline per query, a
//! TTL-bounded cache.
//!
//! Still to build: DNSBL queries, MTA-STS / DANE / TLS-RPT discovery, RDAP domain age.
//!
//! Every lookup can fail; a failure yields `Unavailable` upstream, never "fine".

use std::collections::HashMap;
use std::io::{self, BufRead, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// The record types firstread looks up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    /// TXT (SPF, DKIM keys, DMARC policies).
    Txt,
    /// A.
    A,
    /// AAAA.
    Aaaa,
    /// MX.
    Mx,
    /// PTR.
    Ptr,
}

/// What a lookup returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Answer {
    /// The records, as text (TXT: the character-strings of one record joined; MX: "pref host").
    Records {
        /// One entry per resource record.
        records: Vec<String>,
    },
    /// NXDOMAIN, or the name exists without records of this type.
    NoRecords,
    /// No usable answer: timeout, server failure, or (when replaying) not recorded.
    TempError {
        /// Why.
        reason: String,
    },
}

/// One lookup and its answer, as kept in a decision's record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lookup {
    /// Record type.
    #[serde(rename = "type")]
    pub rtype: RecordType,
    /// Lowercase name without the trailing dot.
    pub name: String,
    /// The answer.
    #[serde(flatten)]
    pub answer: Answer,
}

/// Parse a recording window, `FROM,TO` in Unix seconds (see [`RecordedDns::set_window`]).
pub fn parse_window(v: &str) -> Result<(u64, u64), String> {
    let (from, to) = v
        .split_once(',')
        .ok_or_else(|| format!("window {v}: expected FROM,TO"))?;
    let from: u64 = from
        .trim()
        .parse()
        .map_err(|e| format!("window {v}: {e}"))?;
    let to: u64 = to.trim().parse().map_err(|e| format!("window {v}: {e}"))?;
    if from > to {
        return Err(format!("window {v}: FROM after TO"));
    }
    Ok((from, to))
}

/// The lowercase form of a DNS name without a trailing dot.
pub fn normalise(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// A resolver. Implementations must be safe to share between deliveries.
pub trait Dns: Send + Sync {
    /// Look `name` up.
    fn lookup(&self, rtype: RecordType, name: &str) -> Answer;

    /// Whether this resolver's answers stand for the answers at Unix time `at`. A live resolver
    /// answers for now; a recording only for the period it was recorded for. A message judged at
    /// a time its resolver does not stand for must get no answers at all (`TempError`), or a
    /// policy published today would be applied to mail from years ago.
    fn stands_for(&self, _at: u64) -> bool {
        true
    }
}

/// Answers from a recording; anything not recorded is a `TempError`, so a replay never
/// invents "no record" and never reaches the network.
#[derive(Debug, Default)]
pub struct RecordedDns {
    answers: HashMap<(RecordType, String), Answer>,
    window: Option<(u64, u64)>,
}

impl RecordedDns {
    /// An empty recording.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one answer (a later answer for the same name and type replaces an earlier one).
    pub fn insert(&mut self, l: Lookup) {
        self.answers.insert((l.rtype, normalise(&l.name)), l.answer);
    }

    /// Read a recording: one [`Lookup`] as JSON per line.
    pub fn load(path: &Path) -> io::Result<Self> {
        let mut r = Self::new();
        let f = std::fs::File::open(path)?;
        for (n, line) in io::BufReader::new(f).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let l: Lookup = serde_json::from_str(&line).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}:{}: {e}", path.display(), n + 1),
                )
            })?;
            r.insert(l);
        }
        Ok(r)
    }

    /// Add the answers of another recording for names this one does not hold. On a clash the
    /// answer already here is kept, so adding a recording (the sealed split's) never changes the
    /// answers, and so the decisions, of messages the first one was made for.
    pub fn extend(&mut self, other: RecordedDns) {
        for (k, v) in other.answers {
            self.answers.entry(k).or_insert(v);
        }
    }

    /// The period the recording stands for, Unix seconds `from..=to`. Without one it stands for
    /// any time.
    pub fn set_window(&mut self, from: u64, to: u64) {
        self.window = Some((from, to));
    }

    /// Number of recorded answers.
    pub fn len(&self) -> usize {
        self.answers.len()
    }

    /// Whether nothing is recorded.
    pub fn is_empty(&self) -> bool {
        self.answers.is_empty()
    }
}

impl Dns for RecordedDns {
    fn lookup(&self, rtype: RecordType, name: &str) -> Answer {
        self.answers
            .get(&(rtype, normalise(name)))
            .cloned()
            .unwrap_or_else(|| Answer::TempError {
                reason: "not recorded".into(),
            })
    }

    fn stands_for(&self, at: u64) -> bool {
        self.window
            .is_none_or(|(from, to)| (from..=to).contains(&at))
    }
}

/// A resolver that keeps every lookup it passed through, for the decision's record. The same
/// name and type asked twice is looked up once.
pub struct Logged<'a> {
    inner: &'a dyn Dns,
    log: Mutex<Vec<Lookup>>,
}

impl<'a> Logged<'a> {
    /// Wrap `inner`.
    pub fn new(inner: &'a dyn Dns) -> Self {
        Self {
            inner,
            log: Mutex::new(Vec::new()),
        }
    }

    /// The lookups made, in order.
    pub fn into_lookups(self) -> Vec<Lookup> {
        self.log.into_inner().unwrap_or_else(|p| p.into_inner())
    }
}

impl Dns for Logged<'_> {
    fn lookup(&self, rtype: RecordType, name: &str) -> Answer {
        let name = normalise(name);
        if let Ok(log) = self.log.lock()
            && let Some(l) = log.iter().find(|l| l.rtype == rtype && l.name == name)
        {
            return l.answer.clone();
        }
        let answer = self.inner.lookup(rtype, &name);
        if let Ok(mut log) = self.log.lock() {
            log.push(Lookup {
                rtype,
                name,
                answer: answer.clone(),
            });
        }
        answer
    }

    fn stands_for(&self, at: u64) -> bool {
        self.inner.stands_for(at)
    }
}

/// A resolver with a time budget for one message: once spent, every further lookup is a
/// temporary error at once, so DNS can never push a delivery past its deadline.
pub struct Budgeted<'a> {
    inner: &'a dyn Dns,
    until: Instant,
}

impl<'a> Budgeted<'a> {
    /// `inner`, for at most `budget` from now.
    pub fn new(inner: &'a dyn Dns, budget: Duration) -> Self {
        Self {
            inner,
            until: Instant::now() + budget,
        }
    }
}

impl Dns for Budgeted<'_> {
    fn lookup(&self, rtype: RecordType, name: &str) -> Answer {
        if Instant::now() >= self.until {
            return Answer::TempError {
                reason: "dns budget spent".into(),
            };
        }
        self.inner.lookup(rtype, name)
    }

    fn stands_for(&self, at: u64) -> bool {
        self.inner.stands_for(at)
    }
}

impl RecordType {
    fn code(self) -> u16 {
        match self {
            Self::Txt => 16,
            Self::A => 1,
            Self::Aaaa => 28,
            Self::Mx => 15,
            Self::Ptr => 12,
        }
    }
}

/// Most entries kept in the live resolver's cache.
const CACHE_MAX: usize = 10_000;
/// Longest a cached answer is kept, whatever its TTL.
const CACHE_TTL_MAX: Duration = Duration::from_secs(3600);
/// How long "no records" and temporary errors are kept.
const CACHE_NEGATIVE: Duration = Duration::from_secs(60);

/// A stub resolver: asks the configured recursive resolvers, in order, over UDP (EDNS0, 1232-byte
/// answers) and over TCP when the answer is truncated. Every query has a deadline; an answer is
/// cached for its TTL (at most an hour), "no records" and failures for a minute.
pub struct LiveDns {
    servers: Vec<SocketAddr>,
    timeout: Duration,
    cache: Mutex<HashMap<(RecordType, String), (Instant, Answer)>>,
}

impl LiveDns {
    /// A resolver asking `servers` with `timeout` per attempt.
    pub fn new(servers: Vec<SocketAddr>, timeout: Duration) -> Self {
        Self {
            servers,
            timeout,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The nameservers of a resolv.conf file (port 53).
    pub fn servers_from_resolv_conf(path: &Path) -> io::Result<Vec<SocketAddr>> {
        let text = std::fs::read_to_string(path)?;
        Ok(text
            .lines()
            .filter_map(|l| l.trim().strip_prefix("nameserver"))
            .filter_map(|v| v.trim().parse::<std::net::IpAddr>().ok())
            .map(|ip| SocketAddr::new(ip, 53))
            .collect())
    }

    fn ask(
        &self,
        server: SocketAddr,
        rtype: RecordType,
        name: &str,
    ) -> Result<(Answer, u32), String> {
        let id = query_id(name);
        let q = encode_query(id, rtype, name)?;
        let bind: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0".parse().map_err(|e| format!("{e}"))?
        } else {
            "[::]:0".parse().map_err(|e| format!("{e}"))?
        };
        let sock = UdpSocket::bind(bind).map_err(|e| format!("bind: {e}"))?;
        sock.set_read_timeout(Some(self.timeout))
            .map_err(|e| e.to_string())?;
        sock.connect(server).map_err(|e| format!("connect: {e}"))?;
        sock.send(&q).map_err(|e| format!("send: {e}"))?;
        let mut buf = vec![0u8; 4096];
        let deadline = Instant::now() + self.timeout;
        let resp = loop {
            let n = sock.recv(&mut buf).map_err(|e| format!("recv: {e}"))?;
            if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
                break buf[..n].to_vec();
            }
            if Instant::now() >= deadline {
                return Err("timeout".into());
            }
        };
        if resp.len() > 2 && resp[2] & 0x02 != 0 {
            // Truncated: ask again over TCP.
            let mut tcp = TcpStream::connect_timeout(&server, self.timeout)
                .map_err(|e| format!("tcp connect: {e}"))?;
            tcp.set_read_timeout(Some(self.timeout))
                .map_err(|e| e.to_string())?;
            tcp.set_write_timeout(Some(self.timeout))
                .map_err(|e| e.to_string())?;
            let len = u16::try_from(q.len()).map_err(|e| e.to_string())?;
            let mut framed = len.to_be_bytes().to_vec();
            framed.extend_from_slice(&q);
            tcp.write_all(&framed)
                .map_err(|e| format!("tcp send: {e}"))?;
            let mut lb = [0u8; 2];
            tcp.read_exact(&mut lb)
                .map_err(|e| format!("tcp recv: {e}"))?;
            let mut full = vec![0u8; usize::from(u16::from_be_bytes(lb))];
            tcp.read_exact(&mut full)
                .map_err(|e| format!("tcp recv: {e}"))?;
            return decode_answer(&full, id, rtype);
        }
        decode_answer(&resp, id, rtype)
    }
}

impl Dns for LiveDns {
    fn lookup(&self, rtype: RecordType, name: &str) -> Answer {
        let name = normalise(name);
        let now = Instant::now();
        if let Ok(c) = self.cache.lock()
            && let Some((until, a)) = c.get(&(rtype, name.clone()))
            && *until > now
        {
            return a.clone();
        }
        let mut last = "no resolver configured".to_string();
        let mut got = None;
        for s in &self.servers {
            match self.ask(*s, rtype, &name) {
                Ok(a) => {
                    got = Some(a);
                    break;
                }
                Err(e) => last = e,
            }
        }
        let (answer, ttl) = got.unwrap_or((Answer::TempError { reason: last }, 0));
        let keep = match &answer {
            Answer::Records { .. } => Duration::from_secs(u64::from(ttl)).min(CACHE_TTL_MAX),
            _ => CACHE_NEGATIVE,
        };
        if let Ok(mut c) = self.cache.lock() {
            if c.len() >= CACHE_MAX {
                c.retain(|_, (until, _)| *until > now);
                if c.len() >= CACHE_MAX {
                    c.clear();
                }
            }
            c.insert((rtype, name), (now + keep, answer.clone()));
        }
        answer
    }
}

fn query_id(name: &str) -> u16 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let h = name.bytes().fold(t, |a, b| a.rotate_left(5) ^ u32::from(b));
    (h ^ (h >> 16)) as u16
}

/// A query for `name` with EDNS0 (1232-byte UDP answers), recursion desired.
pub fn encode_query(id: u16, rtype: RecordType, name: &str) -> Result<Vec<u8>, String> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]);
    for label in normalise(name).split('.').filter(|l| !l.is_empty()) {
        let len = u8::try_from(label.len()).map_err(|_| "label too long".to_string())?;
        if len > 63 {
            return Err("label too long".into());
        }
        q.push(len);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&rtype.code().to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    // OPT: root name, type 41, class = UDP payload size, TTL 0, no data.
    q.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
    Ok(q)
}

fn read_name(msg: &[u8], mut i: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(i).ok_or("name past the end")?;
        if len & 0xc0 == 0xc0 {
            let lo = *msg.get(i + 1).ok_or("pointer past the end")?;
            if end.is_none() {
                end = Some(i + 2);
            }
            jumps += 1;
            if jumps > 32 {
                return Err("compression loop".into());
            }
            i = (usize::from(len & 0x3f) << 8) | usize::from(lo);
            continue;
        }
        if len == 0 {
            return Ok((labels.join("."), end.unwrap_or(i + 1)));
        }
        let l = usize::from(len);
        let label = msg.get(i + 1..i + 1 + l).ok_or("label past the end")?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        i += 1 + l;
    }
}

fn u16_at(msg: &[u8], i: usize) -> Result<u16, String> {
    msg.get(i..i + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or_else(|| "short message".to_string())
}

/// The records of type `rtype` in an answer, and the smallest TTL among them.
pub fn decode_answer(msg: &[u8], id: u16, rtype: RecordType) -> Result<(Answer, u32), String> {
    if msg.len() < 12 || u16_at(msg, 0)? != id || msg[2] & 0x80 == 0 {
        return Err("not an answer to our query".into());
    }
    let rcode = msg[3] & 0x0f;
    match rcode {
        0 => {}
        3 => return Ok((Answer::NoRecords, 0)),
        n => {
            return Ok((
                Answer::TempError {
                    reason: format!("rcode {n}"),
                },
                0,
            ));
        }
    }
    let qd = u16_at(msg, 4)?;
    let an = u16_at(msg, 6)?;
    let mut i = 12;
    for _ in 0..qd {
        let (_, next) = read_name(msg, i)?;
        i = next + 4;
    }
    let mut records = Vec::new();
    let mut ttl_min = u32::MAX;
    for _ in 0..an {
        let (_, next) = read_name(msg, i)?;
        i = next;
        let t = u16_at(msg, i)?;
        let ttl = msg
            .get(i + 4..i + 8)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or("short record")?;
        let rdlen = usize::from(u16_at(msg, i + 8)?);
        let start = i + 10;
        let rdata = msg.get(start..start + rdlen).ok_or("short rdata")?;
        i = start + rdlen;
        if t != rtype.code() {
            continue;
        }
        ttl_min = ttl_min.min(ttl);
        let text = match rtype {
            RecordType::Txt => {
                let mut out = Vec::new();
                let mut j = 0;
                while j < rdata.len() {
                    let l = usize::from(rdata[j]);
                    out.extend_from_slice(rdata.get(j + 1..j + 1 + l).ok_or("short txt")?);
                    j += 1 + l;
                }
                String::from_utf8_lossy(&out).into_owned()
            }
            RecordType::A if rdata.len() == 4 => {
                std::net::Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string()
            }
            RecordType::Aaaa if rdata.len() == 16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(rdata);
                std::net::Ipv6Addr::from(b).to_string()
            }
            RecordType::Mx => {
                let pref = u16_at(msg, start)?;
                let (host, _) = read_name(msg, start + 2)?;
                format!("{pref} {host}")
            }
            RecordType::Ptr => read_name(msg, start)?.0,
            _ => return Err("malformed address record".into()),
        };
        records.push(text);
    }
    if records.is_empty() {
        Ok((Answer::NoRecords, 0))
    } else {
        Ok((Answer::Records { records }, ttl_min))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recording_answers_what_it_holds_and_nothing_else() {
        let mut r = RecordedDns::new();
        r.insert(Lookup {
            rtype: RecordType::Txt,
            name: "_dmarc.Example.ORG.".into(),
            answer: Answer::Records {
                records: vec!["v=DMARC1; p=reject".into()],
            },
        });
        r.insert(Lookup {
            rtype: RecordType::Txt,
            name: "x._domainkey.example.org".into(),
            answer: Answer::NoRecords,
        });
        assert!(matches!(
            r.lookup(RecordType::Txt, "_dmarc.example.org"),
            Answer::Records { .. }
        ));
        assert_eq!(
            r.lookup(RecordType::Txt, "x._domainkey.example.org."),
            Answer::NoRecords
        );
        assert!(matches!(
            r.lookup(RecordType::Txt, "other.example.org"),
            Answer::TempError { .. }
        ));
        assert!(matches!(
            r.lookup(RecordType::A, "_dmarc.example.org"),
            Answer::TempError { .. }
        ));
    }

    #[test]
    fn adding_a_recording_never_changes_an_answer_already_held() {
        let one = |a: Answer| {
            let mut r = RecordedDns::new();
            r.insert(Lookup {
                rtype: RecordType::Txt,
                name: "s._domainkey.example.org".into(),
                answer: a,
            });
            r
        };
        let mut main = one(Answer::Records {
            records: vec!["v=DKIM1; p=AAAA".into()],
        });
        let mut later = one(Answer::TempError {
            reason: "rcode 2".into(),
        });
        later.insert(Lookup {
            rtype: RecordType::Txt,
            name: "_dmarc.example.org".into(),
            answer: Answer::NoRecords,
        });
        main.extend(later);
        assert!(matches!(
            main.lookup(RecordType::Txt, "s._domainkey.example.org"),
            Answer::Records { .. }
        ));
        assert_eq!(
            main.lookup(RecordType::Txt, "_dmarc.example.org"),
            Answer::NoRecords,
            "new names are added"
        );
    }

    #[test]
    fn a_recording_stands_only_for_its_window_and_wrappers_say_the_same() {
        let mut r = RecordedDns::new();
        assert!(
            r.stands_for(0) && r.stands_for(u64::MAX),
            "no window: any time"
        );
        r.set_window(1_000, 2_000);
        assert!(!r.stands_for(999));
        assert!(r.stands_for(1_000) && r.stands_for(2_000));
        assert!(!r.stands_for(2_001));
        let logged = Logged::new(&r);
        assert!(!logged.stands_for(999) && logged.stands_for(1_500));
        let budgeted = Budgeted::new(&r, Duration::from_secs(1));
        assert!(!budgeted.stands_for(999) && budgeted.stands_for(1_500));
        assert_eq!(parse_window("1000, 2000"), Ok((1_000, 2_000)));
        assert!(parse_window("2000,1000").is_err() && parse_window("1000").is_err());
    }

    #[test]
    fn the_log_keeps_each_lookup_once_and_round_trips_as_json() {
        let mut r = RecordedDns::new();
        r.insert(Lookup {
            rtype: RecordType::Txt,
            name: "a.example".into(),
            answer: Answer::NoRecords,
        });
        let logged = Logged::new(&r);
        logged.lookup(RecordType::Txt, "A.example.");
        logged.lookup(RecordType::Txt, "a.example");
        logged.lookup(RecordType::Txt, "b.example");
        let l = logged.into_lookups();
        assert_eq!(l.len(), 2);
        let line = serde_json::to_string(&l[1]).unwrap();
        assert_eq!(
            line,
            r#"{"type":"TXT","name":"b.example","result":"temp_error","reason":"not recorded"}"#
        );
        let back: Lookup = serde_json::from_str(&line).unwrap();
        assert_eq!(back, l[1]);
    }

    /// (name, type, records, rcode, truncate over UDP).
    type Entry = (&'static str, u16, Vec<Vec<u8>>, u8, bool);

    /// A DNS server on localhost that answers from a table, truncating over UDP when asked to.
    fn fake_server(answers: Vec<Entry>) -> SocketAddr {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = std::net::TcpListener::bind(addr).unwrap();
        let table = std::sync::Arc::new(answers);
        let respond = {
            let table = table.clone();
            move |q: &[u8], over_udp: bool| -> Vec<u8> {
                let (name, next) = read_name(q, 12).unwrap();
                let qtype = u16_at(q, next).unwrap();
                let entry = table.iter().find(|(n, t, ..)| *n == name && *t == qtype);
                let mut r = q[..2].to_vec();
                let (rcode, trunc, recs) = match entry {
                    Some((_, _, recs, rcode, trunc)) => (*rcode, *trunc && over_udp, recs.clone()),
                    None => (3, false, vec![]),
                };
                let n = if trunc { 0 } else { recs.len() as u16 };
                r.extend_from_slice(&[0x81 | if trunc { 0x02 } else { 0 }, 0x80 | rcode]);
                r.extend_from_slice(&[0, 1]);
                r.extend_from_slice(&n.to_be_bytes());
                r.extend_from_slice(&[0, 0, 0, 0]);
                r.extend_from_slice(&q[12..next + 4]);
                if !trunc {
                    for rd in recs {
                        r.extend_from_slice(&[0xc0, 12]);
                        r.extend_from_slice(&qtype.to_be_bytes());
                        r.extend_from_slice(&[0, 1, 0, 0, 0x0e, 0x10]);
                        r.extend_from_slice(&(rd.len() as u16).to_be_bytes());
                        r.extend_from_slice(&rd);
                    }
                }
                r
            }
        };
        let r2 = respond.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = udp.recv_from(&mut buf) {
                let _ = udp.send_to(&respond(&buf[..n], true), from);
            }
        });
        std::thread::spawn(move || {
            for mut s in tcp.incoming().flatten() {
                let mut lb = [0u8; 2];
                if s.read_exact(&mut lb).is_err() {
                    continue;
                }
                let mut q = vec![0u8; u16::from_be_bytes(lb) as usize];
                if s.read_exact(&mut q).is_err() {
                    continue;
                }
                let r = r2(&q, false);
                let mut out = (r.len() as u16).to_be_bytes().to_vec();
                out.extend_from_slice(&r);
                let _ = s.write_all(&out);
            }
        });
        addr
    }

    fn txt(parts: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for p in parts {
            out.push(p.len() as u8);
            out.extend_from_slice(p.as_bytes());
        }
        out
    }

    #[test]
    fn the_live_resolver_reads_txt_falls_back_to_tcp_and_caches() {
        let long = "p=".to_string() + &"A".repeat(250);
        let server = fake_server(vec![
            (
                "_dmarc.example.org",
                16,
                vec![txt(&["v=DMARC1; ", "p=reject"])],
                0,
                false,
            ),
            (
                "k._domainkey.example.org",
                16,
                vec![txt(&["v=DKIM1; ", &long])],
                0,
                true,
            ),
            ("broken.example.org", 16, vec![], 2, false),
            ("example.org", 1, vec![vec![192, 0, 2, 7]], 0, false),
        ]);
        let dns = LiveDns::new(vec![server], Duration::from_millis(500));
        assert_eq!(
            dns.lookup(RecordType::Txt, "_dmarc.Example.org."),
            Answer::Records {
                records: vec!["v=DMARC1; p=reject".into()]
            }
        );
        match dns.lookup(RecordType::Txt, "k._domainkey.example.org") {
            Answer::Records { records } => assert!(records[0].ends_with(&"A".repeat(250))),
            other => panic!("truncated answer not fetched over TCP: {other:?}"),
        }
        assert_eq!(
            dns.lookup(RecordType::Txt, "nope.example.org"),
            Answer::NoRecords
        );
        assert!(matches!(
            dns.lookup(RecordType::Txt, "broken.example.org"),
            Answer::TempError { .. }
        ));
        assert_eq!(
            dns.lookup(RecordType::A, "example.org"),
            Answer::Records {
                records: vec!["192.0.2.7".into()]
            }
        );
        // Cached: the same answer without asking again.
        let again = LiveDns {
            servers: vec![],
            timeout: Duration::from_millis(10),
            cache: Mutex::new(dns.cache.lock().unwrap().clone()),
        };
        assert!(matches!(
            again.lookup(RecordType::Txt, "_dmarc.example.org"),
            Answer::Records { .. }
        ));
    }

    #[test]
    fn an_unreachable_resolver_is_a_temporary_error_within_the_deadline() {
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dns = LiveDns::new(
            vec![silent.local_addr().unwrap()],
            Duration::from_millis(200),
        );
        let t = Instant::now();
        assert!(matches!(
            dns.lookup(RecordType::Txt, "example.org"),
            Answer::TempError { .. }
        ));
        assert!(t.elapsed() < Duration::from_millis(1000));
    }
}
