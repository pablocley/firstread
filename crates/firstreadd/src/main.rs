//! `firstreadd`: the daemon.
//!
//! Implemented: the delivery socket for `firstread-filter` (frames of `firstread-core::wire`),
//! the pipeline of `firstread-pipeline` per message, a tier-1 provider reached over a local
//! socket (a [`Decider`] with locality `LocalService`), one JSON record per decision appended
//! to a records file, and with `--memory` the mailbox memory of `firstread-graph`: read on every
//! delivery, updated after the reply is sent, and taught by the mailbox owner's actions through
//! the feedback socket (`firstread feedback`, called by Dovecot IMAPSieve scripts, hook D). With
//! `--dns-recorded` (recorded answers, the lab) or `--dns-live` (a stub resolver with a deadline
//! per attempt and a budget per message), our own DKIM and DMARC checks run on every message, and
//! every lookup goes into the record.
//!
//! With `--tier2` a second provider (the decision model, Mica, behind the same sidecar protocol)
//! answers after delivery, from a bounded in-memory queue, for mailboxes with rules written in
//! words (`--rules DIR`) and for verdicts that came close (`--tier2-from`); `--hook-c` applies what
//! it adds through `doveadm` (`late.rs`). `--api-socket` serves the records read-only (`api.rs`).
//!
//! Still to build (docs/01-architecture.md): push-notification events (hook G), the API's
//! authentication front end and search, load shedding and metrics.
//!
//! Configuration is by flags; `firstreadd --help` lists them.

mod api;
mod late;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use firstread_core::context::DeliveryContext;
use firstread_core::decision::{ModelRelease, Question, QuestionId, QuestionKind};
use firstread_core::directive::{Directive, DirectivePolicy, FolderKey};
use firstread_core::provider::{
    Calibration, DataClass, Decider, Locality, Manifest, ProviderError, Rendered,
};
use firstread_core::verdict::VerdictKind;
use firstread_core::wire::{
    MAX_JSON_FRAME, Reply, Request, WireDirective, read_frame, write_frame,
};
use firstread_graph::{
    Applied, FileStore, Hasher, MailboxMemory, MemoryEvent, MemoryStore, MessageKeys, SentKeys,
};
use firstread_net::{Budgeted, Dns, LiveDns, RecordedDns};
use firstread_pipeline::{Checks, Clock, Combiner, Config, Memory, Tier1};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_MESSAGE: u64 = 64 * 1024 * 1024;

struct Args {
    socket: PathBuf,
    sidecar: Option<PathBuf>,
    combiner: Option<PathBuf>,
    calibration: Option<PathBuf>,
    records: Option<PathBuf>,
    deployment: String,
    mac_key: String,
    trusted: Vec<String>,
    junk_threshold: f64,
    render_max_chars: usize,
    data_class: DataClass,
    sidecar_timeout_ms: u64,
    shadow: bool,
    memory: Option<PathBuf>,
    feedback_socket: Option<PathBuf>,
    own_actors: Vec<String>,
    dns_recorded: Vec<PathBuf>,
    dns_window: Option<(u64, u64)>,
    dns_live: bool,
    dns_servers: Vec<std::net::SocketAddr>,
    dns_timeout_ms: u64,
    dns_budget_ms: u64,
    clock_message: bool,
    verdict_combiners: Vec<(VerdictKind, PathBuf)>,
    language: String,
    detail_headers: bool,
    folders: Vec<FolderKey>,
    questions: Option<PathBuf>,
    actions: Option<PathBuf>,
    reasons: Option<PathBuf>,
    tier2: Option<PathBuf>,
    tier2_calibration: Option<PathBuf>,
    tier2_from: f64,
    tier2_timeout_ms: u64,
    rules: Option<PathBuf>,
    hook_c: Option<PathBuf>,
    hook_c_folders: BTreeMap<String, String>,
    api_socket: Option<PathBuf>,
}

/// Most messages waiting for tier 2; past it new ones are not escalated (counted in the log).
const LATE_QUEUE: usize = 256;

const HELP: &str = "firstreadd --socket PATH [--sidecar PATH --calibration FILE] [--combiner FILE]
  [--records FILE] [--deployment ID] [--mac-key KEY] [--trusted-authserv ID,ID]
  [--junk-threshold P] [--render-max-chars N] [--data-class public|synthetic|customer]
  [--sidecar-timeout-ms MS] [--shadow]
  [--memory DIR [--feedback-socket PATH] [--own-actors NAME,NAME]]
  [--dns-recorded FILE ... [--dns-window FROM,TO] | --dns-live [--dns-server IP:PORT ...] [--dns-timeout-ms MS]]
  [--dns-budget-ms MS] [--clock wall|message]
  [--verdict-combiner KIND=FILE ...] [--folders KEY,KEY] [--language TAG] [--no-detail-headers]
  [--questions FILE] [--actions FILE] [--reasons FILE]
  [--tier2 PATH --tier2-calibration FILE [--tier2-from P] [--tier2-timeout-ms MS] [--rules DIR]
   [--hook-c DOVEADM --hook-c-folders KEY=NAME,KEY=NAME]] [--api-socket PATH]

--shadow: decide and record every message as usual, but reply with an empty directive, so the
filter only removes foreign firstread headers and nothing is visible or filed
(docs/07-evaluation.md, rollout step 1). Records carry \"shadow\": true. Memory still learns.

--memory: per-mailbox memory (state and event log, keyed hashes only) in DIR; its facts
(mailbox.*) join the combiner's inputs. --feedback-socket: where `firstread feedback` reports the
mailbox owner's actions. --own-actors: actors whose feedback is firstread's own (for example the
account hook C uses); it is dropped, never learned.

--dns-recorded: run our own DKIM and DMARC checks against these DNS recordings (one lookup per
line, firstread-net; may be given more than once: a name two files hold keeps the earlier
file's answer). A name no recording holds is a temporary
error, never \"no record\". --dns-window: the period the recordings stand for, Unix seconds; a
message judged at a time outside it gets no answers (every lookup a temporary error), so today's
keys and policies are never applied to old mail. --clock: the time signatures are judged at: wall
(default) or message (the message's Date header; for replaying corpora only).

--dns-live: run the checks against live DNS: the --dns-server resolvers, else the nameservers of
/etc/resolv.conf; --dns-timeout-ms per attempt (default 400). --dns-budget-ms: most time one
message may spend on DNS (default 800); after it, lookups are temporary errors.

--verdict-combiner: the combiner of one more verdict (phishing, fraud, needs_action, important,
bulk_low_interest); --combiner is junk's. A verdict without a combiner is not decided. Phishing
and fraud combiners may not let mailbox facts lower P (the safety floor). --folders: the folder
keys this mailbox mode allows (default inbox,junk; the sieve_after script needs one literal
fileinto per key, and firstread-filter the same list in FIRSTREAD_FOLDERS). --language: of the
reason texts (default en). --no-detail-headers: write only X-Firstread and the folder and keyword
headers. --questions, --actions, --reasons: replace the data files compiled in
(crates/firstread-stamp/data/).

--tier2: a decision model (tier 2) behind the sidecar protocol, asked after delivery, never in
it; --tier2-calibration is required (no calibration, no decision; user rules use `rule:*`).
A message goes to tier 2 when its mailbox has rules (--rules DIR, one <user>.json per mailbox:
{\"rules\": [{\"id\", \"text\", \"tag\"}]}) or a verdict reached --tier2-from (default 0.3)
without holding. Queue: in memory, bounded; the message is never written to disk. Updates are
appended to --records under the same id. --hook-c: apply them with this doveadm (keywords added;
a move only from INBOX and never for $NotJunk); --hook-c-folders maps folder keys to the folder
names the sieve_after script uses. Never in --shadow mode.

--api-socket: read-only HTTP on a local socket: GET /v1/messages/{id} with header
X-Firstread-User: the record, only for its own mailbox; GET /v1/health.";

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        socket: PathBuf::from("/run/firstread/filter.sock"),
        sidecar: None,
        combiner: None,
        calibration: None,
        records: None,
        deployment: "dev".into(),
        mac_key: String::new(),
        trusted: vec![],
        junk_threshold: 1.0,
        render_max_chars: 2000,
        data_class: DataClass::Customer,
        sidecar_timeout_ms: 30_000,
        shadow: false,
        memory: None,
        feedback_socket: None,
        own_actors: vec![],
        dns_recorded: vec![],
        dns_window: None,
        dns_live: false,
        dns_servers: vec![],
        dns_timeout_ms: 400,
        dns_budget_ms: 800,
        clock_message: false,
        verdict_combiners: vec![],
        language: "en".into(),
        detail_headers: true,
        folders: vec![],
        questions: None,
        actions: None,
        reasons: None,
        tier2: None,
        tier2_calibration: None,
        tier2_from: 0.3,
        tier2_timeout_ms: 60_000,
        rules: None,
        hook_c: None,
        hook_c_folders: BTreeMap::new(),
        api_socket: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--socket" => a.socket = val()?.into(),
            "--sidecar" => a.sidecar = Some(val()?.into()),
            "--combiner" => a.combiner = Some(val()?.into()),
            "--calibration" => a.calibration = Some(val()?.into()),
            "--records" => a.records = Some(val()?.into()),
            "--deployment" => a.deployment = val()?,
            "--mac-key" => a.mac_key = val()?,
            "--trusted-authserv" => {
                a.trusted = val()?
                    .split(',')
                    .map(str::to_string)
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "--junk-threshold" => a.junk_threshold = val()?.parse().map_err(|e| format!("{e}"))?,
            "--render-max-chars" => {
                a.render_max_chars = val()?.parse().map_err(|e| format!("{e}"))?
            }
            "--sidecar-timeout-ms" => {
                a.sidecar_timeout_ms = val()?.parse().map_err(|e| format!("{e}"))?;
            }
            "--data-class" => {
                a.data_class = match val()?.as_str() {
                    "public" => DataClass::Public,
                    "synthetic" => DataClass::Synthetic,
                    "customer" => DataClass::Customer,
                    other => return Err(format!("unknown data class {other}")),
                };
            }
            "--shadow" => a.shadow = true,
            "--memory" => a.memory = Some(val()?.into()),
            "--feedback-socket" => a.feedback_socket = Some(val()?.into()),
            "--own-actors" => {
                a.own_actors = val()?
                    .split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "--dns-recorded" => a.dns_recorded.push(val()?.into()),
            "--dns-window" => a.dns_window = Some(firstread_net::parse_window(&val()?)?),
            "--dns-live" => a.dns_live = true,
            "--dns-server" => {
                let v = val()?;
                let addr = v
                    .parse::<std::net::SocketAddr>()
                    .or_else(|_| v.parse::<std::net::IpAddr>().map(|ip| (ip, 53).into()))
                    .map_err(|e| format!("--dns-server {v}: {e}"))?;
                a.dns_servers.push(addr);
            }
            "--dns-timeout-ms" => a.dns_timeout_ms = val()?.parse().map_err(|e| format!("{e}"))?,
            "--dns-budget-ms" => a.dns_budget_ms = val()?.parse().map_err(|e| format!("{e}"))?,
            "--clock" => {
                a.clock_message = match val()?.as_str() {
                    "wall" => false,
                    "message" => true,
                    other => return Err(format!("unknown clock {other}")),
                };
            }
            "--verdict-combiner" => {
                let v = val()?;
                let (k, f) = v
                    .split_once('=')
                    .ok_or_else(|| format!("--verdict-combiner {v}: KIND=FILE"))?;
                let kind = VerdictKind::parse(k).ok_or_else(|| format!("unknown verdict {k}"))?;
                if kind == VerdictKind::Junk {
                    return Err("junk's combiner is --combiner".into());
                }
                a.verdict_combiners.push((kind, f.into()));
            }
            "--folders" => {
                a.folders = val()?
                    .split(',')
                    .filter(|k| !k.is_empty())
                    .map(|k| FolderKey::new(k).map_err(|e| format!("--folders: {e}")))
                    .collect::<Result<_, _>>()?;
            }
            "--language" => a.language = val()?,
            "--no-detail-headers" => a.detail_headers = false,
            "--questions" => a.questions = Some(val()?.into()),
            "--actions" => a.actions = Some(val()?.into()),
            "--reasons" => a.reasons = Some(val()?.into()),
            "--tier2" => a.tier2 = Some(val()?.into()),
            "--tier2-calibration" => a.tier2_calibration = Some(val()?.into()),
            "--tier2-from" => a.tier2_from = val()?.parse().map_err(|e| format!("{e}"))?,
            "--tier2-timeout-ms" => {
                a.tier2_timeout_ms = val()?.parse().map_err(|e| format!("{e}"))?;
            }
            "--rules" => a.rules = Some(val()?.into()),
            "--hook-c" => a.hook_c = Some(val()?.into()),
            "--hook-c-folders" => {
                for pair in val()?.split(',').filter(|p| !p.is_empty()) {
                    let (k, n) = pair
                        .split_once('=')
                        .ok_or_else(|| format!("--hook-c-folders {pair}: KEY=NAME"))?;
                    FolderKey::new(k).map_err(|e| format!("--hook-c-folders: {e}"))?;
                    a.hook_c_folders.insert(k.to_string(), n.to_string());
                }
            }
            "--api-socket" => a.api_socket = Some(val()?.into()),
            "--help" | "-h" => return Err(HELP.into()),
            other => return Err(format!("unknown flag {other}\n{HELP}")),
        }
    }
    if a.mac_key.is_empty() {
        return Err("--mac-key is required".into());
    }
    if a.sidecar.is_some() && a.calibration.is_none() {
        return Err("--sidecar needs --calibration: no calibration, no decision".into());
    }
    if a.tier2.is_some() != a.tier2_calibration.is_some() {
        return Err(
            "--tier2 and --tier2-calibration go together: no calibration, no decision".into(),
        );
    }
    if (a.rules.is_some() || a.hook_c.is_some()) && a.tier2.is_none() {
        return Err("--rules and --hook-c need --tier2".into());
    }
    if a.feedback_socket.is_some() && a.memory.is_none() {
        return Err("--feedback-socket needs --memory".into());
    }
    if a.dns_live && !a.dns_recorded.is_empty() {
        return Err("--dns-live and --dns-recorded exclude each other".into());
    }
    if a.dns_window.is_some() && a.dns_recorded.is_empty() {
        return Err("--dns-window needs --dns-recorded".into());
    }
    Ok(a)
}

#[derive(Deserialize)]
struct SidecarManifest {
    release: String,
    licence: String,
    commercial_use: bool,
    #[serde(default)]
    languages: Vec<String>,
    max_input_tokens: u32,
    supported: Vec<String>,
}

#[derive(Deserialize)]
struct SidecarLogits {
    logits: Vec<Vec<f32>>,
}

#[derive(Deserialize)]
struct CalibrationFile {
    release: String,
    temperatures: BTreeMap<String, f32>,
}

/// A tier-1 provider in another process on this machine.
struct SidecarDecider {
    path: PathBuf,
    timeout: Duration,
    manifest: Manifest,
    supported: Vec<String>,
}

fn sidecar_call(
    path: &PathBuf,
    timeout: Duration,
    req: &serde_json::Value,
) -> Result<Vec<u8>, String> {
    let mut s = UnixStream::connect(path).map_err(|e| format!("connect: {e}"))?;
    s.set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    let body = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    write_frame(&mut s, &body).map_err(|e| format!("write: {e}"))?;
    read_frame(&mut s, 64 * 1024 * 1024).map_err(|e| format!("read: {e}"))
}

impl SidecarDecider {
    fn connect(path: PathBuf, timeout: Duration) -> Result<Self, String> {
        let raw = sidecar_call(&path, timeout, &serde_json::json!({"op": "manifest"}))?;
        let m: SidecarManifest =
            serde_json::from_slice(&raw).map_err(|e| format!("manifest: {e}"))?;
        Ok(Self {
            path,
            timeout,
            manifest: Manifest {
                release: ModelRelease(m.release),
                weights_sha256: None,
                licence: m.licence,
                commercial_use: m.commercial_use,
                locality: Locality::LocalService,
                measured_languages: m.languages,
                max_input_tokens: m.max_input_tokens,
            },
            supported: m.supported,
        })
    }
}

impl Decider for SidecarDecider {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    /// A decision model reads the question text, so it declares `*`: any question.
    fn supports(&self, q: &Question) -> bool {
        self.supported.iter().any(|s| s == "*" || *s == q.id.0)
    }
    fn logits(
        &self,
        input: &Rendered<'_>,
        questions: &[Question],
    ) -> Result<Vec<Vec<f32>>, ProviderError> {
        let ids: Vec<&str> = questions.iter().map(|q| q.id.0.as_str()).collect();
        // Heads need only the ids; a decision model needs each question's text and outcomes.
        let specs: Vec<serde_json::Value> = questions
            .iter()
            .map(|q| {
                let (kind, outcomes) = match &q.kind {
                    QuestionKind::Noul => ("noul", vec![]),
                    QuestionKind::Choice { options } => ("choice", options.clone()),
                    QuestionKind::Score { levels } => ("score", levels.clone()),
                };
                serde_json::json!({"id": q.id.0, "text": q.text, "kind": kind, "outcomes": outcomes})
            })
            .collect();
        let req = serde_json::json!({"op": "logits", "text": input.text, "questions": ids, "specs": specs});
        let raw = sidecar_call(&self.path, self.timeout, &req).map_err(ProviderError::Backend)?;
        let r: SidecarLogits =
            serde_json::from_slice(&raw).map_err(|e| ProviderError::Backend(e.to_string()))?;
        Ok(r.logits)
    }
}

/// Most mailbox memories kept loaded; past it the cache is emptied (everything is on disk).
const MAX_LOADED_MAILBOXES: usize = 1000;
/// Save a mailbox's state every this many events (its event log has every one).
const SAVE_EVERY: u64 = 50;

/// The mailbox memories: loaded on first use, one lock per mailbox, every applied event appended
/// to the mailbox's event log and the state saved.
struct Hub {
    store: FileStore,
    hasher: Hasher,
    boxes: Mutex<HashMap<String, Arc<Mutex<MailboxMemory>>>>,
    own_actors: Vec<String>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

impl Hub {
    fn mailbox(&self, name: &str) -> Result<Arc<Mutex<MailboxMemory>>, String> {
        let key = name.to_ascii_lowercase();
        let mut boxes = self.boxes.lock().map_err(|_| "memory lock poisoned")?;
        if let Some(m) = boxes.get(&key) {
            return Ok(Arc::clone(m));
        }
        if boxes.len() >= MAX_LOADED_MAILBOXES {
            boxes.clear();
        }
        let m = Arc::new(Mutex::new(
            self.store.load(&key).map_err(|e| format!("memory: {e}"))?,
        ));
        boxes.insert(key, Arc::clone(&m));
        Ok(m)
    }

    fn commit(
        &self,
        mailbox: &str,
        mem: &mut MailboxMemory,
        e: &MemoryEvent,
    ) -> Result<Applied, String> {
        let key = mailbox.to_ascii_lowercase();
        let applied = mem.apply(e);
        if applied == Applied::Applied {
            // The event log is the source of truth; the state is saved now and then, and
            // loading replays the log past the saved state.
            self.store
                .append(&key, e)
                .map_err(|e| format!("memory log: {e}"))?;
            if mem.events.is_multiple_of(SAVE_EVERY) {
                self.store
                    .save(&key, mem)
                    .map_err(|e| format!("memory save: {e}"))?;
            }
        }
        Ok(applied)
    }

    fn forget(&self, mailbox: &str) -> Result<(), String> {
        let key = mailbox.to_ascii_lowercase();
        let mut boxes = self.boxes.lock().map_err(|_| "memory lock poisoned")?;
        boxes.remove(&key);
        self.store.forget(&key).map_err(|e| format!("forget: {e}"))
    }

    fn is_own(&self, actor: Option<&str>) -> bool {
        actor.is_some_and(|a| self.own_actors.contains(&a.to_ascii_lowercase()))
    }
}

struct State {
    cfg: Config,
    tier1: Option<(SidecarDecider, Calibration)>,
    combiner: Option<Combiner>,
    records: Option<api::Records>,
    shadow: bool,
    tier2: Option<(SidecarDecider, Calibration)>,
    tier2_from: f64,
    rules: Option<PathBuf>,
    late: Option<std::sync::mpsc::SyncSender<late::Job>>,
    hook_c: Option<late::HookC>,
    memory: Option<Hub>,
    dns: Option<Box<dyn Dns>>,
    dns_budget: Duration,
    clock_message: bool,
}

fn handle(state: &State, mut s: UnixStream) -> Result<(), String> {
    s.set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    let head = read_frame(&mut s, MAX_JSON_FRAME).map_err(|e| format!("read request: {e}"))?;
    let req: Request = serde_json::from_slice(&head).map_err(|e| format!("request: {e}"))?;
    if req.message_len > MAX_MESSAGE {
        return Err("message too large".into());
    }
    let mut message = vec![0u8; usize::try_from(req.message_len).map_err(|e| e.to_string())?];
    s.read_exact(&mut message)
        .map_err(|e| format!("read message: {e}"))?;
    let env = |k: &str| match k {
        "USER" => Some(req.user.clone()),
        "SENDER" => Some(req.sender.clone()),
        "RECIPIENT" => Some(req.recipient.clone()),
        "ORIG_RECIPIENT" => req.orig_recipient.clone(),
        _ => None,
    };
    let ctx = DeliveryContext::from_dovecot_env(env).map_err(|e| format!("context: {e:?}"))?;
    let tier1 = state.tier1.as_ref().map(|(d, c)| Tier1 {
        decider: d as &dyn Decider,
        calibration: c,
    });
    // The mailbox's memory is held for the whole delivery, so deliveries to one mailbox are
    // decided in order and each sees the ones before it. A memory failure never blocks delivery:
    // the message is decided without memory and the error is recorded.
    let mut memory_error = None;
    let held = match &state.memory {
        Some(hub) => match hub.mailbox(&ctx.user) {
            Ok(m) => Some((hub, m)),
            Err(e) => {
                memory_error = Some(e);
                None
            }
        },
        None => None,
    };
    let mut guard = match &held {
        Some((_, m)) => Some(m.lock().map_err(|_| "mailbox lock poisoned".to_string())?),
        None => None,
    };
    let mem = match (&held, &guard) {
        (Some((hub, _)), Some(g)) => Some(Memory {
            hasher: &hub.hasher,
            state: g,
        }),
        _ => None,
    };
    let budgeted = state
        .dns
        .as_ref()
        .map(|d| Budgeted::new(d.as_ref(), state.dns_budget));
    let checks = budgeted.as_ref().map(|d| Checks {
        dns: d as &dyn Dns,
        clock: if state.clock_message {
            Clock::MessageDate
        } else {
            Clock::At(u64::try_from(now()).unwrap_or(0))
        },
    });
    let mut out = firstread_pipeline::run(
        &state.cfg,
        &message,
        &ctx,
        tier1,
        state.combiner.as_ref(),
        mem,
        checks,
    );
    if let Some(e) = memory_error {
        out.record.provenance.errors.push(e);
    }
    // In shadow mode the decision is recorded but not applied: the filter gets an empty directive.
    let applied = if state.shadow {
        Directive::default()
    } else {
        out.directive.clone()
    };
    let reply = Reply {
        v: 1,
        stamp_id: out.record.id.clone(),
        directive: WireDirective::from_directive(&applied),
    };
    // The record is written before the reply, so a decision the filter applied is always recorded.
    if let Some(r) = &state.records {
        let mut rec = serde_json::to_value(&out.record).map_err(|e| e.to_string())?;
        if state.shadow {
            rec["shadow"] = serde_json::Value::Bool(true);
        }
        r.append(&rec)?;
    }
    let body = serde_json::to_vec(&reply).map_err(|e| e.to_string())?;
    let sent = write_frame(&mut s, &body).map_err(|e| format!("write reply: {e}"));
    // Learning happens after the reply: the delivery is a fact whatever the verdict was.
    if let (Some((hub, _)), Some(g), Some(keys)) = (&held, guard.as_mut(), out.keys) {
        let e = MemoryEvent::Delivered { at: now(), keys };
        hub.commit(&ctx.user, g, &e)?;
    }
    // Tier 2 after the reply, never before it: a full queue skips the late answer, not the mail.
    if let Some(tx) = &state.late {
        let has_rules = state
            .rules
            .as_ref()
            .and_then(|d| late::rules_path(d, &ctx.user))
            .is_some_and(|p| p.exists());
        if !state.shadow
            && firstread_pipeline::wants_tier2(&out.record, state.tier2_from, has_rules)
        {
            let job = late::Job {
                record: out.record,
                user: ctx.user.clone(),
                message,
            };
            if tx.try_send(job).is_err() {
                eprintln!("firstreadd: tier 2 queue full, message not escalated");
            }
        }
    }
    sent
}

/// The tier-2 worker: one job at a time, in arrival order.
fn late_worker(state: &State, rx: &std::sync::mpsc::Receiver<late::Job>) {
    while let Ok(job) = rx.recv() {
        if let Err(e) = late_one(state, job) {
            eprintln!("firstreadd: tier 2: {e}");
        }
    }
}

fn late_one(state: &State, job: late::Job) -> Result<(), String> {
    let (d, cal) = state.tier2.as_ref().ok_or("no tier 2")?;
    let rules = match &state.rules {
        Some(dir) => late::load_rules(dir, &job.user)?,
        None => vec![],
    };
    let u = firstread_pipeline::tier2_update(
        &state.cfg,
        state.combiner.as_ref(),
        &job.record,
        &job.message,
        Tier1 {
            decider: d as &dyn Decider,
            calibration: cal,
        },
        &rules,
    )?;
    if let Some(r) = &state.records {
        r.append(&serde_json::to_value(&u.record).map_err(|e| e.to_string())?)?;
    }
    if let Some(hook) = &state.hook_c {
        let mid = firstread_parse::parse(&job.message)
            .ok()
            .and_then(|p| p.state.message_id)
            .ok_or("hook C: the message has no Message-ID to find it by")?;
        let mid = format!("<{}>", mid.trim_matches(['<', '>']));
        late::apply(hook, &late::hook_c_commands(hook, &job.user, &mid, &u))?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct FeedbackRequest {
    v: u32,
    op: String,
    mailbox: String,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    at: Option<i64>,
    #[serde(default)]
    message_len: u64,
}

/// One report of the mailbox owner's action: `junk` / `not_junk` (moved into or out of Junk),
/// `sent` (a copy reached Sent), or `forget` (erase the mailbox's memory).
fn handle_feedback(hub: &Hub, mut s: UnixStream) -> Result<(), String> {
    s.set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    let head = read_frame(&mut s, MAX_JSON_FRAME).map_err(|e| format!("read request: {e}"))?;
    let req: FeedbackRequest =
        serde_json::from_slice(&head).map_err(|e| format!("request: {e}"))?;
    if req.v != 1 {
        return Err(format!("feedback protocol v{}", req.v));
    }
    if req.message_len > MAX_MESSAGE {
        return Err("message too large".into());
    }
    let mut message = vec![0u8; usize::try_from(req.message_len).map_err(|e| e.to_string())?];
    s.read_exact(&mut message)
        .map_err(|e| format!("read message: {e}"))?;
    let reply = if req.op == "forget" {
        hub.forget(&req.mailbox)?;
        serde_json::json!({"result": "forgotten"})
    } else if hub.is_own(req.actor.as_deref()) {
        eprintln!("firstreadd: dropped feedback from own actor (never learned)");
        serde_json::json!({"result": "dropped"})
    } else {
        let p = firstread_parse::parse(&message).map_err(|e| format!("parse: {e:?}"))?;
        let at = req.at.unwrap_or_else(now);
        let e = match req.op.as_str() {
            "junk" | "not_junk" => MemoryEvent::Label {
                at,
                keys: MessageKeys::from_parsed(&hub.hasher, &p, false),
                junk: req.op == "junk",
            },
            "sent" => MemoryEvent::Sent {
                at,
                keys: SentKeys::from_parsed(&hub.hasher, &p),
            },
            other => return Err(format!("unknown feedback op {other}")),
        };
        let m = hub.mailbox(&req.mailbox)?;
        let mut g = m.lock().map_err(|_| "mailbox lock poisoned".to_string())?;
        let applied = hub.commit(&req.mailbox, &mut g, &e)?;
        serde_json::json!({
            "result": if applied == Applied::Applied { "applied" } else { "duplicate" },
            "snapshot": g.snapshot(),
        })
    };
    let body = serde_json::to_vec(&reply).map_err(|e| e.to_string())?;
    write_frame(&mut s, &body).map_err(|e| format!("write reply: {e}"))
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &PathBuf) -> Result<T, String> {
    let f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_reader(f).map_err(|e| format!("{}: {e}", path.display()))
}

fn run() -> Result<(), String> {
    let a = parse_args()?;
    let read =
        |p: &PathBuf| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()));
    let questions = match &a.questions {
        Some(p) => firstread_stamp::parse_questions(&read(p)?)?,
        None => firstread_stamp::questions(),
    };
    let actions = match &a.actions {
        Some(p) => firstread_stamp::Actions::parse(&read(p)?)?,
        None => firstread_stamp::Actions::default(),
    }
    .with_junk_threshold(a.junk_threshold);
    let reasons = match &a.reasons {
        Some(p) => firstread_stamp::Reasons::parse(&read(p)?)?,
        None => firstread_stamp::Reasons::default(),
    };
    let mut verdicts = BTreeMap::new();
    for (kind, path) in &a.verdict_combiners {
        let c: Combiner = load_json(path)?;
        c.check_directions()
            .map_err(|e| format!("combiner {}: {e:?}", c.release))?;
        if kind.has_safety_floor() {
            c.check_safety_floor()
                .map_err(|e| format!("combiner {}: {e:?}", c.release))?;
        }
        verdicts.insert(*kind, c);
    }
    let mut policy = DirectivePolicy::default();
    if !a.folders.is_empty() {
        policy.allowed_folders = a.folders.clone();
    }
    let tier1 = match (&a.sidecar, &a.calibration) {
        (Some(p), Some(c)) => {
            let d =
                SidecarDecider::connect(p.clone(), Duration::from_millis(a.sidecar_timeout_ms))?;
            let cf: CalibrationFile = load_json(c)?;
            let mut cal = Calibration::new(ModelRelease(cf.release));
            for (q, t) in cf.temperatures {
                cal.set(QuestionId(q), t);
            }
            Some((d, cal))
        }
        _ => None,
    };
    let combiner = a.combiner.as_ref().map(load_json::<Combiner>).transpose()?;
    if let Some(c) = &combiner {
        c.check_directions()
            .map_err(|e| format!("combiner {}: {e:?}", c.release))?;
    }
    let records = a.records.as_deref().map(api::Records::open).transpose()?;
    let tier2 = match (&a.tier2, &a.tier2_calibration) {
        (Some(p), Some(c)) => {
            let d = SidecarDecider::connect(p.clone(), Duration::from_millis(a.tier2_timeout_ms))?;
            let cf: CalibrationFile = load_json(c)?;
            let mut cal = Calibration::new(ModelRelease(cf.release));
            for (q, t) in cf.temperatures {
                cal.set(QuestionId(q), t);
            }
            eprintln!("firstreadd: tier 2 {}", d.manifest.release.0);
            Some((d, cal))
        }
        _ => None,
    };
    let (late_tx, late_rx) = if tier2.is_some() {
        let (tx, rx) = std::sync::mpsc::sync_channel(LATE_QUEUE);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let dns: Option<Box<dyn Dns>> = if !a.dns_recorded.is_empty() {
        let mut all = RecordedDns::new();
        for p in &a.dns_recorded {
            let r = RecordedDns::load(p).map_err(|e| format!("{}: {e}", p.display()))?;
            eprintln!(
                "firstreadd: {} recorded DNS answers from {}",
                r.len(),
                p.display()
            );
            all.extend(r);
        }
        if let Some((from, to)) = a.dns_window {
            all.set_window(from, to);
        }
        Some(Box::new(all))
    } else if a.dns_live {
        let servers = if a.dns_servers.is_empty() {
            LiveDns::servers_from_resolv_conf(std::path::Path::new("/etc/resolv.conf"))
                .map_err(|e| format!("/etc/resolv.conf: {e}"))?
        } else {
            a.dns_servers.clone()
        };
        if servers.is_empty() {
            return Err("--dns-live: no resolver configured".into());
        }
        eprintln!("firstreadd: live DNS via {servers:?}");
        Some(Box::new(LiveDns::new(
            servers,
            Duration::from_millis(a.dns_timeout_ms),
        )))
    } else {
        None
    };
    let mac_key_bytes = a.mac_key.as_bytes().to_vec();
    let state = Arc::new(State {
        cfg: Config {
            deployment: a.deployment,
            mac_key: mac_key_bytes.clone(),
            trusted_authserv_ids: a.trusted,
            questions,
            verdicts,
            stamp: firstread_pipeline::StampConfig {
                actions,
                reasons,
                language: a.language.clone(),
                detail_headers: a.detail_headers,
            },
            render_max_chars: a.render_max_chars,
            data_class: a.data_class,
            policy,
        },
        tier1,
        combiner,
        records,
        shadow: a.shadow,
        tier2,
        tier2_from: a.tier2_from,
        rules: a.rules.clone(),
        late: late_tx,
        hook_c: a.hook_c.as_ref().map(|d| late::HookC {
            doveadm: d.clone(),
            folders: a.hook_c_folders.clone(),
        }),
        dns,
        dns_budget: Duration::from_millis(a.dns_budget_ms),
        clock_message: a.clock_message,
        memory: match &a.memory {
            Some(dir) => {
                // The memory key is derived from the deployment key, never the key itself.
                let key = Hasher::new(mac_key_bytes.as_slice()).id("derive", "firstread-memory/1");
                let hasher = Hasher::new(key.as_bytes());
                Some(Hub {
                    store: FileStore::new(dir, hasher.clone())
                        .map_err(|e| format!("{}: {e}", dir.display()))?,
                    hasher,
                    boxes: Mutex::new(HashMap::new()),
                    own_actors: a.own_actors.clone(),
                })
            }
            None => None,
        },
    });
    if a.shadow {
        eprintln!("firstreadd: shadow mode: decisions are recorded, not applied");
    }
    if let Some(rx) = late_rx {
        let st = Arc::clone(&state);
        std::thread::spawn(move || late_worker(&st, &rx));
    }
    if let Some(path) = &a.api_socket {
        let _ = std::fs::remove_file(path);
        let l = UnixListener::bind(path).map_err(|e| format!("{}: {e}", path.display()))?;
        eprintln!("firstreadd: API on {}", path.display());
        let st = Arc::clone(&state);
        std::thread::spawn(move || {
            for conn in l.incoming() {
                match conn {
                    Ok(s) => {
                        if let Err(e) = api::handle(st.records.as_ref(), s) {
                            eprintln!("firstreadd: api: {e}");
                        }
                    }
                    Err(e) => eprintln!("firstreadd: api accept: {e}"),
                }
            }
        });
    }
    if let Some(fs) = &a.feedback_socket {
        let _ = std::fs::remove_file(fs);
        let fl = UnixListener::bind(fs).map_err(|e| format!("{}: {e}", fs.display()))?;
        eprintln!("firstreadd: feedback on {}", fs.display());
        let st = Arc::clone(&state);
        std::thread::spawn(move || {
            for conn in fl.incoming() {
                match conn {
                    Ok(s) => {
                        if let Some(hub) = &st.memory
                            && let Err(e) = handle_feedback(hub, s)
                        {
                            eprintln!("firstreadd: feedback: {e}");
                        }
                    }
                    Err(e) => eprintln!("firstreadd: feedback accept: {e}"),
                }
            }
        });
    }
    let _ = std::fs::remove_file(&a.socket);
    let listener =
        UnixListener::bind(&a.socket).map_err(|e| format!("{}: {e}", a.socket.display()))?;
    eprintln!("firstreadd: listening on {}", a.socket.display());
    for conn in listener.incoming() {
        match conn {
            Ok(s) => {
                let st = Arc::clone(&state);
                std::thread::spawn(move || {
                    if let Err(e) = handle(&st, s) {
                        eprintln!("firstreadd: {e}");
                    }
                });
            }
            Err(e) => eprintln!("firstreadd: accept: {e}"),
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("firstreadd: {e}");
            ExitCode::FAILURE
        }
    }
}
