//! `firstreadd`: the daemon.
//!
//! Implemented: the delivery socket for `firstread-filter` (frames of `firstread-core::wire`),
//! the pipeline of `firstread-pipeline` per message, a tier-1 provider reached over a local
//! socket (a [`Decider`] with locality `LocalService`), one JSON record per decision appended
//! to a records file, and with `--memory` the mailbox memory of `firstread-graph`: read on every
//! delivery, updated after the reply is sent, and taught by the mailbox owner's actions through
//! the feedback socket (`firstread feedback`, called by Dovecot IMAPSieve scripts, hook D).
//!
//! Still to build (docs/01-architecture.md): the async queue for late results and tier 2, hook C
//! updates, push-notification events (hook G), the HTTP API, load shedding and metrics.
//!
//! Configuration is by flags; `firstreadd --help` lists them.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use firstread_core::context::DeliveryContext;
use firstread_core::decision::{ModelRelease, Question, QuestionId, QuestionKind};
use firstread_core::directive::{Directive, DirectivePolicy};
use firstread_core::provider::{
    Calibration, DataClass, Decider, Locality, Manifest, ProviderError, Rendered,
};
use firstread_core::wire::{
    MAX_JSON_FRAME, Reply, Request, WireDirective, read_frame, write_frame,
};
use firstread_graph::{
    Applied, FileStore, Hasher, MailboxMemory, MemoryEvent, MemoryStore, MessageKeys, SentKeys,
};
use firstread_pipeline::{Combiner, Config, Memory, Tier1};
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
}

const HELP: &str = "firstreadd --socket PATH [--sidecar PATH --calibration FILE] [--combiner FILE]
  [--records FILE] [--deployment ID] [--mac-key KEY] [--trusted-authserv ID,ID]
  [--junk-threshold P] [--render-max-chars N] [--data-class public|synthetic|customer]
  [--sidecar-timeout-ms MS] [--shadow]
  [--memory DIR [--feedback-socket PATH] [--own-actors NAME,NAME]]

--shadow: decide and record every message as usual, but reply with an empty directive, so the
filter only removes foreign firstread headers and nothing is visible or filed
(docs/07-evaluation.md, rollout step 1). Records carry \"shadow\": true. Memory still learns.

--memory: per-mailbox memory (state and event log, keyed hashes only) in DIR; its facts
(mailbox.*) join the combiner's inputs. --feedback-socket: where `firstread feedback` reports the
mailbox owner's actions. --own-actors: actors whose feedback is firstread's own (for example the
account hook C uses); it is dropped, never learned.";

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
    if a.feedback_socket.is_some() && a.memory.is_none() {
        return Err("--feedback-socket needs --memory".into());
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
    fn supports(&self, q: &Question) -> bool {
        self.supported.contains(&q.id.0)
    }
    fn logits(
        &self,
        input: &Rendered<'_>,
        questions: &[Question],
    ) -> Result<Vec<Vec<f32>>, ProviderError> {
        let ids: Vec<&str> = questions.iter().map(|q| q.id.0.as_str()).collect();
        let req = serde_json::json!({"op": "logits", "text": input.text, "questions": ids});
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
    records: Option<Mutex<BufWriter<File>>>,
    shadow: bool,
    memory: Option<Hub>,
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
    let mut out = firstread_pipeline::run(
        &state.cfg,
        &message,
        &ctx,
        tier1,
        state.combiner.as_ref(),
        mem,
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
    if let Some(w) = &state.records {
        let mut rec = serde_json::to_value(&out.record).map_err(|e| e.to_string())?;
        if state.shadow {
            rec["shadow"] = serde_json::Value::Bool(true);
        }
        let line = serde_json::to_string(&rec).map_err(|e| e.to_string())?;
        let mut w = w.lock().map_err(|_| "records lock poisoned".to_string())?;
        writeln!(w, "{line}").map_err(|e| e.to_string())?;
        w.flush().map_err(|e| e.to_string())?;
    }
    let body = serde_json::to_vec(&reply).map_err(|e| e.to_string())?;
    let sent = write_frame(&mut s, &body).map_err(|e| format!("write reply: {e}"));
    // Learning happens after the reply: the delivery is a fact whatever the verdict was.
    if let (Some((hub, _)), Some(g), Some(keys)) = (&held, guard.as_mut(), out.keys) {
        let e = MemoryEvent::Delivered { at: now(), keys };
        hub.commit(&ctx.user, g, &e)?;
    }
    sent
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
    let questions = vec![Question {
        id: QuestionId("is_spam".into()),
        text: "Is this unwanted bulk mail, phishing or fraud?".into(),
        kind: QuestionKind::Noul,
    }];
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
    let records = a
        .records
        .as_ref()
        .map(|p| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .map(|f| Mutex::new(BufWriter::new(f)))
                .map_err(|e| format!("{}: {e}", p.display()))
        })
        .transpose()?;
    let mac_key_bytes = a.mac_key.as_bytes().to_vec();
    let state = Arc::new(State {
        cfg: Config {
            deployment: a.deployment,
            mac_key: mac_key_bytes.clone(),
            trusted_authserv_ids: a.trusted,
            junk_threshold: a.junk_threshold,
            questions,
            render_max_chars: a.render_max_chars,
            data_class: a.data_class,
            policy: DirectivePolicy::default(),
        },
        tier1,
        combiner,
        records,
        shadow: a.shadow,
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
