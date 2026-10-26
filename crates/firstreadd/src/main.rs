//! `firstreadd`: the daemon.
//!
//! Implemented: the delivery socket for `firstread-filter` (frames of `firstread-core::wire`),
//! the pipeline of `firstread-pipeline` per message, a tier-1 provider reached over a local
//! socket (a [`Decider`] with locality `LocalService`), and one JSON record per decision appended
//! to a records file.
//!
//! Still to build (docs/01-architecture.md): the async queue for late results and tier 2, hook C
//! updates, feedback ingestion, the HTTP API, load shedding and metrics.
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
use firstread_pipeline::{Combiner, Config, Tier1};
use serde::Deserialize;

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
}

const HELP: &str = "firstreadd --socket PATH [--sidecar PATH --calibration FILE] [--combiner FILE]
  [--records FILE] [--deployment ID] [--mac-key KEY] [--trusted-authserv ID,ID]
  [--junk-threshold P] [--render-max-chars N] [--data-class public|synthetic|customer]
  [--sidecar-timeout-ms MS] [--shadow]

--shadow: decide and record every message as usual, but reply with an empty directive, so the
filter only removes foreign firstread headers and nothing is visible or filed
(docs/07-evaluation.md, rollout step 1). Records carry \"shadow\": true.";

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

struct State {
    cfg: Config,
    tier1: Option<(SidecarDecider, Calibration)>,
    combiner: Option<Combiner>,
    records: Option<Mutex<BufWriter<File>>>,
    shadow: bool,
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
    let out = firstread_pipeline::run(&state.cfg, &message, &ctx, tier1, state.combiner.as_ref());
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
    write_frame(&mut s, &body).map_err(|e| format!("write reply: {e}"))?;
    Ok(())
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
    let state = Arc::new(State {
        cfg: Config {
            deployment: a.deployment,
            mac_key: a.mac_key.into_bytes(),
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
    });
    if a.shadow {
        eprintln!("firstreadd: shadow mode: decisions are recorded, not applied");
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
