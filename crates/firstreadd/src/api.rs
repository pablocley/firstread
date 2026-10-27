//! Records and the read-only record API.
//!
//! Every record (a delivery, and later a tier-2 update of the same id) is one JSON line in the
//! records file. [`Records`] keeps the offset of the latest line per stamp id, so the API reads
//! one line per request. ponytail: the index is in memory, one entry per stamp id; a store with
//! retention replaces it when volumes need it (docs/11-scale.md).
//!
//! The API is HTTP/1.1 on a local Unix socket, for the webmail backend and the API front end that
//! authenticates the mailbox owner (docs/03-client-contract.md, API): this socket trusts its
//! caller like the filter socket does. It answers `GET /v1/messages/{id}` with the record, and
//! only when the `X-Firstread-User` header names the mailbox the record belongs to.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

/// The records file and the offset of each stamp id's latest record.
pub struct Records {
    path: PathBuf,
    file: Mutex<BufWriter<File>>,
    index: Mutex<HashMap<String, u64>>,
}

impl Records {
    /// Open (or create) the records file and index what is already there.
    pub fn open(path: &Path) -> Result<Self, String> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let mut index = HashMap::new();
        let mut r =
            BufReader::new(File::open(path).map_err(|e| format!("{}: {e}", path.display()))?);
        let mut at = 0u64;
        let mut line = String::new();
        loop {
            line.clear();
            let n = r.read_line(&mut line).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            if let Some(id) = serde_json::from_str::<serde_json::Value>(&line)
                .ok()
                .and_then(|v| v["id"].as_str().map(str::to_string))
            {
                index.insert(id, at);
            }
            at += n as u64;
        }
        Ok(Self {
            path: path.to_path_buf(),
            file: Mutex::new(BufWriter::new(file)),
            index: Mutex::new(index),
        })
    }

    /// Append one record; it becomes the latest for its id.
    pub fn append(&self, rec: &serde_json::Value) -> Result<(), String> {
        let line = serde_json::to_string(rec).map_err(|e| e.to_string())?;
        let mut w = self.file.lock().map_err(|_| "records lock poisoned")?;
        w.flush().map_err(|e| e.to_string())?;
        let at = w.get_ref().metadata().map_err(|e| e.to_string())?.len();
        writeln!(w, "{line}").map_err(|e| e.to_string())?;
        w.flush().map_err(|e| e.to_string())?;
        if let Some(id) = rec["id"].as_str() {
            self.index
                .lock()
                .map_err(|_| "records index poisoned")?
                .insert(id.to_string(), at);
        }
        Ok(())
    }

    /// The latest record of a stamp id.
    pub fn get(&self, id: &str) -> Result<Option<serde_json::Value>, String> {
        let Some(at) = self
            .index
            .lock()
            .map_err(|_| "records index poisoned")?
            .get(id)
            .copied()
        else {
            return Ok(None);
        };
        let mut f = File::open(&self.path).map_err(|e| e.to_string())?;
        f.seek(SeekFrom::Start(at)).map_err(|e| e.to_string())?;
        let mut line = String::new();
        BufReader::new(f)
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        serde_json::from_str(&line)
            .map(Some)
            .map_err(|e| e.to_string())
    }
}

/// Largest request head the API reads.
const MAX_HEAD: usize = 8192;

/// One parsed request: method, path and the `X-Firstread-User` header.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    method: String,
    path: String,
    user: Option<String>,
}

/// Parse a request head (everything up to the blank line).
pub fn parse_request(head: &str) -> Option<Request> {
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_string();
    let path = first.next()?.to_string();
    if !first.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let user = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(n, _)| n.trim().eq_ignore_ascii_case("x-firstread-user"))
        .map(|(_, v)| v.trim().to_string());
    Some(Request { method, path, user })
}

/// The status and JSON body for a request.
pub fn respond(records: Option<&Records>, req: &Request) -> (u16, serde_json::Value) {
    let err = |code, msg: &str| (code, serde_json::json!({ "error": msg }));
    if req.method != "GET" {
        return err(405, "read-only API: GET only");
    }
    if req.path == "/v1/health" {
        return (200, serde_json::json!({ "ok": true }));
    }
    let Some(id) = req.path.strip_prefix("/v1/messages/") else {
        return err(404, "unknown path");
    };
    let Some(user) = req.user.as_deref().filter(|u| !u.is_empty()) else {
        return err(401, "X-Firstread-User is required");
    };
    let Some(records) = records else {
        return err(503, "no records file configured");
    };
    match records.get(id) {
        // Another mailbox's record is answered exactly like a missing one.
        Ok(Some(rec))
            if rec["input"]["user"]
                .as_str()
                .is_some_and(|u| u.eq_ignore_ascii_case(user)) =>
        {
            (200, rec)
        }
        Ok(_) => err(404, "no such message for this user"),
        Err(e) => err(500, &e),
    }
}

/// Serve one connection.
pub fn handle(records: Option<&Records>, mut s: UnixStream) -> Result<(), String> {
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 || head.len() + n > MAX_HEAD {
            break;
        }
        head.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&head);
    let (code, body) = match parse_request(&text) {
        Some(r) => respond(records, &r),
        None => (400, serde_json::json!({ "error": "bad request" })),
    };
    let body = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    write!(
        s,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .and_then(|()| s.write_all(&body))
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_return_the_latest_line_per_id_and_only_to_its_user() {
        let dir = std::env::temp_dir().join(format!("firstread-api-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("records.jsonl");
        let _ = std::fs::remove_file(&path);
        let r = Records::open(&path).unwrap();
        let rec = |tiers: &str| serde_json::json!({"id": "st_1", "input": {"user": "Alice@x.example"}, "tiers": tiers});
        r.append(&rec("0,1")).unwrap();
        r.append(&serde_json::json!({"id": "st_2", "input": {"user": "bob@x.example"}}))
            .unwrap();
        r.append(&rec("0,1,2")).unwrap();
        // Reopened from disk: the same answers.
        let r = Records::open(&path).unwrap();
        let get = |path: &str, user: Option<&str>| {
            respond(
                Some(&r),
                &Request {
                    method: "GET".into(),
                    path: path.into(),
                    user: user.map(str::to_string),
                },
            )
        };
        let (code, body) = get("/v1/messages/st_1", Some("alice@x.example"));
        assert_eq!((code, body["tiers"].as_str()), (200, Some("0,1,2")));
        assert_eq!(
            get("/v1/messages/st_1", Some("bob@x.example")).0,
            404,
            "not bob's"
        );
        assert_eq!(get("/v1/messages/st_1", None).0, 401);
        assert_eq!(get("/v1/messages/st_9", Some("alice@x.example")).0, 404);
        assert_eq!(get("/v1/health", None).0, 200);
        let post = Request {
            method: "POST".into(),
            path: "/v1/messages/st_1".into(),
            user: Some("alice@x.example".into()),
        };
        assert_eq!(respond(Some(&r), &post).0, 405);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn request_heads_parse() {
        let r = parse_request(
            "GET /v1/messages/st_1 HTTP/1.1\r\nHost: x\r\nx-firstread-user: a@b\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            r,
            Request {
                method: "GET".into(),
                path: "/v1/messages/st_1".into(),
                user: Some("a@b".into())
            }
        );
        assert!(parse_request("GET /\r\n\r\n").is_none());
        assert!(parse_request("").is_none());
    }
}
