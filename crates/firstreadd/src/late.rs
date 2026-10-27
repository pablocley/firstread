//! Late results: tier 2 after delivery, and hook C to apply what it adds.
//!
//! A delivered message goes to tier 2 when its mailbox has rules written in words or a verdict
//! came close without holding ([`firstread_pipeline::wants_tier2`]). Jobs wait in a bounded
//! queue in memory only: the message bytes are never written anywhere by firstread, and a full
//! queue or a restart loses the late answer, never the mail (it was delivered already).
//!
//! Hook C applies a tier-2 update through `doveadm` (docs/12-interfaces.md section 4.5): it adds
//! keywords and moves a message only while it is still in INBOX and the owner has not marked it
//! `$NotJunk`, so it never undoes something the owner did. `doveadm` does not run IMAPSieve, so
//! these writes never come back as feedback; the account name hook C runs as belongs in
//! `--own-actors` as well.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use firstread_pipeline::{LateUpdate, Record};
use firstread_stamp::Rule;

/// One delivered message waiting for tier 2.
pub struct Job {
    /// The delivery's record.
    pub record: Record,
    /// The mailbox.
    pub user: String,
    /// The message as delivered (in memory only).
    pub message: Vec<u8>,
}

/// Where hook C writes: the `doveadm` binary and the real folder per folder key (the same names
/// the `sieve_after` script files into).
pub struct HookC {
    /// Path to `doveadm`.
    pub doveadm: PathBuf,
    /// Folder name per folder key, e.g. `junk` → `Junk`.
    pub folders: BTreeMap<String, String>,
}

/// The `doveadm` invocations (arguments after the binary) that apply an update to the message
/// with this Message-ID. Every value is its own argument: nothing passes through a shell.
pub fn hook_c_commands(
    hook: &HookC,
    user: &str,
    message_id: &str,
    u: &LateUpdate,
) -> Vec<Vec<String>> {
    let s = |x: &str| x.to_string();
    let mut out = Vec::new();
    if !u.add_keywords.is_empty() {
        out.push(vec![
            s("flags"),
            s("add"),
            s("-u"),
            s(user),
            u.add_keywords.join(" "),
            s("header"),
            s("Message-ID"),
            s(message_id),
        ]);
    }
    if let Some(name) = u.folder.as_ref().and_then(|k| hook.folders.get(k)) {
        out.push(vec![
            s("move"),
            s("-u"),
            s(user),
            s(name),
            s("mailbox"),
            s("INBOX"),
            s("header"),
            s("Message-ID"),
            s(message_id),
            s("NOT"),
            s("KEYWORD"),
            s("$NotJunk"),
        ]);
    }
    out
}

/// Run the commands; the first failure is returned, the rest still run.
pub fn apply(hook: &HookC, commands: &[Vec<String>]) -> Result<(), String> {
    let mut first_error = None;
    for args in commands {
        let r = Command::new(&hook.doveadm).args(args).output();
        let err = match r {
            Ok(o) if o.status.success() => None,
            Ok(o) => Some(format!(
                "doveadm {}: {}",
                args[0],
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => Some(format!("doveadm: {e}")),
        };
        if first_error.is_none() {
            first_error = err;
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// Whether a mailbox name may become a file name: no path separators, no leading dot.
fn safe_name(user: &str) -> bool {
    !user.is_empty() && !user.starts_with('.') && !user.contains(['/', '\\', '\0'])
}

/// The rules file of a mailbox, if its name is safe as a file name.
pub fn rules_path(dir: &Path, user: &str) -> Option<PathBuf> {
    safe_name(user).then(|| dir.join(format!("{}.json", user.to_ascii_lowercase())))
}

/// A mailbox's rules; none when it has no file. A file that does not parse is an error the caller
/// records, and the message is decided without rules.
pub fn load_rules(dir: &Path, user: &str) -> Result<Vec<Rule>, String> {
    let Some(p) = rules_path(dir, user) else {
        return Ok(vec![]);
    };
    match std::fs::read_to_string(&p) {
        Ok(s) => firstread_stamp::parse_rules(&s).map_err(|e| format!("{}: {e}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(kws: &[&str], folder: Option<&str>) -> LateUpdate {
        let rec: Record = serde_json::from_value(serde_json::json!({
            "schema": "firstread.verdict/2", "id": "st_1", "deployment": "t", "idempotency_key": "k",
            "input": {"message_id_hash": null, "size": 1, "truncated": false, "recipient": "a@x",
                      "text_sha256": null, "parse_failed": false},
            "auth": {}, "features": {}, "decisions": [], "p_junk": null,
            "directive": {"remove": [], "add": [], "subject_prefix": null, "keywords": [], "folder": null},
            "provenance": {"tiers": [0], "models": [], "combiner": null, "junk_threshold": 0.99,
                           "timings_us": {}, "errors": []}
        }))
        .unwrap();
        LateUpdate {
            record: rec,
            add_keywords: kws.iter().map(|k| (*k).to_string()).collect(),
            folder: folder.map(str::to_string),
        }
    }

    #[test]
    fn hook_c_adds_keywords_anywhere_and_moves_only_from_inbox() {
        let hook = HookC {
            doveadm: "/usr/bin/doveadm".into(),
            folders: [("junk".to_string(), "Junk".to_string())]
                .into_iter()
                .collect(),
        };
        let c = hook_c_commands(
            &hook,
            "alice",
            "<m1@x.example> ALL",
            &update(&["$Phishing", "fr-bank"], Some("junk")),
        );
        assert_eq!(
            c[0],
            [
                "flags",
                "add",
                "-u",
                "alice",
                "$Phishing fr-bank",
                "header",
                "Message-ID",
                "<m1@x.example> ALL"
            ]
        );
        assert_eq!(
            &c[1][..6],
            ["move", "-u", "alice", "Junk", "mailbox", "INBOX"]
        );
        assert_eq!(
            &c[1][9..],
            ["NOT", "KEYWORD", "$NotJunk"],
            "never against the owner's own judgement"
        );
        assert_eq!(
            c[1][8], "<m1@x.example> ALL",
            "a hostile Message-ID stays one argument"
        );
        assert!(
            hook_c_commands(&hook, "alice", "<m>", &update(&[], Some("later"))).is_empty(),
            "no folder name, no move"
        );
        assert!(hook_c_commands(&hook, "alice", "<m>", &update(&[], None)).is_empty());
    }

    #[test]
    fn rules_files_are_found_by_safe_names_only() {
        let dir = std::env::temp_dir().join(format!("firstread-rules-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("alice@x.example.json"),
            r#"{"rules":[{"id":"r","text":"t","tag":"t"}]}"#,
        )
        .unwrap();
        assert_eq!(load_rules(&dir, "Alice@x.example").unwrap().len(), 1);
        assert!(load_rules(&dir, "nobody@x.example").unwrap().is_empty());
        assert!(rules_path(&dir, "../etc/passwd").is_none());
        assert!(rules_path(&dir, ".hidden").is_none());
        std::fs::write(dir.join("bad@x.example.json"), "{").unwrap();
        assert!(load_rules(&dir, "bad@x.example").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
