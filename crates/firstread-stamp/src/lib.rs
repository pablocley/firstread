//! From calibrated verdicts and facts to what a client sees (docs/03-client-contract.md):
//! keywords, a folder key, the detail headers (`X-Firstread-Scores`, `-Tags`, `-Sender`,
//! `-Reasons`) and the verdicts of the record.
//!
//! Everything a person could want to change is a data file (`data/`): the questions
//! (`questions.json`), what each verdict does at which threshold (`actions.json`), and which
//! input is shown as which reason in which language (`reasons.json`). Nothing here reads message
//! text: reasons are fixed texts chosen by key, so nothing a sender wrote reaches a header
//! through this crate, and no extracted personal data (IBANs, amounts, codes) is ever written.
//!
//! Incoming `X-Firstread-*` headers are removed by the filter on every path, not here; the
//! folder and keyword headers are rendered from the validated directive by
//! [`firstread_core::directive::Directive::derived_headers`].

use std::collections::{BTreeMap, BTreeSet};

use firstread_core::decision::{Decision, Question, QuestionId, QuestionKind};
use firstread_core::directive::{
    AddHeader, DirectivePolicy, FolderKey, HeaderName, HeaderValue, ImapKeyword,
};
use firstread_core::verdict::VerdictKind;
use serde::{Deserialize, Serialize};

const QUESTIONS: &str = include_str!("../data/questions.json");
const ACTIONS: &str = include_str!("../data/actions.json");
const REASONS: &str = include_str!("../data/reasons.json");

#[derive(Deserialize)]
struct QuestionsFile {
    questions: Vec<QuestionEntry>,
}

#[derive(Deserialize)]
struct QuestionEntry {
    id: String,
    kind: String,
    text: String,
    #[serde(default)]
    options: Vec<String>,
    #[serde(default)]
    levels: Vec<String>,
}

/// Parse a question registry (the format of `data/questions.json`).
pub fn parse_questions(json: &str) -> Result<Vec<Question>, String> {
    let f: QuestionsFile = serde_json::from_str(json).map_err(|e| format!("questions: {e}"))?;
    let mut seen = BTreeSet::new();
    f.questions
        .into_iter()
        .map(|q| {
            if !seen.insert(q.id.clone()) {
                return Err(format!("question {} twice", q.id));
            }
            let kind = match q.kind.as_str() {
                "noul" => QuestionKind::Noul,
                "choice" if q.options.len() >= 2 => QuestionKind::Choice { options: q.options },
                "score" if q.levels.len() >= 2 => QuestionKind::Score { levels: q.levels },
                other => {
                    return Err(format!(
                        "question {}: bad kind {other} or too few outcomes",
                        q.id
                    ));
                }
            };
            Ok(Question {
                id: QuestionId(q.id),
                text: q.text,
                kind,
            })
        })
        .collect()
}

/// The questions of `data/questions.json`.
pub fn questions() -> Vec<Question> {
    parse_questions(QUESTIONS).expect("data/questions.json is checked by a test")
}

/// The combiner inputs a calibrated decision adds: `head.<q>.logit` for a `noul` question,
/// `head.<q>.<option>` (the probability) for a `choice`, and `head.<q>.expected` (the expected
/// level) for a `score`.
pub fn decision_inputs(q: &Question, d: &Decision) -> Vec<(String, f64)> {
    let p = d.distribution.probabilities();
    match &q.kind {
        QuestionKind::Noul => d
            .p_true()
            .map(|pt| {
                let pt = f64::from(pt).clamp(1e-6, 1.0 - 1e-6);
                vec![(format!("head.{}.logit", q.id.0), (pt / (1.0 - pt)).ln())]
            })
            .unwrap_or_default(),
        QuestionKind::Choice { options } => options
            .iter()
            .zip(p)
            .map(|(o, p)| (format!("head.{}.{o}", q.id.0), f64::from(*p)))
            .collect(),
        QuestionKind::Score { .. } => vec![(
            format!("head.{}.expected", q.id.0),
            f64::from(d.distribution.expected_level()),
        )],
    }
}

#[derive(Deserialize)]
struct ActionsFile {
    verdicts: BTreeMap<String, ActionEntry>,
    tags: TagsEntry,
    fact_keywords: Vec<String>,
    reasons_max: usize,
    rule_threshold: f64,
}

#[derive(Deserialize)]
struct ActionEntry {
    keyword: Option<f64>,
    folder: Option<f64>,
    #[serde(default)]
    keywords: Vec<String>,
    folder_key: Option<String>,
}

#[derive(Deserialize)]
struct TagsEntry {
    threshold: f64,
    questions: BTreeMap<String, String>,
    #[serde(default)]
    choices: BTreeMap<String, BTreeMap<String, String>>,
}

/// What one verdict does.
#[derive(Debug, Clone)]
pub struct VerdictAction {
    /// P at or above which its keywords are set.
    pub keyword: Option<f64>,
    /// P at or above which the message is filed into `folder_key`.
    pub folder: Option<f64>,
    /// Keywords it sets.
    pub keywords: Vec<ImapKeyword>,
    /// The folder key it files into.
    pub folder_key: Option<FolderKey>,
}

impl VerdictAction {
    /// The lowest threshold at which the verdict does anything: from there on it holds.
    pub fn holds_at(&self) -> Option<f64> {
        match (self.keyword, self.folder) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

/// The keywords set from deterministic facts rather than a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FactKeyword {
    HasAttachment,
    HasNoAttachment,
    CanUnsubscribe,
    Autosent,
    IsTrusted,
    FirstContact,
}

impl FactKeyword {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "$HasAttachment" => Self::HasAttachment,
            "$HasNoAttachment" => Self::HasNoAttachment,
            "$CanUnsubscribe" => Self::CanUnsubscribe,
            "$Autosent" => Self::Autosent,
            "$IsTrusted" => Self::IsTrusted,
            "fr-first-contact" => Self::FirstContact,
            _ => return None,
        })
    }

    fn keyword(self) -> &'static str {
        match self {
            Self::HasAttachment => "$HasAttachment",
            Self::HasNoAttachment => "$HasNoAttachment",
            Self::CanUnsubscribe => "$CanUnsubscribe",
            Self::Autosent => "$Autosent",
            Self::IsTrusted => "$IsTrusted",
            Self::FirstContact => "fr-first-contact",
        }
    }
}

/// The action table of `data/actions.json`.
#[derive(Debug, Clone)]
pub struct Actions {
    /// Per verdict.
    pub verdicts: BTreeMap<VerdictKind, VerdictAction>,
    tag_threshold: f64,
    tag_questions: BTreeMap<String, String>,
    tag_choices: BTreeMap<String, BTreeMap<String, String>>,
    fact_keywords: Vec<FactKeyword>,
    reasons_max: usize,
    rule_threshold: f64,
}

/// Whether a string is a valid tag or rule id: 1 to 32 of `a`-`z`, `0`-`9`, `-`.
pub fn tag_ok(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 32
        && t.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Actions {
    /// Parse an action table (the format of `data/actions.json`). Every keyword, folder key and
    /// tag is validated here, so a bad data file fails at start-up, not on a message.
    pub fn parse(json: &str) -> Result<Self, String> {
        let f: ActionsFile = serde_json::from_str(json).map_err(|e| format!("actions: {e}"))?;
        let mut verdicts = BTreeMap::new();
        for (name, a) in f.verdicts {
            let kind =
                VerdictKind::parse(&name).ok_or_else(|| format!("unknown verdict {name}"))?;
            for t in [a.keyword, a.folder].into_iter().flatten() {
                if !(0.0..=1.0).contains(&t) {
                    return Err(format!("{name}: threshold {t} outside 0..1"));
                }
            }
            if a.folder.is_some() != a.folder_key.is_some() {
                return Err(format!("{name}: folder and folder_key go together"));
            }
            let keywords = a
                .keywords
                .iter()
                .map(|k| ImapKeyword::new(k).map_err(|e| format!("{name}: {e}")))
                .collect::<Result<_, _>>()?;
            let folder_key = a
                .folder_key
                .map(|k| FolderKey::new(&k).map_err(|e| format!("{name}: {e}")))
                .transpose()?;
            verdicts.insert(
                kind,
                VerdictAction {
                    keyword: a.keyword,
                    folder: a.folder,
                    keywords,
                    folder_key,
                },
            );
        }
        for t in f
            .tags
            .questions
            .values()
            .chain(f.tags.choices.values().flat_map(BTreeMap::values))
        {
            if !tag_ok(t) {
                return Err(format!("bad tag {t}"));
            }
        }
        let fact_keywords = f
            .fact_keywords
            .iter()
            .map(|k| FactKeyword::parse(k).ok_or_else(|| format!("unknown fact keyword {k}")))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            verdicts,
            tag_threshold: f.tags.threshold,
            tag_questions: f.tags.questions,
            tag_choices: f.tags.choices,
            fact_keywords,
            reasons_max: f.reasons_max,
            rule_threshold: f.rule_threshold,
        })
    }

    /// Replace junk's thresholds with the deployment's cost-derived one (λ, docs/07-evaluation.md).
    pub fn with_junk_threshold(mut self, p: f64) -> Self {
        if let Some(a) = self.verdicts.get_mut(&VerdictKind::Junk) {
            a.keyword = Some(p);
            if a.folder.is_some() {
                a.folder = Some(p);
            }
        }
        self
    }
}

impl Default for Actions {
    fn default() -> Self {
        Self::parse(ACTIONS).expect("data/actions.json is checked by a test")
    }
}

#[derive(Deserialize)]
struct ReasonsFile {
    inputs: BTreeMap<String, String>,
    texts: BTreeMap<String, BTreeMap<String, String>>,
}

/// Reason keys per input, and texts per reason and language (`data/reasons.json`).
#[derive(Debug, Clone)]
pub struct Reasons {
    inputs: BTreeMap<String, String>,
    texts: BTreeMap<String, BTreeMap<String, String>>,
}

impl Reasons {
    /// Parse a reason table; every reason an input names must have a text in `en`.
    pub fn parse(json: &str) -> Result<Self, String> {
        let f: ReasonsFile = serde_json::from_str(json).map_err(|e| format!("reasons: {e}"))?;
        for (input, key) in &f.inputs {
            if !f.texts.get(key).is_some_and(|t| t.contains_key("en")) {
                return Err(format!("{input}: reason {key} has no English text"));
            }
        }
        Ok(Self {
            inputs: f.inputs,
            texts: f.texts,
        })
    }

    /// The reason an input stands for, if it is shown at all.
    pub fn key(&self, input: &str) -> Option<&str> {
        self.inputs.get(input).map(String::as_str)
    }

    /// The text of a reason in a language, English when that language has none.
    pub fn text(&self, key: &str, language: &str) -> Option<&str> {
        let t = self.texts.get(key)?;
        t.get(language).or_else(|| t.get("en")).map(String::as_str)
    }
}

impl Default for Reasons {
    fn default() -> Self {
        Self::parse(REASONS).expect("data/reasons.json is checked by a test")
    }
}

/// A rule a mailbox owner wrote in words: "tag mails where a customer asks for a refund as
/// retour". It is asked as the `noul` question `rule:<id>` (tier 2) and sets `fr-<tag>`. The text
/// only ever reaches the decision model, never a header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Stable id (a tag-like token).
    pub id: String,
    /// The rule as the owner wrote it.
    pub text: String,
    /// The tag it sets.
    pub tag: String,
}

#[derive(Deserialize)]
struct RulesFile {
    rules: Vec<Rule>,
}

/// Longest rule text, in characters.
pub const MAX_RULE_TEXT: usize = 500;
/// Most rules per mailbox.
pub const MAX_RULES: usize = 50;

impl Rule {
    /// The question this rule is asked as.
    pub fn question(&self) -> Question {
        Question {
            id: QuestionId(format!(
                "{}{}",
                firstread_core::provider::RULE_PREFIX,
                self.id
            )),
            text: self.text.clone(),
            kind: QuestionKind::Noul,
        }
    }
}

/// Parse a mailbox's rules (`{"rules": [{"id", "text", "tag"}]}`), validating every id and tag.
pub fn parse_rules(json: &str) -> Result<Vec<Rule>, String> {
    let f: RulesFile = serde_json::from_str(json).map_err(|e| format!("rules: {e}"))?;
    if f.rules.len() > MAX_RULES {
        return Err(format!("more than {MAX_RULES} rules"));
    }
    let mut seen = BTreeSet::new();
    for r in &f.rules {
        if !tag_ok(&r.id) || !tag_ok(&r.tag) || !seen.insert(r.id.clone()) {
            return Err(format!("rule {}: bad or repeated id, or bad tag", r.id));
        }
        if r.text.trim().is_empty() || r.text.chars().count() > MAX_RULE_TEXT {
            return Err(format!(
                "rule {}: empty or longer than {MAX_RULE_TEXT}",
                r.id
            ));
        }
    }
    Ok(f.rules)
}

/// One verdict as a combiner scored it: P and what each input contributed (weight × value).
#[derive(Debug, Clone)]
pub struct Scored {
    /// Which verdict.
    pub kind: VerdictKind,
    /// Calibrated probability.
    pub p: f64,
    /// Contribution per input name.
    pub contributions: Vec<(String, f64)>,
}

/// One verdict in the record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordVerdict {
    /// Verdict name.
    pub kind: String,
    /// Calibrated probability.
    pub p: f64,
    /// Whether it reached the threshold at which it acts.
    pub holds: bool,
    /// Reason keys, most important first.
    pub reasons: Vec<String>,
}

/// How the sender relates to this mailbox, from mailbox memory (docs/02-signals.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// No mail from or to this sender or its domain before.
    FirstContact,
    /// Mail came from them before; the owner never wrote to them.
    Seen,
    /// The owner wrote to this verified sender.
    WroteTo,
    /// The owner wrote to them and this is a reply to the owner's mail.
    Correspondent,
}

impl Relation {
    /// Name in `X-Firstread-Sender` and the record.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FirstContact => "first-contact",
            Self::Seen => "seen",
            Self::WroteTo => "wrote-to",
            Self::Correspondent => "correspondent",
        }
    }

    /// From the `mailbox.*` facts; `None` without memory.
    pub fn from_facts(f: &BTreeMap<String, f64>) -> Option<Self> {
        let on = |k: &str| f.get(k).copied().unwrap_or(0.0) > 0.0;
        if !f.contains_key("mailbox.first_contact") {
            return None;
        }
        Some(if on("mailbox.first_contact") {
            Self::FirstContact
        } else if on("mailbox.wrote_to_sender") && on("mailbox.reply_to_sent") {
            Self::Correspondent
        } else if on("mailbox.wrote_to_sender") {
            Self::WroteTo
        } else {
            Self::Seen
        })
    }
}

/// Settings of the stamp.
#[derive(Debug, Clone)]
pub struct StampConfig {
    /// The action table.
    pub actions: Actions,
    /// Reason keys and texts.
    pub reasons: Reasons,
    /// Language of the reason texts (BCP 47 primary tag, e.g. `nl`).
    pub language: String,
    /// Whether the detail headers are written; switchable per platform.
    pub detail_headers: bool,
}

impl Default for StampConfig {
    fn default() -> Self {
        Self {
            actions: Actions::default(),
            reasons: Reasons::default(),
            language: "en".into(),
            detail_headers: true,
        }
    }
}

/// What the stamp is computed from.
pub struct Facts<'a> {
    /// Every combiner input of the message (tier-0 facts, `mailbox.*`, `head.*`).
    pub inputs: &'a BTreeMap<String, f64>,
    /// The verdicts that were scored, in any order.
    pub scored: &'a [Scored],
    /// Whether the sender's identity is verified (aligned DKIM or trusted DMARC pass).
    pub identity_verified: bool,
    /// The mailbox's rules; a rule whose question was answered at or above the rule threshold
    /// adds its tag.
    pub rules: &'a [Rule],
}

/// What the stamp adds to one message.
#[derive(Debug, Clone, Default)]
pub struct Output {
    /// The verdicts, in order of precedence.
    pub verdicts: Vec<RecordVerdict>,
    /// The first verdict that holds, with its P.
    pub top: Option<(VerdictKind, f64)>,
    /// Keywords to set, without duplicates.
    pub keywords: Vec<ImapKeyword>,
    /// The folder key, from the first holding verdict whose folder the mode allows.
    pub folder: Option<FolderKey>,
    /// Tags (firstread keywords without the `fr-` prefix).
    pub tags: Vec<String>,
    /// Sender relation, with memory on.
    pub relation: Option<Relation>,
    /// The detail headers, empty when switched off.
    pub detail: Vec<AddHeader>,
}

fn reasons_of(s: &Scored, reasons: &Reasons, max: usize) -> Vec<String> {
    let mut c: Vec<&(String, f64)> = s.contributions.iter().filter(|(_, v)| *v > 0.0).collect();
    c.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut out: Vec<String> = Vec::new();
    for (input, _) in c {
        if let Some(k) = reasons.key(input)
            && !out.iter().any(|o| o == k)
        {
            out.push(k.to_string());
        }
        if out.len() == max {
            break;
        }
    }
    out
}

fn header(policy: &DirectivePolicy, suffix: &str, value: HeaderValue) -> AddHeader {
    AddHeader {
        name: HeaderName::new(&format!("{}-{suffix}", policy.own_prefix))
            .expect("own prefix plus a fixed suffix is a valid name"),
        value,
    }
}

fn kw(k: &str) -> ImapKeyword {
    ImapKeyword::new(k).expect("fixed keyword")
}

/// Compute the stamp of one message.
pub fn stamp(cfg: &StampConfig, facts: &Facts<'_>, policy: &DirectivePolicy) -> Output {
    let on = |k: &str| facts.inputs.get(k).copied().unwrap_or(0.0) > 0.0;
    let mut scored: Vec<&Scored> = facts.scored.iter().collect();
    scored.sort_by_key(|s| s.kind);

    let mut out = Output::default();
    let mut keywords: Vec<ImapKeyword> = Vec::new();
    let push = |k: ImapKeyword, list: &mut Vec<ImapKeyword>| {
        if !list.contains(&k)
            && !policy
                .reserved_keywords
                .iter()
                .any(|r| r.as_str().eq_ignore_ascii_case(k.as_str()))
        {
            list.push(k);
        }
    };
    for s in &scored {
        let action = cfg.actions.verdicts.get(&s.kind);
        let holds = action
            .and_then(VerdictAction::holds_at)
            .is_some_and(|t| s.p >= t);
        out.verdicts.push(RecordVerdict {
            kind: s.kind.as_str().into(),
            p: s.p,
            holds,
            reasons: reasons_of(s, &cfg.reasons, cfg.actions.reasons_max),
        });
        let Some(a) = action else { continue };
        if holds && out.top.is_none() {
            out.top = Some((s.kind, s.p));
        }
        if a.keyword.is_some_and(|t| s.p >= t) {
            for k in &a.keywords {
                push(k.clone(), &mut keywords);
            }
        }
        if out.folder.is_none()
            && a.folder.is_some_and(|t| s.p >= t)
            && let Some(f) = &a.folder_key
            && policy.allowed_folders.contains(f)
        {
            out.folder = Some(f.clone());
        }
    }

    // Tags: topic questions and choice options above the tag threshold.
    let t = cfg.actions.tag_threshold;
    for (q, tag) in &cfg.actions.tag_questions {
        let x = facts.inputs.get(&format!("head.{q}.logit")).copied();
        if x.is_some_and(|z| 1.0 / (1.0 + (-z).exp()) >= t) {
            out.tags.push(tag.clone());
        }
    }
    for (q, options) in &cfg.actions.tag_choices {
        for (o, tag) in options {
            if facts
                .inputs
                .get(&format!("head.{q}.{o}"))
                .is_some_and(|p| *p >= t)
                && !out.tags.contains(tag)
            {
                out.tags.push(tag.clone());
            }
        }
    }
    for r in facts.rules {
        let z = facts.inputs.get(&format!(
            "head.{}{}.logit",
            firstread_core::provider::RULE_PREFIX,
            r.id
        ));
        if z.is_some_and(|z| 1.0 / (1.0 + (-z).exp()) >= cfg.actions.rule_threshold)
            && !out.tags.contains(&r.tag)
        {
            out.tags.push(r.tag.clone());
        }
    }
    for tag in &out.tags {
        push(kw(&format!("fr-{tag}")), &mut keywords);
    }

    out.relation = Relation::from_facts(facts.inputs);
    for f in &cfg.actions.fact_keywords {
        let set = match f {
            FactKeyword::HasAttachment => on("attach.count_log"),
            FactKeyword::HasNoAttachment => {
                facts.inputs.contains_key("attach.count_log") && !on("attach.count_log")
            }
            FactKeyword::CanUnsubscribe => on("list.unsubscribe"),
            FactKeyword::Autosent => on("meta.auto_submitted"),
            // An established, authenticated correspondent: never from an unverified message.
            FactKeyword::IsTrusted => facts.identity_verified && on("mailbox.wrote_to_sender"),
            FactKeyword::FirstContact => out.relation == Some(Relation::FirstContact),
        };
        if set {
            push(kw(f.keyword()), &mut keywords);
        }
    }
    out.keywords = keywords;

    if cfg.detail_headers {
        let scores: Vec<String> = out
            .verdicts
            .iter()
            .map(|v| format!("{}={:.2}", v.kind, v.p))
            .chain(
                facts
                    .inputs
                    .get("head.urgency.expected")
                    .map(|u| format!("urgency={u:.1}")),
            )
            .collect();
        if !scores.is_empty() {
            out.detail.push(header(
                policy,
                "Scores",
                HeaderValue::from_text(&scores.join("; ")),
            ));
        }
        if !out.tags.is_empty() {
            out.detail.push(header(
                policy,
                "Tags",
                HeaderValue::from_text(&out.tags.join(", ")),
            ));
        }
        let mut sender = Vec::new();
        if let Some(r) = out.relation {
            sender.push(format!("relation={}", r.as_str()));
        }
        sender.push(format!(
            "verified={}",
            if facts.identity_verified { "yes" } else { "no" }
        ));
        if on("mailbox.spoof_of_verified") {
            sender.push("impersonation=1".into());
        }
        out.detail.push(header(
            policy,
            "Sender",
            HeaderValue::from_text(&sender.join("; ")),
        ));
        if let Some((top, _)) = out.top
            && let Some(v) = out.verdicts.iter().find(|v| v.kind == top.as_str())
        {
            let texts: Vec<&str> = v
                .reasons
                .iter()
                .filter_map(|k| cfg.reasons.text(k, &cfg.language))
                .collect();
            if !texts.is_empty() {
                out.detail.push(header(
                    policy,
                    "Reasons",
                    HeaderValue::from_text(&texts.join("; ")),
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use firstread_core::decision::{Distribution, ModelRelease};
    use firstread_core::tier::Tier;

    fn inputs(pairs: &[(&str, f64)]) -> BTreeMap<String, f64> {
        pairs.iter().map(|(k, v)| ((*k).to_string(), *v)).collect()
    }

    fn scored(kind: VerdictKind, p: f64, c: &[(&str, f64)]) -> Scored {
        Scored {
            kind,
            p,
            contributions: c.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
        }
    }

    fn policy() -> DirectivePolicy {
        DirectivePolicy {
            allowed_folders: ["inbox", "junk", "later"]
                .iter()
                .map(|k| FolderKey::new(k).unwrap())
                .collect(),
            ..DirectivePolicy::default()
        }
    }

    fn names(o: &Output) -> Vec<&str> {
        o.keywords.iter().map(ImapKeyword::as_str).collect()
    }

    #[test]
    fn data_files_parse() {
        assert!(questions().len() > 20);
        let a = Actions::default();
        assert_eq!(
            a.verdicts.len(),
            VerdictKind::ALL.len(),
            "every verdict has an action"
        );
        let r = Reasons::default();
        assert_eq!(
            r.text("first_contact", "nl"),
            Some("eerste mail van deze afzender")
        );
        assert_eq!(
            r.text("first_contact", "de"),
            Some("first mail from this sender")
        );
        // Every tag question exists in the registry.
        let ids: BTreeSet<String> = questions().into_iter().map(|q| q.id.0).collect();
        for q in a.tag_questions.keys().chain(a.tag_choices.keys()) {
            assert!(ids.contains(q), "{q}");
        }
    }

    #[test]
    fn bad_data_files_are_refused() {
        let ok = ACTIONS;
        assert!(Actions::parse(&ok.replace("\"$Phishing\"", "\"bad keyword\"")).is_err());
        assert!(Actions::parse(&ok.replace("\"later\"", "\"Later\"")).is_err());
        assert!(Actions::parse(&ok.replace("\"bulk_low_interest\"", "\"spam\"")).is_err());
        assert!(Actions::parse(&ok.replace("\"fr-first-contact\"", "\"$Seen\"")).is_err());
        assert!(Reasons::parse(&REASONS.replace("\"first_contact\": {", "\"x\": {")).is_err());
        assert!(
            parse_questions(
                r#"{"questions":[{"id":"a","kind":"choice","text":"t","options":["x"]}]}"#
            )
            .is_err()
        );
        assert!(parse_questions(r#"{"questions":[{"id":"a","kind":"noul","text":"t"},{"id":"a","kind":"noul","text":"t"}]}"#).is_err());
    }

    #[test]
    fn a_phish_gets_phishing_first_its_reasons_and_junk_folder() {
        let f = inputs(&[("attach.count_log", 0.0), ("mailbox.first_contact", 1.0)]);
        let s = [
            scored(VerdictKind::Junk, 0.995, &[("links.ip_literal", 5.0)]),
            scored(
                VerdictKind::Phishing,
                0.97,
                &[
                    ("links.ip_literal", 5.0),
                    ("body.hidden_styles_log", 2.0),
                    ("links.count_log", 1.0),
                    ("mailbox.first_contact", 0.5),
                    ("subject.caps_ratio", -1.0),
                ],
            ),
        ];
        let cfg = StampConfig {
            language: "nl".into(),
            ..StampConfig::default()
        };
        let o = stamp(
            &cfg,
            &Facts {
                inputs: &f,
                scored: &s,
                identity_verified: false,
                rules: &[],
            },
            &policy(),
        );
        assert_eq!(o.top.map(|t| t.0), Some(VerdictKind::Phishing));
        assert_eq!(o.folder.as_ref().map(FolderKey::as_str), Some("junk"));
        assert_eq!(
            names(&o),
            ["$Phishing", "$Junk", "$HasNoAttachment", "fr-first-contact"]
        );
        let phish = &o.verdicts[0];
        assert_eq!(
            phish.reasons,
            ["link_to_ip", "hidden_text", "first_contact"],
            "no unmapped input, nothing negative"
        );
        let h: Vec<String> = o
            .detail
            .iter()
            .map(|h| format!("{}: {}", h.name.as_str(), h.value.as_str()))
            .collect();
        assert_eq!(h[0], "X-Firstread-Scores: phishing=0.97; junk=0.99");
        assert_eq!(
            h[1],
            "X-Firstread-Sender: relation=first-contact; verified=no"
        );
        assert!(
            h[2].starts_with("X-Firstread-Reasons: een link gaat naar een kaal"),
            "{}",
            h[2]
        );
    }

    #[test]
    fn below_threshold_nothing_acts_and_the_mode_limits_folders() {
        let f = inputs(&[("attach.count_log", 1.1)]);
        let s = [
            scored(VerdictKind::BulkLowInterest, 0.95, &[]),
            scored(VerdictKind::Important, 0.2, &[]),
        ];
        let o = stamp(
            &StampConfig::default(),
            &Facts {
                inputs: &f,
                scored: &s,
                identity_verified: true,
                rules: &[],
            },
            &policy(),
        );
        assert_eq!(o.folder.as_ref().map(FolderKey::as_str), Some("later"));
        assert_eq!(names(&o), ["fr-later", "$HasAttachment"]);
        assert_eq!(o.verdicts[0].kind, "important", "in order of precedence");
        assert!(!o.verdicts[0].holds && o.verdicts[1].holds);
        let strict = DirectivePolicy::default();
        let o = stamp(
            &StampConfig::default(),
            &Facts {
                inputs: &f,
                scored: &s,
                identity_verified: true,
                rules: &[],
            },
            &strict,
        );
        assert_eq!(o.folder, None, "a mode without Later files nothing there");
    }

    #[test]
    fn fraud_warns_but_does_not_file() {
        let s = [scored(
            VerdictKind::Fraud,
            0.9,
            &[("mailbox.iban_new_for_domain", 3.0)],
        )];
        let o = stamp(
            &StampConfig::default(),
            &Facts {
                inputs: &inputs(&[]),
                scored: &s,
                identity_verified: true,
                rules: &[],
            },
            &policy(),
        );
        assert_eq!(names(&o), ["$Phishing", "fr-fraud"]);
        assert_eq!(o.folder, None);
        assert_eq!(o.verdicts[0].reasons, ["iban_new"]);
    }

    #[test]
    fn tags_trust_and_unsubscribe_from_facts() {
        let f = inputs(&[
            ("head.topic_money.logit", 2.0),
            ("head.topic_travel.logit", -2.0),
            ("head.intent.request_action", 0.8),
            ("head.intent.sell", 0.9),
            ("head.urgency.expected", 3.96),
            ("list.unsubscribe", 1.0),
            ("meta.auto_submitted", 1.0),
            ("mailbox.first_contact", 0.0),
            ("mailbox.wrote_to_sender", 1.0),
            ("mailbox.reply_to_sent", 1.0),
        ]);
        let o = stamp(
            &StampConfig::default(),
            &Facts {
                inputs: &f,
                scored: &[],
                identity_verified: true,
                rules: &[],
            },
            &policy(),
        );
        assert_eq!(o.tags, ["money", "request-action"]);
        assert_eq!(
            names(&o),
            [
                "fr-money",
                "fr-request-action",
                "$CanUnsubscribe",
                "$Autosent",
                "$IsTrusted"
            ]
        );
        assert_eq!(o.relation, Some(Relation::Correspondent));
        let h: Vec<String> = o
            .detail
            .iter()
            .map(|h| format!("{}: {}", h.name.as_str(), h.value.as_str()))
            .collect();
        assert_eq!(
            h,
            [
                "X-Firstread-Scores: urgency=4.0",
                "X-Firstread-Tags: money, request-action",
                "X-Firstread-Sender: relation=correspondent; verified=yes"
            ]
        );
        // The same facts from an unverified message: no trust.
        let o = stamp(
            &StampConfig::default(),
            &Facts {
                inputs: &f,
                scored: &[],
                identity_verified: false,
                rules: &[],
            },
            &policy(),
        );
        assert!(!names(&o).contains(&"$IsTrusted"));
    }

    #[test]
    fn detail_headers_can_be_switched_off_and_user_keywords_are_never_set() {
        let cfg = StampConfig {
            detail_headers: false,
            ..StampConfig::default()
        };
        let o = stamp(
            &cfg,
            &Facts {
                inputs: &inputs(&[]),
                scored: &[scored(VerdictKind::Junk, 1.0, &[])],
                identity_verified: false,
                rules: &[],
            },
            &policy(),
        );
        assert!(o.detail.is_empty());
        let mut sneaky = Actions::default();
        sneaky
            .verdicts
            .get_mut(&VerdictKind::Junk)
            .unwrap()
            .keywords
            .push(kw("$NotJunk"));
        let cfg = StampConfig {
            actions: sneaky,
            ..StampConfig::default()
        };
        let o = stamp(
            &cfg,
            &Facts {
                inputs: &inputs(&[]),
                scored: &[scored(VerdictKind::Junk, 1.0, &[])],
                identity_verified: false,
                rules: &[],
            },
            &policy(),
        );
        assert_eq!(names(&o), ["$Junk"]);
    }

    #[test]
    fn decisions_become_inputs_by_kind() {
        let q = questions();
        let get = |id: &str| q.iter().find(|x| x.id.0 == id).unwrap().clone();
        let d = |id: &str, p: Vec<f32>| Decision {
            question: QuestionId(id.into()),
            distribution: Distribution::new(p).unwrap(),
            tier: Tier::SmallModels,
            model: ModelRelease("t".into()),
        };
        let noul = decision_inputs(&get("risk_phishing"), &d("risk_phishing", vec![0.2, 0.8]));
        assert_eq!(noul[0].0, "head.risk_phishing.logit");
        assert!((noul[0].1 - 4f64.ln()).abs() < 1e-5);
        let choice = decision_inputs(&get("intent"), &d("intent", vec![0.1, 0.6, 0.1, 0.1, 0.1]));
        assert_eq!(choice[1].0, "head.intent.request_action");
        let score = decision_inputs(
            &get("urgency"),
            &d("urgency", vec![0.0, 0.0, 0.0, 0.0, 0.5, 0.5]),
        );
        assert_eq!(
            score,
            [("head.urgency.expected".to_string(), 4.5f32 as f64)]
        );
    }

    #[test]
    fn rules_set_their_tag_and_bad_rules_are_refused() {
        let rules = parse_rules(
            r#"{"rules":[{"id":"refunds","text":"A customer asks for a refund","tag":"retour"}]}"#,
        )
        .unwrap();
        assert_eq!(rules[0].question().id.0, "rule:refunds");
        let f = inputs(&[("head.rule:refunds.logit", 3.0)]);
        let o = stamp(
            &StampConfig::default(),
            &Facts {
                inputs: &f,
                scored: &[],
                identity_verified: false,
                rules: &rules,
            },
            &policy(),
        );
        assert_eq!(names(&o), ["fr-retour"]);
        let low = inputs(&[("head.rule:refunds.logit", 0.0)]);
        let o = stamp(
            &StampConfig::default(),
            &Facts {
                inputs: &low,
                scored: &[],
                identity_verified: false,
                rules: &rules,
            },
            &policy(),
        );
        assert!(o.keywords.is_empty());
        for bad in [
            r#"{"rules":[{"id":"Refunds","text":"x","tag":"retour"}]}"#,
            r#"{"rules":[{"id":"a","text":"x","tag":"$Junk"}]}"#,
            r#"{"rules":[{"id":"a","text":" ","tag":"t"}]}"#,
            r#"{"rules":[{"id":"a","text":"x","tag":"t"},{"id":"a","text":"y","tag":"u"}]}"#,
        ] {
            assert!(parse_rules(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn junk_threshold_from_the_deployment() {
        let a = Actions::default().with_junk_threshold(0.95);
        let j = &a.verdicts[&VerdictKind::Junk];
        assert_eq!((j.keyword, j.folder), (Some(0.95), Some(0.95)));
    }
}
