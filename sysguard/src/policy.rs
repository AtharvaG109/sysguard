use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::fmt;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use sysguard_common::EventKind;

#[derive(Debug, Clone)]
pub struct EventRecord {
    pub kind: EventKind,
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: u32,
    pub comm: String,
    pub filename: Option<String>,
    pub daddr: Option<Ipv4Addr>,
    pub dport: Option<u16>,
    pub exe_path: Option<String>,
}

impl EventRecord {
    pub fn summary(&self) -> String {
        let mut parts = vec![
            format!("event={}", PolicyEventKind::from(self.kind).as_str()),
            format!("pid={}", self.pid),
            format!("uid={}", self.uid),
            format!("comm={}", self.comm),
        ];

        if let Some(ppid) = self.ppid {
            parts.push(format!("ppid={}", ppid));
        }
        if let Some(filename) = &self.filename {
            parts.push(format!("file={}", filename));
        }
        if let Some(addr) = self.daddr {
            parts.push(format!("addr={}", addr));
        }
        if let Some(port) = self.dport {
            parts.push(format!("port={}", port));
        }
        if let Some(exe_path) = &self.exe_path {
            parts.push(format!("exe={}", exe_path));
        }

        parts.join(" ")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyFile {
    pub version: u32,
    #[serde(default = "default_action")]
    pub default_action: RuleAction,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    #[serde(default)]
    pub ignore: IgnoreConfig,
}

impl PolicyFile {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file at {}", path.display()))?;
        let policy: Self = serde_yaml::from_str(&raw)
            .with_context(|| format!("failed to parse policy file at {}", path.display()))?;

        if policy.version != 1 {
            bail!("unsupported policy version {}; expected 1", policy.version);
        }

        Ok(policy)
    }

    pub fn evaluate<'a>(&'a self, event: &EventRecord) -> PolicyDecision<'a> {
        for rule in &self.rules {
            if rule.matches(event) {
                return PolicyDecision {
                    action: rule.action,
                    rule_name: Some(rule.name.as_str()),
                };
            }
        }

        PolicyDecision {
            action: self.default_action,
            rule_name: None,
        }
    }

    pub fn should_ignore(&self, event: &EventRecord) -> bool {
        self.ignore.matches(event)
    }

    pub fn summary_line(&self) -> String {
        let enforceable = self.connect_block_plan().enforceable.len();
        format!(
            "version={} default_action={} rules={} ignored_uids={} ignored_processes={} enforceable_connect_blocks={}",
            self.version,
            self.default_action,
            self.rules.len(),
            self.ignore.uids.len(),
            self.ignore.comm.len(),
            enforceable
        )
    }

    pub fn connect_block_plan(&self) -> ConnectBlockPlan {
        let mut enforceable = Vec::new();
        let mut skipped = Vec::new();

        for rule in &self.rules {
            if rule.action != RuleAction::Block {
                continue;
            }

            if rule.event != PolicyEventKind::Connect {
                skipped.push(format!(
                    "{}: block enforcement currently supports connect rules only",
                    rule.name
                ));
                continue;
            }

            if rule.matcher.comm.is_some() || rule.matcher.filename.is_some() {
                skipped.push(format!(
                    "{}: connect enforcement supports uid/addr/port matches only",
                    rule.name
                ));
                continue;
            }

            let addr = match rule.matcher.addr.as_deref() {
                Some(pattern) => match parse_exact_ipv4(pattern) {
                    Some(addr) => Some(addr),
                    None => {
                        skipped.push(format!(
                            "{}: connect enforcement requires an exact IPv4 addr, got {}",
                            rule.name, pattern
                        ));
                        continue;
                    }
                },
                None => None,
            };

            let port = rule.matcher.port;
            if addr.is_none() && port.is_none() {
                skipped.push(format!(
                    "{}: connect enforcement requires at least an addr or port match",
                    rule.name
                ));
                continue;
            }

            enforceable.push(ConnectBlockRuleSpec {
                name: rule.name.clone(),
                uid: rule.matcher.uid,
                addr,
                port,
            });
        }

        ConnectBlockPlan { enforceable, skipped }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Hash, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Log,
    Alert,
    Block,
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::Log => write!(f, "LOG"),
            Self::Alert => write!(f, "ALERT"),
            Self::Block => write!(f, "BLOCK"),
        }
    }
}

#[derive(Debug)]
pub struct PolicyDecision<'a> {
    pub action: RuleAction,
    pub rule_name: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct ConnectBlockPlan {
    pub enforceable: Vec<ConnectBlockRuleSpec>,
    pub skipped: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ConnectBlockRuleSpec {
    pub name: String,
    pub uid: Option<u32>,
    pub addr: Option<Ipv4Addr>,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub event: PolicyEventKind,
    #[serde(default = "default_action")]
    pub action: RuleAction,
    #[serde(default, rename = "match")]
    pub matcher: PolicyMatch,
}

impl PolicyRule {
    fn matches(&self, event: &EventRecord) -> bool {
        self.event.matches(event.kind) && self.matcher.matches(event)
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Hash, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyEventKind {
    Any,
    Execve,
    Openat,
    Connect,
}

impl PolicyEventKind {
    pub fn matches(self, kind: EventKind) -> bool {
        matches!(self, Self::Any) || self == Self::from(kind)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Execve => "execve",
            Self::Openat => "openat",
            Self::Connect => "connect",
        }
    }
}

impl From<EventKind> for PolicyEventKind {
    fn from(value: EventKind) -> Self {
        match value {
            EventKind::Execve => Self::Execve,
            EventKind::Openat => Self::Openat,
            EventKind::Connect => Self::Connect,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyMatch {
    pub uid: Option<u32>,
    pub comm: Option<String>,
    pub filename: Option<String>,
    pub port: Option<u16>,
    pub addr: Option<String>,
}

impl PolicyMatch {
    fn matches(&self, event: &EventRecord) -> bool {
        if let Some(uid) = self.uid {
            if event.uid != uid {
                return false;
            }
        }

        if let Some(pattern) = &self.comm {
            if !glob_matches(pattern, &event.comm) {
                return false;
            }
        }

        if let Some(pattern) = &self.filename {
            let Some(filename) = &event.filename else {
                return false;
            };
            if !glob_matches(pattern, filename) {
                return false;
            }
        }

        if let Some(port) = self.port {
            if event.dport != Some(port) {
                return false;
            }
        }

        if let Some(pattern) = &self.addr {
            let Some(addr) = event.daddr else {
                return false;
            };
            if !glob_matches(pattern, &addr.to_string()) {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct IgnoreConfig {
    #[serde(default)]
    pub uids: Vec<u32>,
    #[serde(default)]
    pub comm: Vec<String>,
    #[serde(default)]
    pub filename: Vec<String>,
    #[serde(default)]
    pub addr: Vec<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
}

impl IgnoreConfig {
    fn matches(&self, event: &EventRecord) -> bool {
        if self.uids.iter().any(|uid| *uid == event.uid) {
            return true;
        }

        if self.comm.iter().any(|pattern| glob_matches(pattern, &event.comm)) {
            return true;
        }

        if let Some(filename) = &event.filename {
            if self
                .filename
                .iter()
                .any(|pattern| glob_matches(pattern, filename))
            {
                return true;
            }
        }

        if let Some(addr) = event.daddr {
            let addr_string = addr.to_string();
            if self
                .addr
                .iter()
                .any(|pattern| glob_matches(pattern, &addr_string))
            {
                return true;
            }
        }

        if let Some(port) = event.dport {
            if self.ports.iter().any(|candidate| *candidate == port) {
                return true;
            }
        }

        false
    }
}

fn default_action() -> RuleAction {
    RuleAction::Allow
}

fn parse_exact_ipv4(pattern: &str) -> Option<Ipv4Addr> {
    if pattern.contains('*') || pattern.contains('?') {
        return None;
    }
    pattern.parse().ok()
}

pub fn glob_matches(pattern: &str, text: &str) -> bool {
    glob_matches_bytes(pattern.as_bytes(), text.as_bytes())
}

fn glob_matches_bytes(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_idx, mut match_idx) = (None, 0usize);

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
            continue;
        }

        if p < pattern.len() && pattern[p] == b'*' {
            star_idx = Some(p);
            p += 1;
            match_idx = t;
            continue;
        }

        if let Some(star) = star_idx {
            p = star + 1;
            match_idx += 1;
            t = match_idx;
            continue;
        }

        return false;
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }

    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> EventRecord {
        EventRecord {
            kind: EventKind::Openat,
            pid: 100,
            ppid: Some(1),
            uid: 1000,
            comm: "curl".to_string(),
            filename: Some("/etc/hosts".to_string()),
            daddr: Some(Ipv4Addr::new(1, 1, 1, 1)),
            dport: Some(443),
            exe_path: Some("/usr/bin/curl".to_string()),
        }
    }

    #[test]
    fn glob_match_handles_wildcards() {
        assert!(glob_matches("/etc/*", "/etc/hosts"));
        assert!(glob_matches("curl*", "curl"));
        assert!(!glob_matches("/proc/*", "/etc/hosts"));
    }

    #[test]
    fn ignore_config_matches_expected_fields() {
        let ignore = IgnoreConfig {
            uids: vec![0],
            comm: vec!["curl*".to_string()],
            filename: vec!["/proc/*".to_string()],
            addr: vec!["1.1.*".to_string()],
            ports: vec![53],
        };

        assert!(ignore.matches(&sample_event()));
    }

    #[test]
    fn policy_rule_matches_filename() {
        let rule = PolicyRule {
            name: "watch_sensitive_file_reads".to_string(),
            event: PolicyEventKind::Openat,
            action: RuleAction::Alert,
            matcher: PolicyMatch {
                filename: Some("/etc/*".to_string()),
                ..PolicyMatch::default()
            },
        };

        assert!(rule.matches(&sample_event()));
    }

    #[test]
    fn connect_block_plan_skips_unsupported_rules() {
        let policy = PolicyFile {
            version: 1,
            default_action: RuleAction::Log,
            ignore: IgnoreConfig::default(),
            rules: vec![
                PolicyRule {
                    name: "block_https".to_string(),
                    event: PolicyEventKind::Connect,
                    action: RuleAction::Block,
                    matcher: PolicyMatch {
                        port: Some(443),
                        ..PolicyMatch::default()
                    },
                },
                PolicyRule {
                    name: "block_curl_https".to_string(),
                    event: PolicyEventKind::Connect,
                    action: RuleAction::Block,
                    matcher: PolicyMatch {
                        comm: Some("curl".to_string()),
                        port: Some(443),
                        ..PolicyMatch::default()
                    },
                },
            ],
        };

        let plan = policy.connect_block_plan();
        assert_eq!(plan.enforceable.len(), 1);
        assert_eq!(plan.enforceable[0].name, "block_https");
        assert_eq!(plan.skipped.len(), 1);
    }

    #[test]
    fn policy_uses_default_action_when_no_rule_matches() {
        let policy = PolicyFile {
            version: 1,
            default_action: RuleAction::Alert,
            rules: vec![],
            ignore: IgnoreConfig::default(),
        };

        let decision = policy.evaluate(&sample_event());
        assert_eq!(decision.action, RuleAction::Alert);
        assert!(decision.rule_name.is_none());
    }

    #[test]
    fn policy_summary_line_includes_counts() {
        let policy = PolicyFile {
            version: 1,
            default_action: RuleAction::Log,
            ignore: IgnoreConfig {
                uids: vec![0],
                comm: vec!["launchd".to_string()],
                ..IgnoreConfig::default()
            },
            rules: vec![PolicyRule {
                name: "block_dns".to_string(),
                event: PolicyEventKind::Connect,
                action: RuleAction::Block,
                matcher: PolicyMatch {
                    port: Some(53),
                    ..PolicyMatch::default()
                },
            }],
        };

        let summary = policy.summary_line();
        assert!(summary.contains("version=1"));
        assert!(summary.contains("rules=1"));
        assert!(summary.contains("ignored_uids=1"));
        assert!(summary.contains("enforceable_connect_blocks=1"));
    }

    #[test]
    fn parse_exact_ipv4_rejects_globs() {
        assert_eq!(parse_exact_ipv4("1.1.1.1"), Some(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(parse_exact_ipv4("1.1.*").is_none());
    }
}
