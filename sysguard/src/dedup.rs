use crate::policy::{EventRecord, PolicyDecision, PolicyEventKind, RuleAction};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Deduper {
    window: Duration,
    summary_interval: Duration,
    entries: HashMap<EventFingerprint, DedupState>,
}

impl Deduper {
    pub fn new(window: Duration, summary_interval: Duration) -> Self {
        Self {
            window,
            summary_interval,
            entries: HashMap::new(),
        }
    }

    pub fn observe(&mut self, event: &EventRecord, decision: &PolicyDecision<'_>) -> bool {
        let now = Instant::now();
        let key = EventFingerprint::new(event, decision);

        if let Some(state) = self.entries.get_mut(&key) {
            if now.duration_since(state.last_seen) <= self.window {
                state.last_seen = now;
                state.suppressed_count += 1;
                return false;
            }

            state.last_seen = now;
            state.last_summary = now;
            state.suppressed_count = 0;
            state.uid = event.uid;
            state.pid = event.pid;
            state.ppid = event.ppid;
            state.exe_path = event.exe_path.clone();
            return true;
        }

        self.entries.insert(key, DedupState::new(now, event));
        true
    }

    pub fn flush_ready(&mut self, force: bool) -> Vec<DedupSummary> {
        let now = Instant::now();
        let mut summaries = Vec::new();
        let mut stale = Vec::new();

        for (key, state) in &mut self.entries {
            let should_summarize = state.suppressed_count > 0
                && (force || now.duration_since(state.last_summary) >= self.summary_interval);
            if should_summarize {
                summaries.push(DedupSummary {
                    action: key.action,
                    rule_name: key.rule_name.clone(),
                    event: key.event.clone(),
                    uid: state.uid,
                    pid: state.pid,
                    ppid: state.ppid,
                    exe_path: state.exe_path.clone(),
                    suppressed_count: state.suppressed_count,
                });
                state.suppressed_count = 0;
                state.last_summary = now;
            }

            if force || now.duration_since(state.last_seen) > self.window.saturating_mul(4) {
                stale.push(key.clone());
            }
        }

        for key in stale {
            self.entries.remove(&key);
        }

        summaries
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct EventFingerprint {
    action: RuleAction,
    rule_name: Option<String>,
    event: DedupEvent,
}

impl EventFingerprint {
    fn new(event: &EventRecord, decision: &PolicyDecision<'_>) -> Self {
        Self {
            action: decision.action,
            rule_name: decision.rule_name.map(ToOwned::to_owned),
            event: DedupEvent {
                kind: PolicyEventKind::from(event.kind),
                uid: event.uid,
                pid: event.pid,
                comm: event.comm.clone(),
                filename: event.filename.clone(),
                daddr: event.daddr,
                dport: event.dport,
            },
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DedupEvent {
    pub kind: PolicyEventKind,
    pub uid: u32,
    pub pid: u32,
    pub comm: String,
    pub filename: Option<String>,
    pub daddr: Option<Ipv4Addr>,
    pub dport: Option<u16>,
}

#[derive(Debug)]
struct DedupState {
    last_seen: Instant,
    last_summary: Instant,
    suppressed_count: u64,
    uid: u32,
    pid: u32,
    ppid: Option<u32>,
    exe_path: Option<String>,
}

impl DedupState {
    fn new(now: Instant, event: &EventRecord) -> Self {
        Self {
            last_seen: now,
            last_summary: now,
            suppressed_count: 0,
            uid: event.uid,
            pid: event.pid,
            ppid: event.ppid,
            exe_path: event.exe_path.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DedupSummary {
    pub action: RuleAction,
    pub rule_name: Option<String>,
    pub event: DedupEvent,
    pub uid: u32,
    pub pid: u32,
    pub ppid: Option<u32>,
    pub exe_path: Option<String>,
    pub suppressed_count: u64,
}

impl DedupSummary {
    pub fn summary_line(&self) -> String {
        let mut parts = vec![
            format!("event={}", self.event.kind.as_str()),
            format!("pid={}", self.pid),
            format!("uid={}", self.uid),
            format!("comm={}", self.event.comm),
            format!("suppressed_count={}", self.suppressed_count),
        ];

        if let Some(ppid) = self.ppid {
            parts.push(format!("ppid={}", ppid));
        }
        if let Some(filename) = &self.event.filename {
            parts.push(format!("file={}", filename));
        }
        if let Some(addr) = self.event.daddr {
            parts.push(format!("addr={}", addr));
        }
        if let Some(port) = self.event.dport {
            parts.push(format!("port={}", port));
        }
        if let Some(exe_path) = &self.exe_path {
            parts.push(format!("exe={}", exe_path));
        }

        parts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{EventRecord, RuleAction};
    use sysguard_common::EventKind;

    fn sample_event() -> EventRecord {
        EventRecord {
            kind: EventKind::Connect,
            pid: 42,
            ppid: Some(1),
            uid: 1000,
            comm: "curl".to_string(),
            filename: None,
            daddr: Some(Ipv4Addr::new(1, 1, 1, 1)),
            dport: Some(443),
            exe_path: Some("/usr/bin/curl".to_string()),
        }
    }

    #[test]
    fn duplicate_events_are_suppressed_until_summary() {
        let mut deduper = Deduper::new(Duration::from_secs(10), Duration::ZERO);
        let event = sample_event();
        let decision = PolicyDecision {
            action: RuleAction::Alert,
            rule_name: Some("watch_https_connections"),
        };

        assert!(deduper.observe(&event, &decision));
        assert!(!deduper.observe(&event, &decision));
        let summaries = deduper.flush_ready(false);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].suppressed_count, 1);
    }

    #[test]
    fn force_flush_emits_summary_and_clears_state() {
        let mut deduper = Deduper::new(Duration::from_secs(10), Duration::from_secs(60));
        let event = sample_event();
        let decision = PolicyDecision {
            action: RuleAction::Block,
            rule_name: Some("block_https"),
        };

        assert!(deduper.observe(&event, &decision));
        assert!(!deduper.observe(&event, &decision));

        let summaries = deduper.flush_ready(true);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].suppressed_count, 1);
        assert!(deduper.flush_ready(false).is_empty());
    }

    #[test]
    fn summary_line_includes_network_context() {
        let summary = DedupSummary {
            action: RuleAction::Alert,
            rule_name: Some("watch_https_connections".to_string()),
            event: DedupEvent {
                kind: PolicyEventKind::Connect,
                uid: 1000,
                pid: 42,
                comm: "curl".to_string(),
                filename: None,
                daddr: Some(Ipv4Addr::new(1, 1, 1, 1)),
                dport: Some(443),
            },
            uid: 1000,
            pid: 42,
            ppid: Some(1),
            exe_path: Some("/usr/bin/curl".to_string()),
            suppressed_count: 3,
        };

        let line = summary.summary_line();
        assert!(line.contains("event=connect"));
        assert!(line.contains("port=443"));
        assert!(line.contains("exe=/usr/bin/curl"));
    }
}
