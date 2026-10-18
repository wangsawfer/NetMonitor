//! Record store, statistics and export.
//!
//! The store is a bounded ring of display-ready rows. It is the *only* thing
//! shared between the pipeline thread and the UI thread, and it is held behind
//! a mutex that is never held across I/O, never held while rendering, and never
//! acquired by a capture thread.
//!
//! Filtering/aggregation helpers below were written for the terminal front-end.
//! The graphical front-end filters its own rows, so from the binary's point of
//! view some of them are now only exercised by tests -- they are kept as the
//! store's query surface rather than deleted and re-derived later.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::Path;

use anyhow::Context;

use crate::model::{EventKind, Record, Source};

/// Upper bound on retained rows. At ~150 bytes per row this is a few tens of
/// MiB; long sessions should export and clear rather than grow without bound.
pub const DEFAULT_CAPACITY: usize = 200_000;

/// Aggregate counters shown in the statistics panel.
#[derive(Default, Clone, Debug)]
pub struct Stats {
    pub total_records: u64,
    pub queries: u64,
    /// Answers observed on the wire, used to size the IP cache.
    pub responses: u64,
    pub sni_observations: u64,
    /// Events dropped because the PID was outside the target tree.
    pub filtered_out_of_tree: u64,
    /// Events we could not attribute to any PID (Npcap race with socket close).
    pub unattributed: u64,
    /// Duplicates collapsed by the deduplicator.
    pub duplicates: u64,
    /// Records evicted from the ring because it was full.
    pub evicted: u64,
    pub unique_domains: HashSet<String>,
    pub unique_processes: HashSet<String>,
    pub by_source: HashMap<&'static str, u64>,
    pub first_event_ms: Option<i64>,
    pub last_event_ms: Option<i64>,
}

impl Stats {
    pub fn unique_domain_count(&self) -> usize {
        self.unique_domains.len()
    }

    pub fn unique_process_count(&self) -> usize {
        self.unique_processes.len()
    }

    /// Events per second over the observed window.
    pub fn rate_per_sec(&self) -> f64 {
        match (self.first_event_ms, self.last_event_ms) {
            (Some(a), Some(b)) if b > a => {
                self.total_records as f64 / ((b - a) as f64 / 1000.0)
            }
            _ => 0.0,
        }
    }
}

/// Which sources and kinds the list view should include.
#[derive(Clone, Debug)]
pub struct ViewFilter {
    /// Case-insensitive substring match on the domain.
    pub domain: String,
    /// Case-insensitive substring match on the process name.
    pub process: String,
    /// Address match: a bare IP, a network in CIDR form, or a substring.
    pub ip: String,
    /// Exact image names to show, lower-cased. Empty means "no name filter".
    ///
    /// This is the filter for a program that downloads through a helper
    /// process: the whole tree is captured, and this narrows the display to
    /// the processes you actually care about. Matching is by *name* rather than
    /// PID on purpose -- a helper that restarts, or runs one instance per
    /// download, keeps matching.
    pub process_names: HashSet<String>,
    pub show_etw: bool,
    pub show_pcap: bool,
    pub show_sni: bool,
    /// Include rows that could not be attributed to a PID.
    pub show_unattributed: bool,
}

impl Default for ViewFilter {
    fn default() -> Self {
        Self {
            domain: String::new(),
            process: String::new(),
            ip: String::new(),
            process_names: HashSet::new(),
            show_etw: true,
            show_pcap: true,
            show_sni: true,
            show_unattributed: false,
        }
    }
}

impl ViewFilter {
    pub fn is_active(&self) -> bool {
        !self.domain.is_empty()
            || !self.process.is_empty()
            || !self.ip.is_empty()
            || !self.process_names.is_empty()
            || !self.show_etw
            || !self.show_pcap
            || !self.show_sni
            || self.show_unattributed
    }

    /// Toggle one image name in the allow-list.
    pub fn toggle_process_name(&mut self, name: &str) {
        let key = name.to_ascii_lowercase();
        if !self.process_names.remove(&key) {
            self.process_names.insert(key);
        }
    }

    pub fn process_name_selected(&self, name: &str) -> bool {
        self.process_names.contains(&name.to_ascii_lowercase())
    }

    pub fn accepts(&self, r: &Record) -> bool {
        if !self.show_unattributed && r.pid == 0 {
            return false;
        }
        match r.source {
            Source::Etw if !self.show_etw => return false,
            Source::Npcap if !self.show_pcap => return false,
            Source::Sni if !self.show_sni => return false,
            _ => {}
        }
        if !self.domain.is_empty() && !contains_ci(&r.domain, &self.domain) {
            return false;
        }
        if !self.process.is_empty() && !contains_ci(&r.process, &self.process) {
            return false;
        }
        if !self.process_names.is_empty()
            && !self.process_names.contains(&r.process.to_ascii_lowercase())
        {
            return false;
        }
        if !self.ip.is_empty() && !ip_matches(&self.ip, &r.resolved) {
            return false;
        }
        true
    }
}

/// What the address filter box currently means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpQuery {
    /// A network in CIDR form.
    Network { base: IpAddr, prefix: u8 },
    /// A single address.
    Exact(IpAddr),
    /// Not an address or a network: match the rendered text instead, so the
    /// list still narrows while a prefix is being typed.
    Substring(String),
}

/// Parse the filter box.
pub fn parse_ip_query(text: &str) -> IpQuery {
    let t = text.trim();
    if let Some((addr, bits)) = t.split_once('/') {
        if let (Ok(base), Ok(prefix)) = (addr.trim().parse::<IpAddr>(), bits.trim().parse::<u8>()) {
            let max = if base.is_ipv4() { 32 } else { 128 };
            if prefix <= max {
                return IpQuery::Network { base, prefix };
            }
        }
    }
    if let Ok(addr) = t.parse::<IpAddr>() {
        return IpQuery::Exact(addr);
    }
    IpQuery::Substring(t.to_ascii_lowercase())
}

/// Does any of `addrs` satisfy the query?
pub fn ip_matches(text: &str, addrs: &[IpAddr]) -> bool {
    match parse_ip_query(text) {
        IpQuery::Exact(want) => addrs.contains(&want),
        IpQuery::Network { base, prefix } => addrs.iter().any(|a| in_network(*a, base, prefix)),
        // Nothing structured to compare against: fall back to the rendered
        // list, which is what the user can see.
        IpQuery::Substring(needle) => {
            if needle.is_empty() {
                return true;
            }
            addrs
                .iter()
                .any(|a| a.to_string().to_ascii_lowercase().contains(&needle))
        }
    }
}

/// Is `addr` inside `base/prefix`? Address families must match.
pub fn in_network(addr: IpAddr, base: IpAddr, prefix: u8) -> bool {
    match (addr, base) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix.min(32))
            };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask: u128 = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix.min(128))
            };
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
    }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    // ASCII case folding without allocating; DNS names and image names are
    // ASCII in practice, and the fallback keeps non-ASCII working.
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
        || haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// IP -> hostname and hostname -> IP correlation caches, fed by DNS responses
/// seen on the wire.
pub struct IpCache {
    ip_to_name: HashMap<IpAddr, (String, i64)>,
    name_to_ips: HashMap<String, Vec<IpAddr>>,
    ttl_ms: i64,
    max_entries: usize,
    pub inserts: u64,
}

impl IpCache {
    pub fn new(ttl_ms: i64, max_entries: usize) -> Self {
        Self {
            ip_to_name: HashMap::new(),
            name_to_ips: HashMap::new(),
            ttl_ms,
            max_entries,
            inserts: 0,
        }
    }

    /// Record that `name` resolved to `ips` at `now_ms`.
    pub fn insert(&mut self, name: &str, ips: &[IpAddr], now_ms: i64) {
        if name.is_empty() || ips.is_empty() {
            return;
        }
        for ip in ips {
            self.ip_to_name.insert(*ip, (name.to_string(), now_ms));
        }
        let slot = self.name_to_ips.entry(name.to_string()).or_default();
        for ip in ips {
            if !slot.contains(ip) {
                slot.push(*ip);
            }
        }
        self.inserts += 1;
        if self.ip_to_name.len() > self.max_entries {
            self.evict_expired(now_ms, true);
        }
    }

    /// Reverse lookup: which hostname an address resolved from.
    ///
    /// Test-covered; the binary consumes the forward direction today.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn name_for_ip(&self, ip: &IpAddr, now_ms: i64) -> Option<&str> {
        self.ip_to_name
            .get(ip)
            .filter(|(_, t)| now_ms - *t < self.ttl_ms)
            .map(|(n, _)| n.as_str())
    }

    pub fn ips_for_name(&self, name: &str) -> Option<&[IpAddr]> {
        self.name_to_ips.get(name).map(|v| v.as_slice())
    }

    pub fn len(&self) -> usize {
        self.ip_to_name.len()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_empty(&self) -> bool {
        self.ip_to_name.is_empty()
    }

    fn evict_expired(&mut self, now_ms: i64, aggressive: bool) {
        let ttl = if aggressive { self.ttl_ms / 4 } else { self.ttl_ms };
        self.ip_to_name.retain(|_, (_, t)| now_ms - *t < ttl);
        if aggressive && self.ip_to_name.len() > self.max_entries {
            // Still too big: drop the oldest half of the name index to bound
            // memory without a full LRU implementation.
            let keep = self.max_entries / 2;
            if self.name_to_ips.len() > keep {
                let mut ages: Vec<(String, i64)> = self
                    .name_to_ips
                    .iter()
                    .map(|(k, _)| {
                        let newest = self
                            .ip_to_name
                            .values()
                            .filter(|(n, _)| n == k)
                            .map(|(_, t)| *t)
                            .max()
                            .unwrap_or(0);
                        (k.clone(), newest)
                    })
                    .collect();
                ages.sort_by_key(|(_, t)| *t);
                for (k, _) in ages.into_iter().take(keep) {
                    self.name_to_ips.remove(&k);
                }
            }
        }
    }
}

/// The shared record store.
pub struct Store {
    rows: VecDeque<Record>,
    capacity: usize,
    pub stats: Stats,
    pub ips: IpCache,
    seq: u64,
}

impl Store {
    pub fn new(capacity: usize) -> Self {
        Self {
            rows: VecDeque::with_capacity(4096),
            capacity,
            stats: Stats::default(),
            ips: IpCache::new(15 * 60 * 1000, 65_536),
            seq: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Append a row, updating aggregate statistics.
    pub fn push(&mut self, mut rec: Record) {
        self.seq += 1;
        rec.seq = self.seq;
        if self.rows.len() >= self.capacity {
            self.rows.pop_front();
            self.stats.evicted += 1;
        }
        self.stats.total_records += 1;
        match rec.kind {
            EventKind::Query => self.stats.queries += 1,
            EventKind::Response => self.stats.responses += 1,
            EventKind::TlsSni => self.stats.sni_observations += 1,
        }
        *self
            .stats
            .by_source
            .entry(rec.source.as_str())
            .or_insert(0) += 1;
        self.stats.unique_domains.insert(rec.domain.clone());
        if rec.pid != 0 {
            self.stats.unique_processes.insert(rec.process.clone());
        }
        self.stats.first_event_ms.get_or_insert(rec.unix_ms);
        self.stats.last_event_ms = Some(rec.unix_ms);
        self.rows.push_back(rec);
    }

    pub fn clear(&mut self) {
        self.rows.clear();
    }

    /// Rows matching `filter`, newest last, capped at `limit`.
    pub fn view(&self, filter: &ViewFilter, limit: usize) -> Vec<&Record> {
        let mut out: Vec<&Record> = Vec::with_capacity(limit.min(1024));
        for r in self.rows.iter().rev() {
            if filter.accepts(r) {
                out.push(r);
                if out.len() >= limit {
                    break;
                }
            }
        }
        out.reverse();
        out
    }

    /// Total number of rows matching `filter` (for the status line).
    pub fn count_matching(&self, filter: &ViewFilter) -> usize {
        self.rows.iter().filter(|r| filter.accepts(r)).count()
    }

    /// Every process that has produced at least one record, most active first.
    ///
    /// Returns `(image name, record count, one representative PID)`. This is
    /// what the process picker lists: you cannot filter by a name you have not
    /// seen, and the point of the picker is exactly that a download helper is
    /// invisible until it runs.
    pub fn process_summary(&self) -> Vec<(String, usize, u32)> {
        let mut counts: HashMap<(&str, u32), usize> = HashMap::new();
        for r in &self.rows {
            if r.pid != 0 {
                *counts.entry((r.process.as_str(), r.pid)).or_insert(0) += 1;
            }
        }
        let mut by_name: HashMap<&str, (usize, u32)> = HashMap::new();
        for ((name, pid), count) in counts {
            let e = by_name.entry(name).or_insert((0, pid));
            e.0 += count;
            e.1 = e.1.max(pid);
        }
        let mut v: Vec<(String, usize, u32)> = by_name
            .into_iter()
            .map(|(n, (c, p))| (n.to_string(), c, p))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    /// Rows appended after `seq`, oldest first, capped at `limit`.
    ///
    /// Walks backwards from the tail and stops as soon as it reaches `seq`, so
    /// a streaming consumer pays only for what is new.
    pub fn since(&self, seq: u64, limit: usize) -> Vec<&Record> {
        let mut out = Vec::new();
        for r in self.rows.iter().rev() {
            if r.seq <= seq {
                break;
            }
            out.push(r);
            if out.len() >= limit {
                break;
            }
        }
        out.reverse();
        out
    }

    /// Top domains by occurrence.
    pub fn top_domains(&self, n: usize) -> Vec<(String, usize)> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for r in &self.rows {
            *counts.entry(r.domain.as_str()).or_insert(0) += 1;
        }
        let mut v: Vec<(String, usize)> = counts
            .into_iter()
            .map(|(k, c)| (k.to_string(), c))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    /// Top processes by occurrence of their records.
    pub fn top_processes(&self, n: usize) -> Vec<(String, usize)> {
        let mut counts: HashMap<(&str, u32), usize> = HashMap::new();
        for r in &self.rows {
            if r.pid != 0 {
                *counts.entry((r.process.as_str(), r.pid)).or_insert(0) += 1;
            }
        }
        let mut v: Vec<(String, usize)> = counts
            .into_iter()
            .map(|((p, pid), c)| (format!("{p} ({pid})"), c))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    /// Write every retained row to `path`, choosing the format from the
    /// extension (`.json` -> JSON array, anything else -> CSV).
    ///
    /// Returns the number of rows written.
    pub fn export(&self, path: &Path, filter: &ViewFilter) -> anyhow::Result<usize> {
        let rows: Vec<&Record> = self.rows.iter().filter(|r| filter.accepts(r)).collect();
        let is_json = path
            .extension()
            .map(|e| e.eq_ignore_ascii_case("json"))
            .unwrap_or(false);

        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).ok();
            }
        }

        if is_json {
            #[derive(serde::Serialize)]
            struct Row<'a> {
                seq: u64,
                time: &'a str,
                timestamp: String,
                process: &'a str,
                pid: u32,
                domain: &'a str,
                qtype: &'a str,
                source: &'a str,
                kind: &'a str,
                detail: &'a str,
            }
            let out: Vec<Row<'_>> = rows
                .iter()
                .map(|r| Row {
                    seq: r.seq,
                    time: &r.time,
                    timestamp: crate::util::fmt_datetime_ms(r.unix_ms),
                    process: &r.process,
                    pid: r.pid,
                    domain: &r.domain,
                    qtype: &r.qtype,
                    source: r.source.as_str(),
                    kind: match r.kind {
                        EventKind::Query => "query",
                        EventKind::Response => "response",
                        EventKind::TlsSni => "tls_sni",
                    },
                    detail: &r.detail,
                })
                .collect();
            let f = std::fs::File::create(path)
                .with_context(|| format!("creating {}", path.display()))?;
            serde_json::to_writer_pretty(std::io::BufWriter::new(f), &out)
                .with_context(|| format!("writing {}", path.display()))?;
        } else {
            let f = std::fs::File::create(path)
                .with_context(|| format!("creating {}", path.display()))?;
            let mut w = csv::Writer::from_writer(std::io::BufWriter::new(f));
            w.write_record([
                "seq",
                "time",
                "timestamp",
                "process",
                "pid",
                "domain",
                "qtype",
                "source",
                "kind",
                "detail",
            ])?;
            for r in &rows {
                w.write_record([
                    r.seq.to_string(),
                    r.time.clone(),
                    crate::util::fmt_datetime_ms(r.unix_ms),
                    r.process.clone(),
                    r.pid.to_string(),
                    r.domain.clone(),
                    r.qtype.clone(),
                    r.source.as_str().to_string(),
                    match r.kind {
                        EventKind::Query => "query",
                        EventKind::Response => "response",
                        EventKind::TlsSni => "tls_sni",
                    }
                    .to_string(),
                    r.detail.clone(),
                ])?;
            }
            w.flush()?;
        }
        Ok(rows.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EventKind;

    fn rec(domain: &str, process: &str, pid: u32, src: Source, kind: EventKind) -> Record {
        Record {
            seq: 0,
            unix_ms: 1_700_000_000_000,
            time: "12:00:00.000".into(),
            process: process.into(),
            pid,
            qtype: "A".into(),
            source: src,
            kind,
            domain: domain.into(),
            resolved: Vec::new(),
            detail: String::new(),
        }
    }

    #[test]
    fn filtering_by_domain_and_process() {
        let mut s = Store::new(100);
        s.push(rec("a.example.com", "chrome.exe", 10, Source::Etw, EventKind::Query));
        s.push(rec("b.test.org", "chrome.exe", 10, Source::Etw, EventKind::Query));
        s.push(rec("c.test.org", "curl.exe", 11, Source::Etw, EventKind::Query));

        let f = ViewFilter {
            domain: "TEST".into(),
            ..Default::default()
        };
        assert_eq!(s.count_matching(&f), 2);

        let f = ViewFilter {
            process: "chrome".into(),
            ..Default::default()
        };
        assert_eq!(s.count_matching(&f), 2);

        let f = ViewFilter {
            domain: "example".into(),
            process: "curl".into(),
            ..Default::default()
        };
        assert_eq!(s.count_matching(&f), 0);
    }

    #[test]
    fn source_toggles_and_unattributed() {
        let mut s = Store::new(100);
        s.push(rec("x.test", "app.exe", 1, Source::Etw, EventKind::Query));
        s.push(rec("y.test", "(unattributed)", 0, Source::Npcap, EventKind::Query));
        let f = ViewFilter::default();
        // Unattributed rows are hidden unless explicitly enabled.
        assert_eq!(s.count_matching(&f), 1);
        let f = ViewFilter {
            show_unattributed: true,
            ..Default::default()
        };
        assert_eq!(s.count_matching(&f), 2);
    }

    #[test]
    fn ring_evicts_oldest() {
        let mut s = Store::new(3);
        for i in 0..5 {
            s.push(rec(&format!("d{i}.test"), "a.exe", 1, Source::Etw, EventKind::Query));
        }
        assert_eq!(s.len(), 3);
        assert_eq!(s.stats.evicted, 2);
        assert_eq!(s.stats.total_records, 5);
    }

    #[test]
    fn stats_track_uniques() {
        let mut s = Store::new(100);
        s.push(rec("a.test", "x.exe", 1, Source::Etw, EventKind::Query));
        s.push(rec("a.test", "x.exe", 1, Source::Etw, EventKind::Query));
        s.push(rec("b.test", "y.exe", 2, Source::Npcap, EventKind::Query));
        assert_eq!(s.stats.unique_domain_count(), 2);
        assert_eq!(s.stats.unique_process_count(), 2);
        assert_eq!(s.stats.by_source.get("ETW"), Some(&2));
    }

    #[test]
    fn ip_cache_round_trip() {
        let mut c = IpCache::new(1000, 10);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        c.insert("a.test", &[ip], 1000);
        assert_eq!(c.name_for_ip(&ip, 1500), Some("a.test"));
        // Past the TTL it must be gone.
        assert_eq!(c.name_for_ip(&ip, 3000), None);
        assert_eq!(c.ips_for_name("a.test"), Some(&[ip][..]));
    }

    #[test]
    fn process_name_allow_list() {
        let mut s = Store::new(100);
        s.push(rec("a.test", "BaiduNetdisk.exe", 10, Source::Etw, EventKind::Query));
        s.push(rec("b.test", "BaiduNetdiskHost.exe", 11, Source::Etw, EventKind::Query));
        s.push(rec("c.test", "BaiduNetdiskHost.exe", 12, Source::Etw, EventKind::Query));
        s.push(rec("d.test", "unrelated.exe", 13, Source::Etw, EventKind::Query));

        // Nothing selected: everything is shown.
        let f = ViewFilter::default();
        assert_eq!(s.count_matching(&f), 4);

        // Narrow to the download helper only.
        let mut f = ViewFilter::default();
        f.toggle_process_name("BaiduNetdiskHost.exe");
        assert_eq!(s.count_matching(&f), 2);
        assert!(f.is_active());

        // Matching is case-insensitive, and covers every PID with that name --
        // a helper that runs one instance per download keeps matching.
        let mut f = ViewFilter::default();
        f.process_names.insert("baidunetdisklost.exe".into());
        f.process_names.clear();
        f.process_names.insert("baidunetdiskhost.exe".into());
        assert_eq!(s.count_matching(&f), 2);

        // Toggling twice removes it.
        let mut f = ViewFilter::default();
        f.toggle_process_name("BaiduNetdiskHost.exe");
        f.toggle_process_name("baidunetdiskhost.exe");
        assert!(!f.is_active());
        assert_eq!(s.count_matching(&f), 4);
    }

    #[test]
    fn process_summary_groups_by_name_across_pids() {
        let mut s = Store::new(100);
        s.push(rec("a.test", "host.exe", 1, Source::Etw, EventKind::Query));
        s.push(rec("b.test", "host.exe", 2, Source::Etw, EventKind::Query));
        s.push(rec("c.test", "main.exe", 3, Source::Etw, EventKind::Query));
        let summary = s.process_summary();
        assert_eq!(summary.len(), 2, "one entry per image name");
        assert_eq!(summary[0].0, "host.exe");
        assert_eq!(summary[0].1, 2, "counts from every pid");
    }

    #[test]
    fn ip_query_parsing() {
        assert_eq!(
            parse_ip_query("10.0.0.0/8"),
            IpQuery::Network { base: "10.0.0.0".parse().unwrap(), prefix: 8 }
        );
        assert_eq!(
            parse_ip_query("2606:4700::/32"),
            IpQuery::Network { base: "2606:4700::".parse().unwrap(), prefix: 32 }
        );
        assert_eq!(
            parse_ip_query("10.0.0.5"),
            IpQuery::Exact("10.0.0.5".parse().unwrap())
        );
        // An out-of-range prefix is not a network; it falls back to text so the
        // box still does something sensible.
        assert_eq!(
            parse_ip_query("10.0.0.0/99"),
            IpQuery::Substring("10.0.0.0/99".into())
        );
        assert_eq!(parse_ip_query("104.16."), IpQuery::Substring("104.16.".into()));
    }

    #[test]
    fn network_membership() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(in_network(ip("10.1.2.3"), ip("10.0.0.0"), 8));
        assert!(!in_network(ip("11.1.2.3"), ip("10.0.0.0"), 8));
        assert!(in_network(ip("10.0.0.0"), ip("0.0.0.0"), 0), "/0 matches everything");
        assert!(in_network(ip("2606:4700::1"), ip("2606:4700::"), 32));
        assert!(!in_network(ip("2606:4701::1"), ip("2606:4700::"), 32));
        // Address families never mix.
        assert!(!in_network(ip("10.0.0.1"), ip("::"), 0));
    }

    #[test]
    fn ip_filter_narrows_the_list() {
        let mut s = Store::new(100);
        let mut a = rec("a.test", "p.exe", 1, Source::Etw, EventKind::Query);
        a.resolved = vec!["104.16.1.1".parse().unwrap(), "2606:4700::1".parse().unwrap()];
        let mut b = rec("b.test", "p.exe", 1, Source::Etw, EventKind::Query);
        b.resolved = vec!["20.205.243.166".parse().unwrap()];
        let c = rec("c.test", "p.exe", 1, Source::Etw, EventKind::Query);
        s.push(a);
        s.push(b);
        s.push(c);

        let f = |ip: &str| ViewFilter { ip: ip.into(), ..Default::default() };
        assert_eq!(s.count_matching(&f("104.16.0.0/12")), 1, "CDN range");
        assert_eq!(s.count_matching(&f("104.16.1.1")), 1, "exact v4");
        assert_eq!(s.count_matching(&f("2606:4700::/32")), 1, "v6 range");
        assert_eq!(s.count_matching(&f("2606:")), 1, "substring while typing");
        assert_eq!(s.count_matching(&f("192.168.")), 0);
    }

    #[test]
    fn top_domains_sorted() {
        let mut s = Store::new(100);
        s.push(rec("a", "p", 1, Source::Etw, EventKind::Query));
        s.push(rec("b", "p", 1, Source::Etw, EventKind::Query));
        s.push(rec("b", "p", 1, Source::Etw, EventKind::Query));
        let t = s.top_domains(5);
        assert_eq!(t[0], ("b".to_string(), 2));
    }
}
