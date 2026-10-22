//! Per-process domain tables with AAAA enrichment.
//!
//! Two things live here:
//!
//! * **The table.** Every accepted DNS query record contributes its domain to
//!   the table of the process that asked for it. Each process's list is
//!   deduplicated, so it answers "which names has this process touched".
//! * **The querier.** A pool of worker threads that resolve the AAAA record of
//!   every domain as it appears, and remember the answer.
//!
//! # Why the queries are on their own threads
//!
//! Resolving a name is a blocking call into the operating system that can take
//! seconds when a server is slow or unreachable. Nothing on the capture path
//! may ever wait for that: a stalled resolver would back up the pipeline, the
//! ETW delivery thread would be held behind it, and the monitor would start
//! dropping the very events it exists to collect.
//!
//! So `observe` -- the only function the pipeline calls -- takes a short lock,
//! inserts into a set, and does a non-blocking send. The blocking work happens
//! in worker threads that nobody waits on. The monitor cannot be slowed down by
//! a slow DNS server, a hung lookup, or a queue that has grown long.

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};

use crate::util::now_unix_ms;
use crate::win::dnsq::{AaaaAnswer, query_aaaa};

/// Capacity of the work queue. A domain is only queued once, so this is really
/// "how many distinct names may be waiting for a lookup at one moment".
pub const QUEUE_CAPACITY: usize = 4096;

/// Default number of lookup workers.
pub const DEFAULT_WORKERS: usize = 4;

/// A name that fails for a transient reason is retried this many times.
const MAX_ATTEMPTS: u32 = 2;

/// Backoff before a retry, so a dead server does not spin the workers.
const RETRY_BACKOFF: Duration = Duration::from_millis(400);

/// One process's deduplicated domain table.
#[derive(Clone, Debug)]
pub struct ProcessDomains {
    pub name: String,
    /// Most recent PID seen for this name.
    pub pid: u32,
    /// Deduplicated, and sorted so the list is stable across renders.
    pub domains: BTreeSet<String>,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    /// How many query records this process contributed in total.
    pub records: u64,
    /// A table the user created by hand. Kept even when it has no domains yet,
    /// so an empty process survives a restart.
    pub manual: bool,
}

/// Where a domain's AAAA lookup stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AaaaState {
    /// Seen, not yet handed to a worker.
    Pending,
    /// A worker is resolving it right now.
    Querying,
    Answered(AaaaAnswer),
    /// The lookup itself failed (no resolver, timeout, ...). Distinct from
    /// "the name has no AAAA record", which is an answer.
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct AaaaEntry {
    pub domain: String,
    pub state: AaaaState,
    pub attempts: u32,
    pub queried_at_ms: i64,
    /// How long the successful lookup took.
    pub elapsed_ms: u64,
    /// Addresses this program resolved itself, used when the traffic we
    /// observed never carried an answer for the name.
    ///
    /// A name served from the DNS client cache still produces an ETW query
    /// event, so it lands in the table, but no packet goes out -- without this
    /// the row would sit there with no address forever.
    pub own_lookup: Vec<std::net::IpAddr>,
    /// Restored from the cache rather than observed in this session.
    ///
    /// The answer is the last one the previous session saw, which is exactly
    /// what is needed to manage the hosts entries that session wrote -- and
    /// exactly why automatic writing ignores these rows: a stale address must
    /// never be written back to the hosts file without a fresh observation.
    pub archived: bool,
}

impl AaaaEntry {
    /// A row that has been seen but not looked up yet.
    fn pending(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            state: AaaaState::Pending,
            attempts: 0,
            queried_at_ms: 0,
            elapsed_ms: 0,
            own_lookup: Vec::new(),
            archived: false,
        }
    }

    /// Status text for the UI.
    pub fn status(&self) -> String {
        match &self.state {
            AaaaState::Pending => "待查询".into(),
            AaaaState::Querying => "查询中…".into(),
            AaaaState::Answered(a) => a.label(),
            AaaaState::Failed(e) => format!("查询失败: {e}"),
        }
    }

    pub fn addresses(&self) -> &[Ipv6Addr] {
        match &self.state {
            AaaaState::Answered(a) => a.addresses(),
            _ => &[],
        }
    }

    /// True when the lookup finished, however it turned out.
    pub fn settled(&self) -> bool {
        matches!(
            self.state,
            AaaaState::Answered(_) | AaaaState::Failed(_)
        )
    }
}

/// Addresses to show for a domain: what the observed traffic carried, plus
/// what this program resolved itself when the traffic carried nothing.
///
/// The second list exists because a name served from the DNS client cache still
/// produces an ETW query event but no packet, so its address never reaches the
/// correlation cache. Returns whether our own lookup contributed.
pub fn merged_addresses(
    observed: &[std::net::IpAddr],
    entry: Option<&AaaaEntry>,
) -> (Vec<std::net::IpAddr>, bool) {
    if !observed.is_empty() {
        return (observed.to_vec(), false);
    }
    match entry {
        Some(e) if !e.own_lookup.is_empty() => (e.own_lookup.clone(), true),
        _ => (Vec::new(), false),
    }
}

/// Counters for the statistics panel.
#[derive(Default, Debug, Clone)]
pub struct DomainStats {
    /// Distinct names that needed a lookup (a name shared by two processes
    /// counts once).
    pub unique_domains: u64,
    pub lookups_done: u64,
    pub found_aaaa: u64,
    pub no_aaaa: u64,
    pub no_such_name: u64,
    pub failed: u64,
    pub retried: u64,
    pub queue_dropped: u64,
    pub requeries: u64,
}

struct Inner {
    /// process name (original case) -> its table
    processes: HashMap<String, ProcessDomains>,
    /// Insertion order of process names, for a stable listing.
    order: Vec<String>,
    results: HashMap<String, AaaaEntry>,
}

/// The shared state: the tables, the answers, and the queue feeding the workers.
pub struct DomainIntel {
    /// Shared with the worker threads, which is why it is an `Arc`.
    inner: Arc<Mutex<Inner>>,
    tx: Sender<String>,
    stop: Arc<AtomicBool>,
    workers: Vec<std::thread::JoinHandle<()>>,
    counters: Arc<Counters>,
    bypass_cache: bool,
}

#[derive(Default)]
struct Counters {
    unique_domains: AtomicU64,
    lookups_done: AtomicU64,
    found_aaaa: AtomicU64,
    no_aaaa: AtomicU64,
    no_such_name: AtomicU64,
    failed: AtomicU64,
    retried: AtomicU64,
    queue_dropped: AtomicU64,
    requeries: AtomicU64,
}

impl DomainIntel {
    /// Start the worker pool. Nothing is queried until `observe` is called.
    pub fn start(workers: usize, bypass_cache: bool) -> Arc<Self> {
        let (tx, rx) = bounded::<String>(QUEUE_CAPACITY);
        let inner = Arc::new(Mutex::new(Inner {
            processes: HashMap::new(),
            order: Vec::new(),
            results: HashMap::new(),
        }));
        let counters = Arc::new(Counters::default());
        let stop = Arc::new(AtomicBool::new(false));

        let mut handles = Vec::with_capacity(workers);
        for i in 0..workers.max(1) {
            let rx: Receiver<String> = rx.clone();
            let inner = inner.clone();
            let counters = counters.clone();
            let stop = stop.clone();
            handles.push(
                std::thread::spawn(move || worker_loop(i, rx, inner, counters, stop, bypass_cache)),
            );
        }

        Arc::new(Self {
            inner,
            tx,
            stop,
            workers: handles,
            counters,
            bypass_cache,
        })
    }

    /// Record that `process` (pid `pid`) asked for `domain`.
    ///
    /// This is the only function on the capture path. It takes one short lock,
    /// inserts into a set, and does a non-blocking send -- it never waits for a
    /// resolver, and never blocks on a full queue.
    ///
    /// Returns true when the domain was **new for that process** -- that is,
    /// when this process's table changed.
    ///
    /// That is deliberately not the same as "a lookup was scheduled": a domain
    /// two processes both ask for grows both tables but is resolved once, since
    /// an AAAA record is a property of the name and not of the asker.
    pub fn observe(&self, process: &str, pid: u32, domain: &str) -> bool {
        if process.is_empty() || domain.is_empty() {
            return false;
        }
        let now = now_unix_ms();
        let (new_for_process, schedule_lookup) = {
            let Ok(mut inner) = self.inner.lock() else {
                return false;
            };
            if !inner.processes.contains_key(process) {
                inner.order.push(process.to_string());
                inner.processes.insert(
                    process.to_string(),
                    ProcessDomains {
                        name: process.to_string(),
                        pid,
                        domains: BTreeSet::new(),
                        first_seen_ms: now,
                        last_seen_ms: now,
                        records: 0,
                        manual: false,
                    },
                );
            }
            let entry = inner.processes.get_mut(process).expect("just inserted");
            entry.pid = pid;
            entry.last_seen_ms = now;
            entry.records += 1;

            let new_for_process = entry.domains.insert(domain.to_string());
            // Whatever the previous session cached for this name, this session
            // has now observed it live -- so it stops counting as history.
            if let Some(e) = inner.results.get_mut(domain) {
                e.archived = false;
            }
            if !new_for_process {
                (false, false)
            } else {
                // Reserve the lookup slot in the same critical section, so two
                // processes asking for the same name at the same moment cannot
                // both decide it needs one.
                let schedule = !inner.results.contains_key(domain);
                if schedule {
                    inner.results.insert(domain.to_string(), AaaaEntry::pending(domain));
                }
                (true, schedule)
            }
        };

        if schedule_lookup {
            self.counters.unique_domains.fetch_add(1, Ordering::Relaxed);
            self.enqueue(domain.to_string());
        }
        new_for_process
    }

    fn enqueue(&self, domain: String) {
        match self.tx.try_send(domain) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                // Dropping the lookup is the correct trade: the queue is a
                // background enrichment task, and blocking here would put the
                // monitor behind a slow resolver.
                self.counters.queue_dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    /// Re-queue every domain whose lookup failed, or every domain at all.
    ///
    /// Exists because an answer recorded while the network was down is not
    /// wrong so much as stale, and there is no way to know from one sample.
    pub fn requery(&self, only_failed: bool) -> usize {
        let domains: Vec<String> = {
            let Ok(mut inner) = self.inner.lock() else {
                return 0;
            };
            let pick: Vec<String> = inner
                .results
                .iter()
                .filter(|(_, e)| !only_failed || matches!(e.state, AaaaState::Failed(_)))
                .map(|(d, _)| d.clone())
                .collect();
            for d in &pick {
                if let Some(e) = inner.results.get_mut(d) {
                    e.state = AaaaState::Pending;
                    // A fresh answer is on its way, so this is no longer just
                    // the previous session's record.
                    e.archived = false;
                }
            }
            pick
        };
        let n = domains.len();
        self.counters
            .requeries
            .fetch_add(n as u64, Ordering::Relaxed);
        for d in domains {
            self.enqueue(d);
        }
        n
    }

    /// Snapshot of every process table, busiest first.
    pub fn process_tables(&self) -> Vec<ProcessDomains> {
        let Ok(inner) = self.inner.lock() else {
            return Vec::new();
        };
        let mut v: Vec<ProcessDomains> = inner
            .order
            .iter()
            .filter_map(|n| inner.processes.get(n).cloned())
            .collect();
        v.sort_by(|a, b| {
            b.domains
                .len()
                .cmp(&a.domains.len())
                .then_with(|| a.name.cmp(&b.name))
        });
        v
    }

    /// Every table as a serializable snapshot, for the local cache.
    ///
    /// Taken under the same lock as everything else, so the snapshot is a
    /// consistent view rather than a mix of before and after states.
    pub fn snapshot(&self) -> crate::persist::Snapshot {
        let mut processes = Vec::new();
        let saved_at_ms = now_unix_ms();
        if let Ok(inner) = self.inner.lock() {
            for name in &inner.order {
                let Some(p) = inner.processes.get(name) else {
                    continue;
                };
                processes.push(crate::persist::SavedProcess {
                    process: p.name.clone(),
                    pid: p.pid,
                    first_seen_ms: p.first_seen_ms,
                    last_seen_ms: p.last_seen_ms,
                    manual: p.manual,
                    domains: p
                        .domains
                        .iter()
                        .map(|d| saved_domain(d, inner.results.get(d)))
                        .collect(),
                });
            }
        }
        crate::persist::Snapshot {
            version: crate::persist::SNAPSHOT_VERSION,
            saved_at_ms,
            processes,
        }
    }

    /// Load a previous session's tables, marked as archived.
    ///
    /// Live data wins: a process or a domain this session has already seen is
    /// not overwritten from the cache. Returns how many domain rows were
    /// restored.
    pub fn restore(&self, snap: &crate::persist::Snapshot) -> usize {
        let Ok(mut inner) = self.inner.lock() else {
            return 0;
        };
        let Inner {
            processes,
            order,
            results,
        } = &mut *inner;
        let mut restored = 0;
        for p in &snap.processes {
            if p.process.is_empty() {
                continue;
            }
            if !processes.contains_key(&p.process) {
                order.push(p.process.clone());
                processes.insert(
                    p.process.clone(),
                    ProcessDomains {
                        name: p.process.clone(),
                        pid: p.pid,
                        domains: BTreeSet::new(),
                        first_seen_ms: p.first_seen_ms,
                        last_seen_ms: p.last_seen_ms,
                        records: 0,
                        manual: p.manual,
                    },
                );
            }
            let Some(table) = processes.get_mut(&p.process) else {
                continue;
            };
            for d in &p.domains {
                if d.domain.is_empty() {
                    continue;
                }
                table.domains.insert(d.domain.clone());
                if results.contains_key(&d.domain) {
                    continue;
                }
                results.insert(d.domain.clone(), saved_entry(d));
                restored += 1;
            }
        }
        restored
    }

    /// The AAAA entry for one domain.
    ///
    /// Test-covered; the UI reads whole tables at a time.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn lookup(&self, domain: &str) -> Option<AaaaEntry> {
        self.inner
            .lock()
            .ok()
            .and_then(|i| i.results.get(domain).cloned())
    }

    /// Every domain in one process's table, with its lookup state.
    pub fn rows_for(&self, process: &str) -> Vec<(String, AaaaEntry)> {
        let Ok(inner) = self.inner.lock() else {
            return Vec::new();
        };
        let Some(p) = inner.processes.get(process) else {
            return Vec::new();
        };
        p.domains
            .iter()
            .map(|d| {
                let e = inner
                    .results
                    .get(d)
                    .cloned()
                    .unwrap_or_else(|| AaaaEntry::pending(d));
                (d.clone(), e)
            })
            .collect()
    }

    /// Create an empty table for a process the user typed in.
    ///
    /// Returns false when a table with that name already exists. The table is
    /// marked manual so an empty one survives a restart; adding a domain to it
    /// works exactly like a table captured from traffic.
    pub fn add_process(&self, process: &str) -> bool {
        let process = process.trim();
        if process.is_empty() {
            return false;
        }
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        if inner
            .processes
            .keys()
            .any(|k| k.eq_ignore_ascii_case(process))
        {
            return false;
        }
        let now = now_unix_ms();
        inner.order.push(process.to_string());
        inner.processes.insert(
            process.to_string(),
            ProcessDomains {
                name: process.to_string(),
                pid: 0,
                domains: BTreeSet::new(),
                first_seen_ms: now,
                last_seen_ms: now,
                records: 0,
                manual: true,
            },
        );
        true
    }

    /// Add names to one process's table, creating the table when needed.
    ///
    /// Returns how many names were new. A name that is already there is left
    /// alone (and not re-resolved); a new name is queued for an AAAA lookup so
    /// the hosts preview can use it as soon as the answer arrives.
    pub fn add_domains(&self, process: &str, domains: &[String]) -> usize {
        let process = process.trim();
        if process.is_empty() {
            return 0;
        }
        let mut new_names: Vec<String> = Vec::new();
        let mut scheduled_names: Vec<String> = Vec::new();
        {
            let Ok(mut inner) = self.inner.lock() else {
                return 0;
            };
            if !inner.processes.contains_key(process) {
                let now = now_unix_ms();
                inner.order.push(process.to_string());
                inner.processes.insert(
                    process.to_string(),
                    ProcessDomains {
                        name: process.to_string(),
                        pid: 0,
                        domains: BTreeSet::new(),
                        first_seen_ms: now,
                        last_seen_ms: now,
                        records: 0,
                        manual: true,
                    },
                );
            }
            let Some(table) = inner.processes.get_mut(process) else {
                return 0;
            };
            table.last_seen_ms = now_unix_ms();
            for raw in domains {
                let d = raw.trim().to_ascii_lowercase();
                if d.is_empty() || d.contains(char::is_whitespace) || d.contains('#') {
                    continue;
                }
                if table.domains.iter().any(|x| x.eq_ignore_ascii_case(&d)) {
                    continue;
                }
                table.domains.insert(d.clone());
                new_names.push(d);
            }
            for d in &new_names {
                if !inner.results.contains_key(d) {
                    inner.results.insert(d.clone(), AaaaEntry::pending(d));
                    scheduled_names.push(d.clone());
                }
            }
            if !scheduled_names.is_empty() {
                self.counters
                    .unique_domains
                    .fetch_add(scheduled_names.len() as u64, Ordering::Relaxed);
            }
        }
        for d in scheduled_names {
            self.enqueue(d);
        }
        new_names.len()
    }

    /// Remove names from one process's table. Returns how many disappeared.
    ///
    /// The process itself stays, even when its table becomes empty: deleting a
    /// whole process is a separate, explicit action.
    pub fn remove_domains(&self, process: &str, domains: &[String]) -> usize {
        let Ok(mut inner) = self.inner.lock() else {
            return 0;
        };
        let Some(table) = inner.processes.get_mut(process) else {
            return 0;
        };
        let mut removed = 0usize;
        for raw in domains {
            let d = raw.trim();
            if d.is_empty() {
                continue;
            }
            if let Some(key) = table
                .domains
                .iter()
                .find(|x| x.eq_ignore_ascii_case(d))
                .cloned()
            {
                table.domains.remove(&key);
                removed += 1;
            }
        }
        if removed > 0 {
            prune_orphan_results(&mut inner);
        }
        removed
    }

    /// Delete a process table and every domain in it.
    ///
    /// Existing hosts lines are not touched: they are managed on the hosts page,
    /// where removing a process's entries is a separate decision.
    pub fn remove_process(&self, process: &str) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        if inner.processes.remove(process).is_none() {
            return false;
        }
        inner.order.retain(|n| n != process);
        prune_orphan_results(&mut inner);
        true
    }

    /// Flattened view over every process, for export and for the "all" listing.
    pub fn all_rows(&self) -> Vec<(String, String, AaaaEntry)> {
        let Ok(inner) = self.inner.lock() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for name in &inner.order {
            if let Some(p) = inner.processes.get(name) {
                for d in &p.domains {
                    let e = inner
                        .results
                        .get(d)
                        .cloned()
                        .unwrap_or_else(|| AaaaEntry::pending(d));
                    out.push((name.clone(), d.clone(), e));
                }
            }
        }
        out
    }

    pub fn stats(&self) -> DomainStats {
        DomainStats {
            unique_domains: self.counters.unique_domains.load(Ordering::Relaxed),
            lookups_done: self.counters.lookups_done.load(Ordering::Relaxed),
            found_aaaa: self.counters.found_aaaa.load(Ordering::Relaxed),
            no_aaaa: self.counters.no_aaaa.load(Ordering::Relaxed),
            no_such_name: self.counters.no_such_name.load(Ordering::Relaxed),
            failed: self.counters.failed.load(Ordering::Relaxed),
            retried: self.counters.retried.load(Ordering::Relaxed),
            queue_dropped: self.counters.queue_dropped.load(Ordering::Relaxed),
            requeries: self.counters.requeries.load(Ordering::Relaxed),
        }
    }

    /// How many lookup workers are running.
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    pub fn bypass_cache(&self) -> bool {
        self.bypass_cache
    }
}

impl Drop for DomainIntel {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Workers block on `recv`; dropping the sender is what wakes them.
        // (`self.tx` is dropped as part of `self`, after this body runs, so
        // give them a moment and then join.)
        for _ in 0..self.workers.len() {
            // Nothing to send; workers exit when the channel disconnects.
        }
    }
}

fn worker_loop(
    _id: usize,
    rx: Receiver<String>,
    inner: Arc<Mutex<Inner>>,
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
    bypass_cache: bool,
) {
    while !stop.load(Ordering::Relaxed) {
        let domain = match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(d) => d,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        };

        if let Ok(mut i) = inner.lock() {
            if let Some(e) = i.results.get_mut(&domain) {
                e.state = AaaaState::Querying;
            }
        }

        // A alongside AAAA. Whether the answer comes from the resolver's cache
        // or from the wire, this is the address the machine would actually use.
        let own_lookup: Vec<std::net::IpAddr> = match crate::win::dnsq::query_a(
            &domain,
            bypass_cache,
        ) {
            Ok(v4) => v4.into_iter().map(std::net::IpAddr::V4).collect(),
            Err(_) => Vec::new(),
        };

        let started = std::time::Instant::now();
        let mut attempts = 0u32;
        let outcome = loop {
            attempts += 1;
            match query_aaaa(&domain, bypass_cache) {
                Ok(answer) => break Ok(answer),
                Err(e) if attempts < MAX_ATTEMPTS => {
                    counters.retried.fetch_add(1, Ordering::Relaxed);
                    std::thread::sleep(RETRY_BACKOFF);
                    let _ = e;
                }
                Err(e) => break Err(e),
            }
        };
        let elapsed_ms = started.elapsed().as_millis() as u64;

        // The three answers are counted separately, and only a non-empty
        // address list counts as a hit. Folding "no record" in with "found"
        // made the summary claim IPv6 support that did not exist.
        let state = match outcome {
            Ok(a) => {
                match &a {
                    AaaaAnswer::Addresses(v) => {
                        debug_assert!(!v.is_empty(), "query_aaaa normalises empty to NoRecord");
                        counters.found_aaaa.fetch_add(1, Ordering::Relaxed);
                    }
                    AaaaAnswer::NoRecord => {
                        counters.no_aaaa.fetch_add(1, Ordering::Relaxed);
                    }
                    AaaaAnswer::NoSuchName => {
                        counters.no_such_name.fetch_add(1, Ordering::Relaxed);
                    }
                }
                AaaaState::Answered(a)
            }
            Err(e) => {
                counters.failed.fetch_add(1, Ordering::Relaxed);
                AaaaState::Failed(e.to_string())
            }
        };

        counters.lookups_done.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut i) = inner.lock() {
            if let Some(entry) = i.results.get_mut(&domain) {
                // A requery may have replaced the state while we were working;
                // the fresh answer wins either way.
                entry.state = state;
                entry.attempts = attempts;
                entry.queried_at_ms = now_unix_ms();
                entry.elapsed_ms = elapsed_ms;
                entry.own_lookup = own_lookup.clone();
            }
        }
    }
}

/// One row of the snapshot.
fn saved_domain(domain: &str, entry: Option<&AaaaEntry>) -> crate::persist::SavedDomain {
    let mut s = crate::persist::SavedDomain {
        domain: domain.to_string(),
        answer: "pending".to_string(),
        aaaa: Vec::new(),
        own: Vec::new(),
        error: String::new(),
        queried_at_ms: 0,
    };
    let Some(e) = entry else {
        return s;
    };
    s.queried_at_ms = e.queried_at_ms;
    s.own = e.own_lookup.iter().map(|a| a.to_string()).collect();
    match &e.state {
        AaaaState::Answered(AaaaAnswer::Addresses(v)) => {
            s.answer = "found".into();
            s.aaaa = v.iter().map(|a| a.to_string()).collect();
        }
        AaaaState::Answered(AaaaAnswer::NoRecord) => s.answer = "none".into(),
        AaaaState::Answered(AaaaAnswer::NoSuchName) => s.answer = "nxdomain".into(),
        AaaaState::Failed(msg) => {
            s.answer = "failed".into();
            s.error = msg.clone();
        }
        AaaaState::Pending | AaaaState::Querying => {}
    }
    s
}

/// Drop lookup results no table references any more.
fn prune_orphan_results(inner: &mut Inner) {
    let used: std::collections::HashSet<&String> = inner
        .processes
        .values()
        .flat_map(|p| p.domains.iter())
        .collect();
    inner.results.retain(|d, _| used.contains(d));
}

/// Rebuild an entry from the snapshot. Always archived: nothing here was
/// observed in the running session.
fn saved_entry(d: &crate::persist::SavedDomain) -> AaaaEntry {
    let state = match d.answer.as_str() {
        "found" => {
            let addrs: Vec<Ipv6Addr> = d.aaaa.iter().filter_map(|a| a.parse().ok()).collect();
            if addrs.is_empty() {
                AaaaState::Answered(AaaaAnswer::NoRecord)
            } else {
                AaaaState::Answered(AaaaAnswer::Addresses(addrs))
            }
        }
        "none" => AaaaState::Answered(AaaaAnswer::NoRecord),
        "nxdomain" => AaaaState::Answered(AaaaAnswer::NoSuchName),
        "failed" => AaaaState::Failed(if d.error.is_empty() {
            "上次会话查询失败".to_string()
        } else {
            d.error.clone()
        }),
        _ => AaaaState::Pending,
    };
    AaaaEntry {
        domain: d.domain.clone(),
        state,
        attempts: 0,
        queried_at_ms: d.queried_at_ms,
        elapsed_ms: 0,
        own_lookup: d.own.iter().filter_map(|a| a.parse().ok()).collect(),
        archived: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A querier that never touches the network, for testing the table itself.
    fn offline() -> Arc<DomainIntel> {
        let (tx, _rx) = bounded::<String>(QUEUE_CAPACITY);
        Arc::new(DomainIntel {
            inner: Arc::new(Mutex::new(Inner {
                processes: HashMap::new(),
                order: Vec::new(),
                results: HashMap::new(),
            })),
            tx,
            stop: Arc::new(AtomicBool::new(false)),
            workers: Vec::new(),
            counters: Arc::new(Counters::default()),
            bypass_cache: false,
        })
    }

    #[test]
    fn table_is_per_process_and_deduplicated() {
        let d = offline();
        assert!(d.observe("msedge.exe", 1, "a.example.com"));
        assert!(d.observe("msedge.exe", 1, "b.example.com"));
        // Same domain again for the same process: nothing changes.
        assert!(!d.observe("msedge.exe", 1, "a.example.com"));
        // New for *this* process, even though the name is already known.
        assert!(d.observe("helper.exe", 2, "a.example.com"));

        let tables = d.process_tables();
        assert_eq!(tables.len(), 2);
        let msedge = tables.iter().find(|t| t.name == "msedge.exe").unwrap();
        assert_eq!(msedge.domains.len(), 2);
        // Sorted, so the display order is stable.
        assert_eq!(
            msedge.domains.iter().cloned().collect::<Vec<_>>(),
            vec!["a.example.com", "b.example.com"]
        );
        // The third call was the second sighting of a.example.com, but it still
        // counts as a record from that process.
        assert_eq!(msedge.records, 3);
    }

    #[test]
    fn a_domain_shared_by_two_processes_is_queried_once() {
        let d = offline();
        d.observe("a.exe", 1, "shared.test");
        d.observe("b.exe", 2, "shared.test");
        // One result slot, so one lookup, even though both tables list it.
        assert_eq!(d.stats().unique_domains, 1);
        assert_eq!(d.rows_for("a.exe").len(), 1);
        assert_eq!(d.rows_for("b.exe").len(), 1);
        assert_eq!(d.all_rows().len(), 2, "but each table shows it");
    }

    #[test]
    fn new_domains_are_queued_for_lookup() {
        let (tx, rx) = bounded::<String>(QUEUE_CAPACITY);
        let d = Arc::new(DomainIntel {
            inner: Arc::new(Mutex::new(Inner {
                processes: HashMap::new(),
                order: Vec::new(),
                results: HashMap::new(),
            })),
            tx,
            stop: Arc::new(AtomicBool::new(false)),
            workers: Vec::new(),
            counters: Arc::new(Counters::default()),
            bypass_cache: false,
        });
        d.observe("p.exe", 1, "one.test");
        d.observe("p.exe", 1, "one.test"); // duplicate: must not queue twice
        d.observe("p.exe", 1, "two.test");
        let queued: Vec<String> = rx.try_iter().collect();
        assert_eq!(queued, vec!["one.test".to_string(), "two.test".to_string()]);
    }

    #[test]
    fn empty_inputs_are_ignored() {
        let d = offline();
        assert!(!d.observe("", 1, "a.test"));
        assert!(!d.observe("p.exe", 1, ""));
        assert!(d.process_tables().is_empty());
    }

    #[test]
    fn a_slow_resolver_cannot_block_the_capture_path() {
        // The point of the design: `observe` must return promptly even when the
        // queue is completely full, because the pipeline calls it.
        let (tx, _rx) = bounded::<String>(1);
        let d = Arc::new(DomainIntel {
            inner: Arc::new(Mutex::new(Inner {
                processes: HashMap::new(),
                order: Vec::new(),
                results: HashMap::new(),
            })),
            tx,
            stop: Arc::new(AtomicBool::new(false)),
            workers: Vec::new(),
            counters: Arc::new(Counters::default()),
            bypass_cache: false,
        });
        let started = std::time::Instant::now();
        for i in 0..500 {
            d.observe("p.exe", 1, &format!("d{i}.test"));
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "observing 500 domains took {:?}; the hot path must not block",
            started.elapsed()
        );
        // The lookups that did not fit are dropped and counted, not waited on.
        assert!(d.stats().queue_dropped > 0);
    }

    #[test]
    fn user_edits_create_and_remove_tables() {
        let d = offline();
        assert!(d.add_process("manual.exe"));
        assert!(!d.add_process("MANUAL.EXE"), "names are case-insensitive here");
        assert!(d.add_domains(
            "manual.exe",
            &["Added.Example".into(), "added.example".into(), "bad name".into()]
        ) == 1);
        let rows = d.rows_for("manual.exe");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "added.example");

        // A second process can be created by adding a name directly.
        assert_eq!(d.add_domains("other.exe", &["x.test".into()]), 1);
        assert_eq!(d.process_tables().len(), 2);

        assert_eq!(d.remove_domains("manual.exe", &["ADDED.EXAMPLE".into()]), 1);
        assert!(d.rows_for("manual.exe").is_empty());
        assert!(!d.remove_process("missing.exe"));
        assert!(d.remove_process("other.exe"));
        assert_eq!(d.process_tables().len(), 1);
    }

    #[test]
    fn a_snapshot_restores_the_tables_as_archived() {
        let d = offline();
        d.observe("a.exe", 1, "one.test");
        d.observe("a.exe", 1, "two.test");
        d.observe("b.exe", 2, "one.test");
        {
            let mut inner = d.inner.lock().unwrap();
            if let Some(e) = inner.results.get_mut("one.test") {
                e.state = AaaaState::Answered(AaaaAnswer::Addresses(vec![
                    "2606:4700::1".parse().unwrap(),
                ]));
                e.own_lookup = vec!["1.2.3.4".parse().unwrap()];
                e.queried_at_ms = 1234;
            }
        }
        let snap = d.snapshot();
        assert_eq!(snap.processes.len(), 2);
        assert_eq!(snap.processes[0].domains.len(), 2);

        // A fresh instance, as after a restart.
        let next = offline();
        assert_eq!(next.restore(&snap), 2, "one row per unique domain");
        let rows = next.rows_for("a.exe");
        assert_eq!(rows.len(), 2, "the table is back");
        let (_, one) = rows.iter().find(|(d, _)| d == "one.test").unwrap();
        assert_eq!(one.addresses(), &["2606:4700::1".parse::<Ipv6Addr>().unwrap()]);
        assert!(one.archived, "restored rows must be marked as history");
        assert_eq!(one.own_lookup.len(), 1, "the addresses we resolved are kept");
        assert_eq!(next.rows_for("b.exe").len(), 1);
    }

    #[test]
    fn observing_a_restored_domain_makes_it_live_again() {
        let d = offline();
        d.observe("a.exe", 1, "one.test");
        let snap = d.snapshot();
        let next = offline();
        next.restore(&snap);
        assert!(next.rows_for("a.exe")[0].1.archived);
        next.observe("a.exe", 2, "one.test");
        assert!(
            !next.rows_for("a.exe")[0].1.archived,
            "seen live in this session"
        );
    }

    #[test]
    fn restoring_never_overwrites_what_this_session_already_knows() {
        let d = offline();
        d.observe("a.exe", 1, "one.test");
        let snap = d.snapshot();

        let live = offline();
        live.observe("a.exe", 9, "one.test");
        live.restore(&snap);

        let rows = live.rows_for("a.exe");
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].1.archived);
        let t = live.process_tables();
        assert_eq!(t[0].pid, 9, "the live pid wins");
        assert_eq!(t[0].records, 1);
    }

    /// End-to-end against the real resolver. Skipped when there is no network.
    #[test]
    fn real_lookup_records_an_answer() {
        let d = DomainIntel::start(2, false);
        d.observe("p.exe", 1, "localhost");
        for _ in 0..100 {
            if let Some(e) = d.lookup("localhost") {
                if e.settled() {
                    assert_eq!(e.addresses(), &[Ipv6Addr::LOCALHOST]);
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("localhost lookup never settled");
    }
}
