//! The processing stage between capture threads and the UI.
//!
//! Capture threads do the absolute minimum -- parse a name, push a `RawEvent` --
//! and one worker thread does everything expensive: process-tree attribution,
//! duplicate collapsing, IP-cache maintenance and record construction.
//!
//! # Why a channel and not a shared structure
//!
//! The channel is `crossbeam`'s bounded MPMC queue, which is lock-free on the
//! fast path. Capture threads never take a mutex, so they can never be stalled
//! by a slow UI. When the queue is full the send fails immediately and the event
//! is counted as dropped rather than blocking the ETW delivery thread -- losing
//! an event is survivable, stalling `ProcessTrace` is not.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crossbeam_channel::{Receiver, RecvTimeoutError};

use crate::model::{EventKind, RawEvent, Record, Source};
use crate::store::Store;
use crate::util::{fmt_time_ms, qtype_name};
use crate::win::proctree::TreeTracker;

/// Capacity of the capture -> worker queue.
pub const QUEUE_CAPACITY: usize = 262_144;

/// Identical observations within this window collapse into one row.
const DEDUP_WINDOW_MS: i64 = 750;

/// How long a "process P resolved name N" fact stays usable for attributing a
/// later TLS handshake to N.
///
/// This exists because the packet-capture source is inherently racy for short
/// connections: the SNI is read from the first data packet, but by the time the
/// reader asks the kernel's TCP table who owned the socket, a client that sent
/// its ClientHello and closed immediately -- which is exactly what a connection
/// probe, a range request, or a failing handshake looks like -- has already
/// released the port, and the lookup returns nothing.
///
/// Falling back to "this process resolved that name a moment ago" is a
/// correlation, not a measurement, so such rows are labelled as such. It is
/// sound in the direction that matters: the process must already be a member of
/// the target tree for its query to have been recorded at all.
const SNI_CORRELATION_WINDOW_MS: i64 = 60_000;

/// Cap on the name -> pid correlation map.
const SNI_CORRELATION_MAX: usize = 4096;

/// Counters owned by the pipeline.
#[derive(Default)]
pub struct PipelineStats {
    /// Events that arrived after the queue was full.
    pub queue_dropped: AtomicU64,
    pub processed: AtomicU64,
}

/// Handle to the running worker.
pub struct Pipeline {
    handle: Option<std::thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    pub stats: Arc<PipelineStats>,
}

impl Pipeline {
    /// Spawn the worker. `tree` is shared with the watcher thread, which
    /// refreshes membership in the background.
    ///
    /// `include_unattributed` is off by default: an event whose owning process
    /// could not be determined is *not* evidence that the target produced it,
    /// and the contract is to show only the target tree. The switch exists so
    /// the behaviour can be inspected deliberately.
    pub fn spawn(
        rx: Receiver<RawEvent>,
        store: Arc<Mutex<Store>>,
        tree: Arc<Mutex<TreeTracker>>,
        include_unattributed: Arc<AtomicBool>,
        domains: Arc<crate::domains::DomainIntel>,
        observe_domains: bool,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(PipelineStats::default());
        let stop2 = stop.clone();
        let stats2 = stats.clone();

        let handle = std::thread::spawn(move || {
            // (pid, domain, qtype, source) -> last seen (unix ms)
            let mut dedup: HashMap<(u32, String, u16, u8), i64> = HashMap::new();
            // domain -> (pid that resolved it, when). Only ever holds PIDs that
            // already passed the process-tree check.
            let mut resolved_by: HashMap<String, (u32, i64)> = HashMap::new();
            let mut last_gc = crate::util::now_unix_ms();

            loop {
                if stop2.load(Ordering::Relaxed) && rx.is_empty() {
                    break;
                }
                let ev = match rx.recv_timeout(std::time::Duration::from_millis(50)) {
                    Ok(e) => e,
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => break,
                };
                stats2.processed.fetch_add(1, Ordering::Relaxed);

                // ---- responses feed the correlation cache, they are not rows
                if ev.kind == EventKind::Response {
                    let now = crate::util::now_unix_ms();
                    let mut s = store.lock().unwrap();
                    s.ips.insert(&ev.name, &ev.answers, now);
                    s.push(Record {
                        seq: 0,
                        unix_ms: ev.unix_ms(),
                        time: fmt_time_ms(ev.unix_ms()),
                        process: "(dns server)".to_string(),
                        pid: 0,
                        qtype: qtype_name(ev.qtype).to_string(),
                        source: ev.source,
                        kind: EventKind::Response,
                        domain: ev.name.clone(),
                        resolved: Vec::new(),
                        detail: format!(
                            "{} answer(s), rcode {}, id {}",
                            ev.answers.len(),
                            ev.rcode.unwrap_or(0),
                            ev.dns_id
                        ),
                    });
                    continue;
                }

                // ---- process attribution ------------------------------------
                //
                // Only the target application and its descendants are kept.
                if ev.pid == 0 {
                    // No owning process could be established. This is not the
                    // target tree by any evidence we have, so it is dropped
                    // unless the operator explicitly asked to see it.
                    if !include_unattributed.load(Ordering::Relaxed) {
                        let mut s = store.lock().unwrap();
                        s.stats.unattributed += 1;
                        continue;
                    }
                }

                let now = crate::util::now_unix_ms();

                // ---- process attribution ------------------------------------
                //
                // A TLS handshake whose owning socket could not be identified
                // is attributed to whichever in-tree process resolved that name
                // recently. This is a correlation and is labelled as one; it
                // never widens the tree, because only PIDs that already passed
                // the check below are ever recorded in `resolved_by`.
                let mut correlated = false;
                let mut owner_pid = ev.pid;
                if owner_pid == 0 && ev.kind == EventKind::TlsSni {
                    if let Some((pid, at)) = resolved_by.get(&ev.name) {
                        if now - *at < SNI_CORRELATION_WINDOW_MS {
                            owner_pid = *pid;
                            correlated = true;
                        }
                    }
                }

                let (in_tree, proc_name) = {
                    let mut t = tree.lock().unwrap();
                    // "No root yet" normally means nothing to watch, and every
                    // event is rejected. Under `--watch` it means the opposite:
                    // we are waiting for a process to appear, and the event in
                    // hand may be the very first thing it did. Rejecting here
                    // would drop exactly the queries the user armed us for.
                    if t.root().is_none() && t.watch_names().is_empty() {
                        (false, String::new())
                    } else if owner_pid == 0 {
                        (true, "(unattributed)".to_string())
                    } else if t.contains_or_adopt(owner_pid) {
                        (true, t.name_of(owner_pid))
                    } else {
                        (false, String::new())
                    }
                };
                if !in_tree {
                    // Bind the lock once: two `tree.lock()` temporaries in a
                    // single expression both live until the end of the
                    // statement, so the second one deadlocks against the first.
                    let (roots, members) = {
                        let t = tree.lock().unwrap();
                        (t.debug_roots(), t.live_member_count())
                    };
                    crate::util::filter_log(format_args!(
                        "pipeline-reject pid={} name={} roots={:?} members={}",
                        owner_pid, ev.name, roots, members
                    ));
                    let mut s = store.lock().unwrap();
                    s.stats.filtered_out_of_tree += 1;
                    continue;
                }
                crate::util::filter_log(format_args!(
                    "pipeline-accept pid={} name={}", owner_pid, ev.name
                ));

                // ---- duplicate collapsing -----------------------------------
                let src_key = match ev.source {
                    Source::Etw => 0u8,
                    Source::Npcap => 1,
                    Source::Sni => 2,
                };
                let key = (owner_pid, ev.name.clone(), ev.qtype, src_key);
                if let Some(prev) = dedup.get(&key) {
                    if now - *prev < DEDUP_WINDOW_MS {
                        dedup.insert(key, now);
                        let mut s = store.lock().unwrap();
                        s.stats.duplicates += 1;
                        continue;
                    }
                }
                dedup.insert(key, now);

                // Remember who resolved what, for the SNI fallback above.
                if ev.kind == EventKind::Query && owner_pid != 0 {
                    if resolved_by.len() >= SNI_CORRELATION_MAX {
                        resolved_by.retain(|_, (_, at)| now - *at < SNI_CORRELATION_WINDOW_MS);
                    }
                    resolved_by.insert(ev.name.clone(), (owner_pid, now));
                }

                // Bound the maps: drop everything older than its window.
                if now - last_gc > 5_000 {
                    dedup.retain(|_, t| now - *t < DEDUP_WINDOW_MS);
                    resolved_by.retain(|_, (_, at)| now - *at < SNI_CORRELATION_WINDOW_MS);
                    last_gc = now;
                }

                // ---- build the display row ----------------------------------
                // The addresses are kept both structured (for the IP filter)
                // and rendered (for the column), from the same read.
                let (resolved, mut detail) = {
                    let s = store.lock().unwrap();
                    match s.ips.ips_for_name(&ev.name) {
                        Some(ips) if !ips.is_empty() => {
                            let shown: Vec<IpAddr> = ips.iter().take(4).copied().collect();
                            let text = shown
                                .iter()
                                .map(|i| i.to_string())
                                .collect::<Vec<_>>()
                                .join(", ");
                            (shown, text)
                        }
                        _ => (Vec::new(), String::new()),
                    }
                };
                if correlated {
                    if !detail.is_empty() {
                        detail.push_str("  ");
                    }
                    detail.push_str("owner inferred from a recent DNS lookup");
                }

                let rec = Record {
                    seq: 0,
                    unix_ms: ev.unix_ms(),
                    time: fmt_time_ms(ev.unix_ms()),
                    process: proc_name,
                    pid: owner_pid,
                    qtype: if ev.kind == EventKind::TlsSni {
                        "SNI".to_string()
                    } else {
                        qtype_name(ev.qtype).to_string()
                    },
                    source: ev.source,
                    kind: ev.kind,
                    domain: ev.name,
                    resolved,
                    detail,
                };
                // Contribute to the process's domain table. This only takes a
                // short lock and a non-blocking send, so the capture path is
                // never waiting on a resolver.
                if observe_domains && rec.kind == EventKind::Query {
                    domains.observe(&rec.process, rec.pid, &rec.domain);
                }
                store.lock().unwrap().push(rec);
            }
        });

        Self {
            handle: Some(handle),
            stop,
            stats,
        }
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Source;
    use crossbeam_channel::bounded;

    fn ev(pid: u32, name: &str) -> RawEvent {
        RawEvent {
            ts_100ns: crate::util::FILETIME_UNIX_EPOCH + 10_000_000,
            pid,
            name: name.to_string(),
            qtype: 1,
            source: Source::Etw,
            kind: EventKind::Query,
            answers: Vec::new(),
            rcode: None,
            dns_id: 0x1234,
        }
    }

    #[test]
    fn filters_by_process_tree_and_dedups() {
        let (tx, rx) = bounded(QUEUE_CAPACITY);
        let store = Arc::new(Mutex::new(Store::new(1000)));
        let tree = Arc::new(Mutex::new(TreeTracker::new()));

        // No root yet: everything must be rejected.
        // Two workers and no network: these tests are about attribution, not
        // about lookups.
        let mut p = Pipeline::spawn(
            rx,
            store.clone(),
            tree.clone(),
            Arc::new(AtomicBool::new(false)),
            crate::domains::DomainIntel::start(1, false),
            true,
        );
        tx.send(ev(1234, "before-root.test")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(store.lock().unwrap().len(), 0);

        // Adopt this test process as the root, then send from our own PID.
        let me = std::process::id();
        {
            let mut t = tree.lock().unwrap();
            t.set_root(me);
            t.refresh();
            assert!(t.contains(me), "own pid must be a member of its own tree");
        }
        tx.send(ev(me, "in-tree.test")).unwrap();
        tx.send(ev(me, "in-tree.test")).unwrap(); // duplicate within window
        tx.send(ev(999_999, "foreign.test")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(400));

        let s = store.lock().unwrap();
        assert_eq!(s.len(), 1, "only the in-tree query should be stored");
        assert_eq!(s.view(&crate::store::ViewFilter::default(), 10)[0].domain, "in-tree.test");
        assert!(s.stats.duplicates >= 1);
        assert!(s.stats.filtered_out_of_tree >= 1);
        drop(s);

        drop(tx);
        p.stop();
    }

    #[test]
    fn responses_populate_ip_cache() {
        let (tx, rx) = bounded(64);
        let store = Arc::new(Mutex::new(Store::new(100)));
        let tree = Arc::new(Mutex::new(TreeTracker::new()));
        // Two workers and no network: these tests are about attribution, not
        // about lookups.
        let mut p = Pipeline::spawn(
            rx,
            store.clone(),
            tree.clone(),
            Arc::new(AtomicBool::new(false)),
            crate::domains::DomainIntel::start(1, false),
            true,
        );

        let mut e = ev(0, "cached.test");
        e.kind = EventKind::Response;
        e.answers = vec!["10.0.0.1".parse().unwrap()];
        tx.send(e).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));

        let s = store.lock().unwrap();
        assert!(s.ips.ips_for_name("cached.test").is_some());
        drop(s);
        drop(tx);
        p.stop();
    }
}
