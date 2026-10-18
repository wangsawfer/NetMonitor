//! Primary capture source: the ETW `Microsoft-Windows-DNS-Client` provider.
//!
//! # Why this provider
//!
//! It is the only in-box source that reports DNS queries *in the context of the
//! process that asked for the name*. Events 3006 ("query is being issued") and
//! 3008 ("query completed") are written by the calling thread, so
//! `EVENT_HEADER.ProcessId` identifies the application -- not `svchost.exe`.
//! (The provider's *other* events, 3009-3020 and friends, are emitted by the
//! DNS Client service itself and all carry the svchost PID; they are ignored
//! here. This was verified empirically with `--bin etwprobe` on Windows 11
//! 26100: a `ping.exe` for a unique name produced 3006/3008 with exactly the
//! ping process's PID.)
//!
//! # Payload layout (verified, both events)
//!
//! ```text
//! offset 0   : QueryName, NUL-terminated UTF-16LE
//! offset 2*(len+1) : QueryType, u32 LE
//! ...        : provider-private metadata (options, interface index, status)
//! ```
//!
//! Only the name and query type are consumed; the trailing metadata differs in
//! size and meaning between the two event ids and is not needed.
//!
//! # Cost
//!
//! The callback runs on the `ProcessTrace` delivery thread. It rejects
//! non-DNS event ids with a single comparison (the provider is chatty), rejects
//! PIDs already proven to be outside the target tree, and otherwise does one
//! small allocation and a non-blocking channel send. Nothing here blocks.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crossbeam_channel::Sender;

use crate::model::{EventKind, RawEvent, Source};
use crate::util::{read_u16, read_u32, read_utf16_z};
use crate::win::etw::{
    EtwConsumer, EtwSession, EventView, SESSION_NAME_PREFIX, providers,
};

/// "A DNS query is being issued." Carries the caller's PID.
pub const EVENT_QUERY: u16 = 3006;
/// "The DNS query completed." Carries the caller's PID.
pub const EVENT_RESPONSE: u16 = 3008;

/// Kernel-side ring sizing. Deliberately generous: these buffers are paged and
/// only become resident under load, and they are the cheapest possible defence
/// against `EventsLost` when a browser opens 40 connections at once.
const BUFFER_KB: u32 = 128;
const MIN_BUFFERS: u32 = 64;
const MAX_BUFFERS: u32 = 512;

/// Live counters for the UI.
#[derive(Default)]
pub struct EtwDnsStats {
    /// Events 3006 parsed into `RawEvent`s.
    pub queries: AtomicU64,
    /// Events 3008 observed (used to compute an answered/unanswered ratio).
    pub responses: AtomicU64,
    /// Events dropped because the PID was already known to be foreign.
    pub filtered_foreign: AtomicU64,
    /// Events rejected because the payload did not look like a DNS name.
    pub malformed: AtomicU64,
}

/// A running ETW DNS-Client subscription.
pub struct EtwDnsSource {
    session: EtwSession,
    consumer: EtwConsumer,
    pub stats: Arc<EtwDnsStats>,
}

impl EtwDnsSource {
    /// Start the trace session and begin delivering events into `tx`.
    ///
    /// `foreign` is the set of PIDs the process watcher has *proven* are not
    /// descendants of the target. It is only ever used as a negative filter:
    /// an unknown PID is always forwarded, so a freshly spawned child can never
    /// be lost. See `win::proctree` for how the set is derived.
    ///
    /// Returns the source and the names of any stale sessions it had to clear,
    /// so the caller can tell the user what happened.
    pub fn start(
        session_name: &str,
        tx: Sender<RawEvent>,
        foreign: Arc<RwLock<HashSet<u32>>>,
    ) -> anyhow::Result<(Self, Vec<String>)> {
        // Clear anything a previous, forcibly-killed run left behind before we add
    // to the pile. Only sessions whose owning process is gone are touched, so a
    // second instance the user is running on purpose is safe.
    let swept = crate::win::etw::stop_stale_sessions(SESSION_NAME_PREFIX, session_name, false);
    let (session, mut cleared) = open_with_recovery(session_name)?;
    if cleared.is_empty() {
        cleared = swept;
    }

        let stats = Arc::new(EtwDnsStats::default());
        let cb_stats = stats.clone();

        let consumer = EtwConsumer::start(session_name, move |ev: &EventView<'_>| {
            handle_event(ev, &tx, &foreign, &cb_stats);
        })
        .map_err(|e| anyhow::anyhow!("could not open ETW consumer: {e}"))?;

        let mut consumer = consumer;
        consumer.spawn();

        Ok((
            Self {
                session,
                consumer,
                stats,
            },
            cleared,
        ))
    }

    /// Events the kernel dropped because our consumer fell behind.
    pub fn events_lost(&mut self) -> u32 {
        self.session.events_lost()
    }

    pub fn stop(&mut self) {
        self.consumer.stop();
        self.session.stop();
    }
}

impl Drop for EtwDnsSource {
    fn drop(&mut self) {
        self.stop();
    }
}

/// `ERROR_NO_SYSTEM_RESOURCES`. Raised by `StartTraceW` / `EnableTraceEx2`
/// when the machine has run out of ETW session resources -- in practice almost
/// always because sessions leaked by processes that were killed before they
/// could stop them.
const ERROR_NO_SYSTEM_RESOURCES: i32 = 1450;

fn is_resource_exhaustion(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(ERROR_NO_SYSTEM_RESOURCES)
}

/// A short, actionable sentence to append to an ETW error.
fn hint_for(e: &std::io::Error) -> &'static str {
    match e.raw_os_error() {
        Some(ERROR_NO_SYSTEM_RESOURCES) => {
            ". The system has run out of ETW resources; run 'netmon --doctor --clean-sessions' \
             to clear sessions left behind by terminated runs"
        }
        Some(5) => ". Access denied -- NetMonitor must run elevated (Administrator)",
        _ => "",
    }
}

/// Start a trace session, recovering once from ETW resource exhaustion.
///
/// Recovery is deliberately attempted *only* after a failure rather than
/// pre-emptively: a blanket "stop every NetMonitor session" sweep at startup
/// would kill a second instance that the user is running on purpose.
fn open_with_recovery(name: &str) -> anyhow::Result<(EtwSession, Vec<String>)> {
    match try_open(name) {
        Ok(s) => Ok((s, Vec::new())),
        Err(e) if is_resource_exhaustion(&e) => {
            let cleared = crate::win::etw::stop_stale_sessions(SESSION_NAME_PREFIX, name, false);
            if cleared.is_empty() {
                return Err(anyhow::anyhow!(
                    "could not open ETW session '{name}': {e}{}",
                    hint_for(&e)
                ));
            }
            let s = try_open(name).map_err(|e2| {
                anyhow::anyhow!(
                    "could not open ETW session '{name}' even after clearing {} stale \
                     session(s): {e2}{}",
                    cleared.len(),
                    hint_for(&e2)
                )
            })?;
            Ok((s, cleared))
        }
        Err(e) => Err(anyhow::anyhow!(
            "could not open ETW session '{name}': {e}{}",
            hint_for(&e)
        )),
    }
}

/// Open a session and enable the DNS provider in it. Both steps can fail with
/// resource exhaustion, so both are inside the retried unit of work.
fn try_open(name: &str) -> std::io::Result<EtwSession> {
    let session = EtwSession::start(name, BUFFER_KB, MIN_BUFFERS, MAX_BUFFERS)?;
    match session.enable(&providers::DNS_CLIENT, 5 /* VERBOSE */, u64::MAX) {
        Ok(()) => Ok(session),
        Err(e) => {
            // Dropping stops the session we just created, so a failed attempt
            // never leaves anything behind for the next attempt to trip over.
            drop(session);
            Err(e)
        }
    }
}

/// Hot path. Keep it short and allocation-light.
fn handle_event(
    ev: &EventView<'_>,
    tx: &Sender<RawEvent>,
    foreign: &Arc<RwLock<HashSet<u32>>>,
    stats: &Arc<EtwDnsStats>,
) {
    let kind = match ev.id {
        EVENT_QUERY => EventKind::Query,
        EVENT_RESPONSE => EventKind::Response,
        // The provider also emits 1001/1015/1017/3009-3020 from the DNS Client
        // service. They carry no per-application information we want.
        _ => return,
    };

    // Cheap negative filter: PIDs proven (by a full ancestor walk) to be
    // outside the target tree. Unknown PIDs fall through on purpose.
    if let Ok(set) = foreign.read() {
        if !set.is_empty() && set.contains(&ev.pid) {
            stats.filtered_foreign.fetch_add(1, Ordering::Relaxed);
            crate::util::filter_log(format_args!("etw-foreign pid={} id={}", ev.pid, ev.id));
            return;
        }
    }

    let Some((name, qtype)) = parse_query_payload(ev.payload) else {
        stats.malformed.fetch_add(1, Ordering::Relaxed);
        crate::util::filter_log(format_args!("etw-malformed pid={} id={}", ev.pid, ev.id));
        return;
    };
    crate::util::filter_log(format_args!(
        "etw-forward pid={} kind={:?} name={}",
        ev.pid, kind, name
    ));

    match kind {
        EventKind::Query => &stats.queries,
        _ => &stats.responses,
    }
    .fetch_add(1, Ordering::Relaxed);

    // A full queue must never block the ETW delivery thread; dropping is the
    // correct behaviour and is surfaced in the UI.
    let _ = tx.try_send(RawEvent {
        ts_100ns: ev.ts_100ns,
        pid: ev.pid,
        name,
        qtype,
        source: Source::Etw,
        kind,
        answers: Vec::new(),
        rcode: None,
        dns_id: 0,
    });
}

/// Extract `(name, qtype)` from a 3006/3008 payload.
///
/// Returns `None` when the payload is not shaped like a DNS name, which is the
/// signal that a future Windows build changed the template -- better to count
/// and skip than to emit garbage.
pub fn parse_query_payload(payload: &[u8]) -> Option<(String, u16)> {
    let (raw_name, next) = read_utf16_z(payload, 0);
    if raw_name.is_empty() {
        return None;
    }
    let name = normalize_domain(&raw_name)?;
    let qtype = read_u32(payload, next)
        .map(|v| (v & 0xffff) as u16)
        .or_else(|| read_u16(payload, next))
        .unwrap_or(0);
    Some((name, qtype))
}

/// Canonicalise a domain name: lower case, no trailing dot, no control bytes.
///
/// Names come from the network and from other processes; they must never be
/// able to inject escape sequences into the terminal.
pub fn normalize_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim_end_matches('.').trim();
    if trimmed.is_empty() || trimmed.len() > 255 {
        return None;
    }
    let mut out = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if ch.is_ascii_graphic() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == ' ' {
            // Some reverse lookups contain a literal space; keep it visible
            // rather than silently gluing labels together.
            out.push('_');
        } else {
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(name: &str, qtype: u32) -> Vec<u8> {
        let mut v: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(&qtype.to_le_bytes());
        v.extend_from_slice(&[0u8; 20]); // trailing provider metadata
        v
    }

    #[test]
    fn parses_real_payload_shape() {
        let p = payload("gator.volces.com", 1);
        assert_eq!(
            parse_query_payload(&p),
            Some(("gator.volces.com".to_string(), 1))
        );
        let p = payload("WWW.Example.COM.", 28);
        assert_eq!(
            parse_query_payload(&p),
            Some(("www.example.com".to_string(), 28))
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_query_payload(&[]).is_none());
        assert!(parse_query_payload(&[0, 0, 1, 0]).is_none());
        // Control characters must not reach the UI.
        let mut p: Vec<u8> = "bad\u{1b}[31mname"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        p.extend_from_slice(&[0, 0, 1, 0, 0, 0]);
        assert!(parse_query_payload(&p).is_none());
    }

    #[test]
    fn normalizes_names() {
        assert_eq!(normalize_domain("A.B.").as_deref(), Some("a.b"));
        assert_eq!(normalize_domain("").as_deref(), None);
        assert_eq!(normalize_domain(".").as_deref(), None);
    }

    #[test]
    fn payload_without_trailing_metadata_ok() {
        // Some builds truncate to just name + type.
        let p = payload("x.test", 12);
        assert_eq!(
            parse_query_payload(&p[..16]),
            Some(("x.test".to_string(), 12))
        );
    }
}
