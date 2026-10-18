//! Core data types shared by the capture, pipeline and UI layers.

use std::net::IpAddr;

/// Which capture mechanism produced an observation.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Source {
    /// ETW `Microsoft-Windows-DNS-Client` provider (event 3006/3008).
    /// Carries the PID of the process that called the resolver.
    Etw,
    /// Raw packet capture of UDP/53 via Npcap. Catches applications that
    /// implement their own resolver and never touch the Windows DNS Client.
    Npcap,
    /// TLS ClientHello SNI seen on port 443 -- the DoH / DoT fallback that
    /// recovers hostnames when the query itself is encrypted.
    Sni,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Etw => "ETW",
            Source::Npcap => "PCAP",
            Source::Sni => "SNI",
        }
    }
}

/// What the observation represents.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventKind {
    /// A DNS question was issued.
    Query,
    /// A DNS answer arrived (may be a negative/failed answer).
    Response,
    /// A TLS handshake revealed a hostname.
    TlsSni,
}

/// A single observation, produced by a capture thread and pushed into the
/// pipeline channel. Deliberately small and `Send`; no pointers, no locks.
#[derive(Clone, Debug)]
pub struct RawEvent {
    /// ETW/FILETIME ticks (100 ns since 1601); use `util::filetime_to_unix_ms`.
    pub ts_100ns: i64,
    /// Owning process id, as reported by the kernel.
    pub pid: u32,
    /// Domain name in canonical lower-case ASCII presentation form.
    pub name: String,
    /// DNS query type; `0` for SNI-only observations.
    pub qtype: u16,
    pub source: Source,
    pub kind: EventKind,
    /// Addresses returned, when the observation is a response we could parse.
    pub answers: Vec<IpAddr>,
    /// Set for responses: `0` means NOERROR.
    pub rcode: Option<u8>,
    /// DNS transaction id, when the observation came from a DNS message. Lets
    /// a query and its answer be paired in an export.
    pub dns_id: u16,
}

impl RawEvent {
    pub fn unix_ms(&self) -> i64 {
        crate::util::filetime_to_unix_ms(self.ts_100ns)
    }
}

/// A display-ready row. Built by the pipeline once per accepted event.
#[derive(Clone, Debug)]
pub struct Record {
    pub seq: u64,
    pub unix_ms: i64,
    pub time: String,
    pub process: String,
    pub pid: u32,
    pub qtype: String,
    pub source: Source,
    pub kind: EventKind,
    pub domain: String,
    /// Addresses known for this domain when the row was created.
    ///
    /// Kept structured as well as rendered, so the address filter can match a
    /// network prefix without re-parsing the display string once per row.
    pub resolved: Vec<IpAddr>,
    /// Pre-rendered extra column (answers, status, ...).
    pub detail: String,
}
