//! Secondary capture source: raw packets via Npcap.
//!
//! This covers the ETW blind spot. `Microsoft-Windows-DNS-Client` only sees
//! queries that go through the Windows resolver; an application that ships its
//! own DNS stack, speaks DNS-over-TCP, or has the answer cached while a
//! connection is nevertheless made, produces no ETW event at all.
//!
//! Three things are mined here:
//!
//! 1. **UDP/53 queries** -- parsed with `dns_msg`, attributed to a PID through
//!    the kernel endpoint tables (`win::endpoint`). Rows owned by
//!    `svchost.exe` are suppressed: those are the Windows resolver's own
//!    packets, and the ETW source already attributes them to the real caller.
//! 2. **UDP/53 responses** -- not displayed, but used to populate the
//!    IP -> hostname cache so later connections can be labelled.
//! 3. **TLS ClientHello SNI** on 443/853 -- the DoH/DoT fallback.
//!
//! # Blocking, not polling
//!
//! Each capture handle runs `pcap_next_ex` in immediate mode, which blocks in
//! the driver until a packet matching the BPF filter arrives. There is no timer
//! anywhere in this file.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use crossbeam_channel::Sender;
use pcap::{Active, Capture, Device};

use crate::capture::dns_msg;
use crate::capture::tls;
use crate::model::{EventKind, RawEvent, Source};
use crate::win::endpoint::{PortOwnerCache, Table};

/// Interface types we know how to skip the link-layer header for.
const DLT_NULL: i32 = 0;
const DLT_EN10MB: i32 = 1;
const DLT_RAW: i32 = 101;
const DLT_LOOP: i32 = 108;
const DLT_LINUX_SLL: i32 = 113;
const DLT_LINUX_SLL2: i32 = 276;

/// 8 MiB per handle. Npcap's default is 1 MiB, which is easily overrun by a
/// burst of TLS handshakes; the buffer is a paged kernel allocation, so the
/// cost of oversizing is negligible and the cost of under-sizing is dropped
/// DNS answers.
const SNAPLEN: i32 = 65_535;
const BUFFER_BYTES: i32 = 8 * 1024 * 1024;
/// How long `PortOwnerCache` trusts a port -> PID mapping.
const PORT_CACHE_TTL_MS: i64 = 400;

/// BPF programs, tried in order until one compiles.
///
/// # Why the obvious optimisation is not used
///
/// A filter of the form
///
/// ```text
/// (tcp dst port 443) and (tcp[((tcp[12] & 0xf0) >> 2)] = 0x16)
/// ```
///
/// is the classic idiom for "first payload byte is a TLS handshake", and it
/// would cut the HTTPS volume before it ever reaches user space. It was tried
/// and **rejected**: measured on Windows 11 26100 with Npcap 1.79, it silently
/// failed to match IPv6 ClientHellos, so the SNI fallback produced nothing for
/// any host whose name resolved to AAAA first (which, on a dual-stack machine,
/// is most of them). A capture filter that quietly drops the traffic it was
/// written to select is worse than no filter at all.
///
/// The port-only filter costs almost nothing: `process_frame` rejects a
/// non-ClientHello from its first byte, and promiscuous mode is off, so only
/// this host's own flows are ever copied up.
const BPF_CANDIDATES: &[&str] = &[
    "udp port 53 or tcp dst port 443 or tcp dst port 853",
    "udp port 53",
];

/// Counters shared with the UI.
#[derive(Default)]
pub struct PcapStats {
    pub packets: AtomicU64,
    pub dns_queries: AtomicU64,
    pub dns_responses: AtomicU64,
    pub sni_names: AtomicU64,
    /// Queries attributed to `svchost.exe` and dropped as duplicates of ETW.
    pub suppressed_service: AtomicU64,
    pub kernel_dropped: AtomicU64,
    /// Devices we managed to open.
    pub devices: AtomicU64,
}

/// One running capture on one interface.
struct Handle {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// The whole Npcap source: one blocking capture thread per usable interface.
pub struct PcapSource {
    handles: Vec<Handle>,
    pub stats: Arc<PcapStats>,
    /// Human-readable description of what was opened, for the UI/log.
    pub devices: Vec<String>,
    /// Which BPF program won.
    pub filter: String,
}

impl PcapSource {
    /// Open every usable interface and start capturing.
    ///
    /// Returns an error only if *no* interface could be opened; a partial
    /// success is normal (a sleeping Wi-Fi adapter, a filter driver that
    /// refuses promiscuous mode, ...) and is reported through `devices`.
    /// Open every usable interface and start capturing.
    ///
    /// `bpf_override` replaces the built-in filter candidates; it exists for
    /// `--pcap-filter`, which is the escape hatch when a site's traffic needs a
    /// narrower or wider expression than the defaults.
    pub fn start_with_filter(
        tx: Sender<RawEvent>,
        include_loopback: bool,
        bpf_override: Option<&str>,
    ) -> anyhow::Result<Self> {
        let devices = Device::list().map_err(|e| {
            anyhow::anyhow!(
                "Npcap device enumeration failed: {e}. Is the Npcap driver installed \
                 and is the process elevated?"
            )
        })?;

        let mut handles = Vec::new();
        let mut opened = Vec::new();
        let mut filter_used = String::new();
        let stats = Arc::new(PcapStats::default());
        let mut last_err: Option<String> = None;

        for dev in devices {
            if dev.flags.is_loopback() && !include_loopback {
                continue;
            }
            // Interfaces with no address at all cannot carry the traffic we
            // care about; skipping them avoids pointless handles.
            if dev.addresses.is_empty() && !dev.flags.is_loopback() {
                continue;
            }
            let name = dev.name.clone();
            let label = match &dev.desc {
                Some(d) if !d.is_empty() => format!("{name} ({d})"),
                _ => name.clone(),
            };

            match open_capture(&dev, &mut filter_used, bpf_override) {
                Ok(cap) => {
                    let stop = Arc::new(AtomicBool::new(false));
                    let t = spawn_reader(cap, tx.clone(), stats.clone(), stop.clone());
                    handles.push(Handle {
                        stop,
                        thread: Some(t),
                    });
                    opened.push(label);
                }
                Err(e) => last_err = Some(format!("{label}: {e}")),
            }
        }

        if handles.is_empty() {
            return Err(anyhow::anyhow!(
                "no capture interface could be opened{}",
                last_err.map(|e| format!(" (last error: {e})")).unwrap_or_default()
            ));
        }

        stats
            .devices
            .store(opened.len() as u64, Ordering::Relaxed);
        Ok(Self {
            handles,
            stats,
            devices: opened,
            filter: filter_used,
        })
    }

    pub fn stop(&mut self) {
        for h in &self.handles {
            h.stop.store(true, Ordering::SeqCst);
        }
        for h in self.handles.iter_mut() {
            if let Some(t) = h.thread.take() {
                let _ = t.join();
            }
        }
        self.handles.clear();
    }

    /// Diagnostic open used by `--doctor`: binds (and immediately releases)
    /// every interface with the real filter, proving that capture would work.
    pub fn start_probe(include_loopback: bool) -> anyhow::Result<(usize, String)> {
        let devices = Device::list()
            .map_err(|e| anyhow::anyhow!("device enumeration failed: {e}"))?;
        let mut ok = 0usize;
        let mut filter = String::new();
        let mut last = String::new();
        for dev in devices {
            if dev.flags.is_loopback() && !include_loopback {
                continue;
            }
            if dev.addresses.is_empty() && !dev.flags.is_loopback() {
                continue;
            }
            match open_capture(&dev, &mut filter, None) {
                Ok(_cap) => ok += 1,
                Err(e) => last = format!("{}: {e}", dev.name),
            }
        }
        if ok == 0 {
            return Err(anyhow::anyhow!(
                "no interface usable{}",
                if last.is_empty() {
                    String::new()
                } else {
                    format!(" (last error: {last})")
                }
            ));
        }
        Ok((ok, filter))
    }
}

impl Drop for PcapSource {
    fn drop(&mut self) {
        self.stop();
    }
}

fn open_capture(
    dev: &Device,
    filter_used: &mut String,
    bpf_override: Option<&str>,
) -> anyhow::Result<Capture<Active>> {
    let cap = Capture::from_device(dev.clone())
        .map_err(|e| anyhow::anyhow!("pcap_create: {e}"))?
        // Not promiscuous: we only care about this host's own traffic, and
        // leaving promisc off keeps the adapter from waking for foreign frames.
        .promisc(false)
        .snaplen(SNAPLEN)
        // Immediate mode: hand each packet up as it arrives instead of waiting
        // for the buffer to fill or the timeout to expire. This is what makes
        // the display feel live.
        .immediate_mode(true)
        .buffer_size(BUFFER_BYTES)
        // The timeout is only a safety net now that immediate mode is on.
        .timeout(100)
        .open()
        .map_err(|e| anyhow::anyhow!("pcap_activate: {e}"))?;

    let mut cap = cap;
    let mut last: Option<pcap::Error> = None;
    let candidates: Vec<&str> = match bpf_override {
        Some(expr) => vec![expr],
        None => BPF_CANDIDATES.to_vec(),
    };
    for candidate in candidates {
        match cap.filter(candidate, true) {
            Ok(()) => {
                if filter_used.is_empty() {
                    *filter_used = candidate.to_string();
                }
                return Ok(cap);
            }
            Err(e) => last = Some(e),
        }
    }
    Err(anyhow::anyhow!(
        "no BPF filter could be installed: {}",
        last.map(|e| e.to_string()).unwrap_or_default()
    ))
}

fn spawn_reader(
    mut cap: Capture<Active>,
    tx: Sender<RawEvent>,
    stats: Arc<PcapStats>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let linktype = cap.get_datalink().0;
        let mut ports = PortOwnerCache::new(PORT_CACHE_TTL_MS);
        let mut last_stats = std::time::Instant::now();

        while !stop.load(Ordering::SeqCst) {
            match cap.next_packet() {
                Ok(packet) => {
                    stats.packets.fetch_add(1, Ordering::Relaxed);
                    process_frame(
                        linktype,
                        packet.data,
                        &tx,
                        &mut ports,
                        &stats,
                    );
                }
                Err(pcap::Error::TimeoutExpired) => {}
                Err(pcap::Error::NoMorePackets) => break,
                Err(_) => {
                    // A read error on a live handle usually means the adapter
                    // went away (Wi-Fi roam, VPN reconnect). Back off briefly
                    // rather than spinning.
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            if last_stats.elapsed() >= Duration::from_millis(500) {
                last_stats = std::time::Instant::now();
                if let Ok(s) = cap.stats() {
                    // ps_drop is cumulative; report the delta of interest as a
                    // monotonically increasing total.
                    let prev = stats.kernel_dropped.load(Ordering::Relaxed);
                    let now = u64::from(s.dropped) + u64::from(s.if_dropped);
                    if now > prev {
                        stats.kernel_dropped.store(now, Ordering::Relaxed);
                    }
                }
            }
        }
    })
}

/// Locate the network-layer header inside a link-layer frame.
///
/// Returns `(l3_offset, is_ipv6)`.
fn l3_offset(linktype: i32, data: &[u8]) -> Option<(usize, bool)> {
    match linktype {
        DLT_EN10MB => {
            if data.len() < 14 {
                return None;
            }
            let mut off = 14usize;
            let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
            // Walk up to two stacked VLAN tags (802.1Q / QinQ).
            let mut guard = 0;
            while (ethertype == 0x8100 || ethertype == 0x88a8) && guard < 2 {
                if data.len() < off + 4 {
                    return None;
                }
                ethertype = u16::from_be_bytes([data[off + 2], data[off + 3]]);
                off += 4;
                guard += 1;
            }
            match ethertype {
                0x0800 => Some((off, false)),
                0x86dd => Some((off, true)),
                _ => None,
            }
        }
        DLT_RAW => {
            let v = data.first()? >> 4;
            match v {
                4 => Some((0, false)),
                6 => Some((0, true)),
                _ => None,
            }
        }
        DLT_NULL | DLT_LOOP => {
            if data.len() < 4 {
                return None;
            }
            // The family field is host-endian for DLT_NULL and big-endian for
            // DLT_LOOP; accept either encoding of AF_INET/AF_INET6.
            let le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            match (le, be) {
                (2, _) | (_, 2) => Some((4, false)),
                (23, _) | (_, 23) => Some((4, true)),
                (24, _) | (_, 24) => Some((4, true)), // AF_INET6 on some BSDs
                _ => None,
            }
        }
        DLT_LINUX_SLL => {
            if data.len() < 16 {
                return None;
            }
            match u16::from_be_bytes([data[14], data[15]]) {
                0x0800 => Some((16, false)),
                0x86dd => Some((16, true)),
                _ => None,
            }
        }
        DLT_LINUX_SLL2 => {
            if data.len() < 20 {
                return None;
            }
            match u16::from_be_bytes([data[0], data[1]]) {
                0x0800 => Some((20, false)),
                0x86dd => Some((20, true)),
                _ => None,
            }
        }
        _ => {
            // Unknown link type: guess from the first nibble.
            match data.first()? >> 4 {
                4 => Some((0, false)),
                6 => Some((0, true)),
                _ => None,
            }
        }
    }
}

/// Transport-layer view of one frame.
struct Transport<'a> {
    src_port: u16,
    dst_port: u16,
    payload: &'a [u8],
    is_tcp: bool,
}

fn parse_transport(l3: &[u8], is_v6: bool) -> Option<Transport<'_>> {
    let (proto, l4) = if is_v6 {
        if l3.len() < 40 {
            return None;
        }
        // The IPv6 header is fixed at 40 bytes; extension headers are not
        // followed (DNS and TLS never sit behind one in practice on this host).
        let next_header = l3[6];
        let payload_len = u16::from_be_bytes([l3[4], l3[5]]) as usize;
        let end = (40 + payload_len).min(l3.len());
        let l4 = l3.get(40..end)?;
        (next_header, l4)
    } else {
        if l3.len() < 20 {
            return None;
        }
        let ihl = ((l3[0] & 0x0f) as usize) * 4;
        if ihl < 20 || l3.len() < ihl {
            return None;
        }
        // Fragmented (non-first) packets have no transport header.
        let frag = u16::from_be_bytes([l3[6], l3[7]]);
        if frag & 0x1fff != 0 {
            return None;
        }
        let total_len = u16::from_be_bytes([l3[2], l3[3]]) as usize;
        let end = total_len.max(ihl).min(l3.len());
        let l4 = l3.get(ihl..end)?;
        (l3[9], l4)
    };

    match proto {
        17 => {
            if l4.len() < 8 {
                return None;
            }
            let src = u16::from_be_bytes([l4[0], l4[1]]);
            let dst = u16::from_be_bytes([l4[2], l4[3]]);
            let ulen = u16::from_be_bytes([l4[4], l4[5]]) as usize;
            let end = ulen.clamp(8, l4.len());
            Some(Transport {
                src_port: src,
                dst_port: dst,
                payload: &l4[8..end],
                is_tcp: false,
            })
        }
        6 => {
            if l4.len() < 20 {
                return None;
            }
            let src = u16::from_be_bytes([l4[0], l4[1]]);
            let dst = u16::from_be_bytes([l4[2], l4[3]]);
            let data_off = ((l4[12] >> 4) as usize) * 4;
            if data_off < 20 || l4.len() < data_off {
                return None;
            }
            Some(Transport {
                src_port: src,
                dst_port: dst,
                payload: &l4[data_off..],
                is_tcp: true,
            })
        }
        _ => None,
    }
}

fn process_frame(
    linktype: i32,
    data: &[u8],
    tx: &Sender<RawEvent>,
    ports: &mut PortOwnerCache,
    stats: &PcapStats,
) {
    let Some((off, is_v6)) = l3_offset(linktype, data) else {
        return;
    };
    let Some(l3) = data.get(off..) else { return };
    let Some(t) = parse_transport(l3, is_v6) else {
        return;
    };

    if !t.is_tcp {
        if t.dst_port == 53 {
            // A query leaving this host.
            let Some(msg) = dns_msg::parse(t.payload) else {
                return;
            };
            if msg.is_response {
                return;
            }
            let Some(name) = msg.first_name() else { return };
            if name.is_empty() {
                return;
            }
            let qtype = msg.first_qtype();
            let pid = ports.owner(Table::Udp, t.src_port);
            // The Windows resolver sends from svchost. ETW already attributes
            // those to the real caller with better fidelity, so a PCAP row here
            // would just be a confusing duplicate.
            if let Some(pid) = pid {
                if is_service_process(pid) {
                    stats.suppressed_service.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
            stats.dns_queries.fetch_add(1, Ordering::Relaxed);
            let _ = tx.try_send(RawEvent {
                ts_100ns: now_filetime(),
                pid: pid.unwrap_or(0),
                name,
                qtype,
                source: Source::Npcap,
                kind: EventKind::Query,
                answers: Vec::new(),
                rcode: None,
                dns_id: msg.id,
            });
        } else if t.src_port == 53 {
            // A response coming back: mine it for the IP -> name cache.
            let Some(msg) = dns_msg::parse(t.payload) else {
                return;
            };
            // A truncated answer (TC=1) means the server wants a TCP retry and
            // the address list we can see is incomplete, so caching it would
            // record a mapping the client never actually used.
            if !msg.is_response || msg.truncated || msg.addresses.is_empty() {
                return;
            }
            let Some(name) = msg.first_name() else { return };
            stats.dns_responses.fetch_add(1, Ordering::Relaxed);
            let _ = tx.try_send(RawEvent {
                ts_100ns: now_filetime(),
                pid: 0,
                name,
                qtype: msg.first_qtype(),
                source: Source::Npcap,
                kind: EventKind::Response,
                answers: msg.addresses,
                rcode: Some(msg.rcode),
                dns_id: msg.id,
            });
        }
        return;
    }

    // TCP: DNS-over-TCP on 53, or a TLS handshake on 443/853.
    if t.dst_port == 443 || t.dst_port == 853 {
        let Some(sni) = tls::extract_sni(t.payload) else {
            return;
        };
        // SNI rides on TCP, so it is the TCP endpoint table that knows which
        // process owns this connection.
        let pid = ports.owner(Table::Tcp, t.src_port);
        if let Some(pid) = pid {
            if is_service_process(pid) {
                return;
            }
        }
        stats.sni_names.fetch_add(1, Ordering::Relaxed);
        let _ = tx.try_send(RawEvent {
            ts_100ns: now_filetime(),
            pid: pid.unwrap_or(0),
            name: sni,
            qtype: 0,
            source: Source::Sni,
            kind: EventKind::TlsSni,
            answers: Vec::new(),
            rcode: None,
            dns_id: 0,
        });
    } else if t.dst_port == 53 {
        let Some(stripped) = tls::strip_dot_length_prefix(t.payload) else {
            return;
        };
        let Some(msg) = dns_msg::parse(stripped) else {
            return;
        };
        let Some(name) = msg.first_name() else { return };
        let pid = ports.owner(Table::Tcp, t.src_port);
        if let Some(pid) = pid {
            if is_service_process(pid) {
                return;
            }
        }
        let _ = tx.try_send(RawEvent {
            ts_100ns: now_filetime(),
            pid: pid.unwrap_or(0),
            name,
            qtype: msg.first_qtype(),
            source: Source::Npcap,
            kind: EventKind::Query,
            answers: Vec::new(),
            rcode: None,
            dns_id: msg.id,
        });
    }
}

/// Is this PID one of the Windows service hosts that proxy DNS on behalf of
/// every application? Such rows are suppressed in favour of ETW attribution.
fn is_service_process(pid: u32) -> bool {
    if pid == 0 || pid == 4 {
        return true;
    }
    matches!(
        crate::win::proctree::image_name(pid).as_deref(),
        Some("svchost.exe") | Some("System") | Some("lsass.exe")
    )
}

fn now_filetime() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    crate::util::FILETIME_UNIX_EPOCH + (d.as_nanos() as i64) / 100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_ipv4_offset() {
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f[13] = 0x00;
        f.extend_from_slice(&[0x45, 0, 0, 20]);
        assert_eq!(l3_offset(DLT_EN10MB, &f), Some((14, false)));
    }

    #[test]
    fn ethernet_vlan_is_skipped() {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x81, 0x00]); // VLAN
        f.extend_from_slice(&[0, 0]); // tag
        f.extend_from_slice(&[0x86, 0xdd]); // IPv6
        f.extend_from_slice(&[0x60, 0, 0, 0]);
        assert_eq!(l3_offset(DLT_EN10MB, &f), Some((18, true)));
    }

    #[test]
    fn raw_and_loopback_offsets() {
        assert_eq!(l3_offset(DLT_RAW, &[0x45, 0, 0, 20]), Some((0, false)));
        assert_eq!(l3_offset(DLT_RAW, &[0x60, 0, 0, 0]), Some((0, true)));
        assert_eq!(
            l3_offset(DLT_NULL, &[2, 0, 0, 0, 0x45, 0, 0, 20]),
            Some((4, false))
        );
    }

    #[test]
    fn truncated_frames_are_rejected() {
        assert_eq!(l3_offset(DLT_EN10MB, &[0u8; 5]), None);
        assert_eq!(l3_offset(DLT_RAW, &[]), None);
        assert!(parse_transport(&[0x45], false).is_none());
    }

    #[test]
    fn udp_transport_parsing() {
        // IPv4 + UDP with a 4-byte payload.
        let mut l3 = vec![0u8; 20];
        l3[0] = 0x45;
        l3[9] = 17;
        let total = 20 + 8 + 4;
        l3[2] = (total >> 8) as u8;
        l3[3] = (total & 0xff) as u8;
        l3.extend_from_slice(&[0x9c, 0x40]); // src port 40000
        l3.extend_from_slice(&[0x00, 0x35]); // dst port 53
        l3.extend_from_slice(&[0x00, 0x0c]); // udp length
        l3.extend_from_slice(&[0, 0]); // checksum
        l3.extend_from_slice(&[1, 2, 3, 4]);
        let t = parse_transport(&l3, false).unwrap();
        assert_eq!(t.src_port, 40000);
        assert_eq!(t.dst_port, 53);
        assert_eq!(t.payload, &[1, 2, 3, 4]);
        assert!(!t.is_tcp);
    }

    /// Build an IPv4 packet: `ip_opts` bytes of IP options and `tcp_opts` bytes
    /// of TCP options, followed by `payload`.
    fn ipv4_tcp(src_port: u16, dst_port: u16, ip_opts: usize, tcp_opts: usize, payload: &[u8]) -> Vec<u8> {
        let ihl = 20 + ip_opts;
        let doff = 20 + tcp_opts;
        let total = ihl + doff + payload.len();

        let mut v = vec![0u8; ihl];
        v[0] = 0x40 | ((ihl / 4) as u8); // version 4, IHL in words
        v[2] = (total >> 8) as u8;
        v[3] = (total & 0xff) as u8;
        v[9] = 6; // TCP

        v.extend_from_slice(&src_port.to_be_bytes());
        v.extend_from_slice(&dst_port.to_be_bytes());
        v.extend_from_slice(&[0u8; 8]); // seq + ack
        v.push(((doff / 4) as u8) << 4);
        v.push(0x18); // PSH | ACK
        v.extend_from_slice(&[0u8; 6]); // window(2) + checksum(2) + urgent(2)
        v.extend(std::iter::repeat_n(0x01u8, tcp_opts)); // NOP padding
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn tcp_without_options() {
        let l3 = ipv4_tcp(49152, 443, 0, 0, &[0x16, 0x03, 0x01]);
        let t = parse_transport(&l3, false).unwrap();
        assert!(t.is_tcp);
        assert_eq!(t.src_port, 49152);
        assert_eq!(t.dst_port, 443);
        assert_eq!(t.payload, &[0x16, 0x03, 0x01]);
    }

    #[test]
    fn tcp_options_are_honoured() {
        // 12 bytes of TCP options push the payload to offset 32 in the header,
        // so a parser that ignores the data-offset field would read options as
        // payload and fail to see the ClientHello.
        let l3 = ipv4_tcp(49152, 443, 0, 12, &[0x16, 0x03, 0x01]);
        let t = parse_transport(&l3, false).unwrap();
        assert_eq!(t.payload, &[0x16, 0x03, 0x01]);
    }

    #[test]
    fn ip_options_shift_the_transport_header() {
        let l3 = ipv4_tcp(40000, 53, 8, 0, &[0xde, 0xad]);
        let t = parse_transport(&l3, false).unwrap();
        assert_eq!(t.src_port, 40000);
        assert_eq!(t.dst_port, 53);
        assert_eq!(t.payload, &[0xde, 0xad]);
    }

    #[test]
    fn non_first_fragments_are_ignored() {
        let mut l3 = ipv4_tcp(40000, 53, 0, 0, &[0xde, 0xad]);
        l3[6] = 0x00;
        l3[7] = 0x10; // more-fragments set, non-zero offset
        assert!(parse_transport(&l3, false).is_none());
    }
}
