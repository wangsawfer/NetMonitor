//! Map a local transport port to the PID that owns it.
//!
//! Used by the Npcap source: when we observe a DNS query packet leaving with
//! source port `P`, the kernel endpoint table tells us which process bound `P`.
//! That is real attribution for applications that ship their own resolver and
//! never call the Windows DNS Client -- including the common case where the
//! packet is sent from a process the ETW DNS provider never mentions.
//!
//! Both families are needed: DNS rides on **UDP**/53, while the SNI fallback
//! observes **TCP** handshakes on 443/853.
//!
//! The `GetExtended*Table` calls are snapshots; we invoke them lazily and cache
//! the result for a short interval (see `PortOwnerCache`), because a burst of
//! packets from one process must not turn into a burst of table walks.

use std::collections::HashMap;

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

/// Ports in `GetExtendedUdpTable` come back in network byte order.
#[inline]
fn decode_port(raw: u32) -> u16 {
    u16::from_be((raw & 0xffff) as u16)
}

fn walk_table<const IS_V6: bool>() -> Vec<(u16, u32)> {
    let mut out = Vec::new();
    let mut size: u32 = 0;
    let family = if IS_V6 { AF_INET6 as u32 } else { AF_INET as u32 };

    unsafe {
        // First call sizes the buffer (expected to fail with
        // ERROR_INSUFFICIENT_BUFFER).
        let rc = GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            family,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if rc != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            return out;
        }
        let mut buf = vec![0u8; size as usize];
        let rc = GetExtendedUdpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            family,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if rc != NO_ERROR {
            return out;
        }

        let count = *(buf.as_ptr() as *const u32) as usize;
        if IS_V6 {
            // MIB_UDP6TABLE_OWNER_PID: u32 count, then rows of
            // { uchar[16] addr; u32 scope; u32 port; u32 pid }
            const ROW: usize = 16 + 4 + 4 + 4;
            let base = buf.as_ptr() as usize + 4;
            for i in 0..count {
                let p = (base + i * ROW) as *const u8;
                let port = u32::from_ne_bytes([*p.add(20), *p.add(21), *p.add(22), *p.add(23)]);
                let pid = u32::from_ne_bytes([*p.add(24), *p.add(25), *p.add(26), *p.add(27)]);
                out.push((decode_port(port), pid));
            }
        } else {
            let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
            let rows = table.table.as_ptr();
            for i in 0..count {
                let row = &*rows.add(i);
                out.push((decode_port(row.dwLocalPort), row.dwOwningPid));
            }
        }
    }
    out
}

fn walk_tcp_table<const IS_V6: bool>() -> Vec<(u16, u32)> {
    let mut out = Vec::new();
    let mut size: u32 = 0;
    let family = if IS_V6 { AF_INET6 as u32 } else { AF_INET as u32 };

    unsafe {
        let rc = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if rc != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            return out;
        }
        let mut buf = vec![0u8; size as usize];
        let rc = GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if rc != NO_ERROR {
            return out;
        }

        let count = *(buf.as_ptr() as *const u32) as usize;
        if IS_V6 {
            // MIB_TCP6ROW_OWNER_PID (56 bytes): local addr[16], local scope u32,
            // local port u32, remote addr[16], remote scope u32, remote port u32,
            // state u32, owning pid u32.
            const ROW: usize = 56;
            let base = buf.as_ptr() as usize + 4;
            for i in 0..count {
                let p = (base + i * ROW) as *const u8;
                let port = u32::from_ne_bytes([*p.add(20), *p.add(21), *p.add(22), *p.add(23)]);
                let pid = u32::from_ne_bytes([*p.add(52), *p.add(53), *p.add(54), *p.add(55)]);
                out.push((decode_port(port), pid));
            }
        } else {
            // MIB_TCPROW_OWNER_PID (24 bytes): state, local addr, local port,
            // remote addr, remote port, owning pid -- all u32.
            const ROW: usize = 24;
            let base = buf.as_ptr() as usize + 4;
            for i in 0..count {
                let p = (base + i * ROW) as *const u8;
                let port = u32::from_ne_bytes([*p.add(8), *p.add(9), *p.add(10), *p.add(11)]);
                let pid = u32::from_ne_bytes([*p.add(20), *p.add(21), *p.add(22), *p.add(23)]);
                out.push((decode_port(port), pid));
            }
        }
    }
    out
}

/// Snapshot of every UDP endpoint currently bound, for both address families.
pub fn udp_owners() -> Vec<(u16, u32)> {
    let mut v = walk_table::<false>();
    v.extend(walk_table::<true>());
    v
}

/// Snapshot of every TCP endpoint (listening and connected), both families.
pub fn tcp_owners() -> Vec<(u16, u32)> {
    let mut v = walk_tcp_table::<false>();
    v.extend(walk_tcp_table::<true>());
    v
}

/// Which endpoint table a lookup should consult.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Table {
    Udp,
    Tcp,
}

/// Short-lived cache in front of the endpoint tables.
///
/// Freshness matters (ports are recycled aggressively by browsers), but so does
/// cost: a busy page load produces hundreds of packets in a few milliseconds and
/// they all come from a handful of sockets.
pub struct PortOwnerCache {
    udp: HashMap<u16, u32>,
    tcp: HashMap<u16, u32>,
    udp_at: i64,
    tcp_at: i64,
    ttl_ms: i64,
}

impl PortOwnerCache {
    pub fn new(ttl_ms: i64) -> Self {
        Self {
            udp: HashMap::new(),
            tcp: HashMap::new(),
            udp_at: 0,
            tcp_at: 0,
            ttl_ms,
        }
    }

    fn refresh_udp(&mut self, now: i64) {
        self.udp.clear();
        for (p, pid) in udp_owners() {
            self.udp.insert(p, pid);
        }
        self.udp_at = now;
    }

    fn refresh_tcp(&mut self, now: i64) {
        self.tcp.clear();
        for (p, pid) in tcp_owners() {
            self.tcp.insert(p, pid);
        }
        self.tcp_at = now;
    }

    /// Owner of a local port in the given table.
    pub fn owner(&mut self, table: Table, port: u16) -> Option<u32> {
        let now = crate::util::now_unix_ms();
        let (map, at) = match table {
            Table::Udp => (&mut self.udp, &mut self.udp_at),
            Table::Tcp => (&mut self.tcp, &mut self.tcp_at),
        };
        let stale = now - *at >= self.ttl_ms;
        let missing = !map.contains_key(&port);
        if stale || missing {
            match table {
                Table::Udp => self.refresh_udp(now),
                Table::Tcp => self.refresh_tcp(now),
            }
        }
        let map = match table {
            Table::Udp => &self.udp,
            Table::Tcp => &self.tcp,
        };
        map.get(&port).copied()
    }
}

impl Default for PortOwnerCache {
    fn default() -> Self {
        Self::new(500)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_decoding() {
        // 53 in network byte order inside the low 16 bits: 0x3500
        assert_eq!(decode_port(0x0000_3500), 53);
        assert_eq!(decode_port(0x0000_0035), 0x3500);
    }

    #[test]
    fn snapshot_does_not_panic() {
        let _ = udp_owners();
    }
}
