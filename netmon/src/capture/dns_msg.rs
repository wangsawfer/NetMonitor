//! DNS wire-format parser (RFC 1035 + compression pointers).
//!
//! Only what the monitor needs: transaction id, RCODE, the question section and
//! A/AAAA/CNAME answers. Everything is bounds-checked and loop-guarded, because
//! this parses attacker-controlled bytes arriving from the network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Maximum number of compression-pointer jumps before we declare a loop.
const MAX_POINTER_HOPS: u32 = 32;
/// Upper bound on a single label, per RFC 1035.
const MAX_LABEL: usize = 63;
/// Upper bound on a full presentation name.
const MAX_NAME: usize = 255;

#[derive(Clone, Debug, PartialEq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
}

#[derive(Clone, Debug, Default)]
pub struct Message {
    pub id: u16,
    pub is_response: bool,
    pub rcode: u8,
    pub truncated: bool,
    pub questions: Vec<Question>,
    /// Every A/AAAA record in the answer + additional sections.
    pub addresses: Vec<IpAddr>,
    /// CNAME targets in the answer section, in order.
    pub cnames: Vec<String>,
}

impl Message {
    /// First question's name, lower-cased, if any.
    pub fn first_name(&self) -> Option<String> {
        self.questions.first().map(|q| q.name.clone())
    }

    pub fn first_qtype(&self) -> u16 {
        self.questions.first().map(|q| q.qtype).unwrap_or(0)
    }
}

/// Read a (possibly compressed) domain name starting at `offset`.
///
/// Returns the presentation-form name and the offset just past the name *in the
/// section being parsed* (i.e. past the first pointer, not the pointed-to data).
pub fn read_name(buf: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut name = String::with_capacity(48);
    let mut pos = offset;
    let mut hops = 0u32;
    let mut after: Option<usize> = None;
    let mut total = 0usize;

    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // Compression pointer: top two bits set.
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= buf.len() {
                return None;
            }
            let target = ((len & 0x3f) << 8) | buf[pos + 1] as usize;
            if after.is_none() {
                after = Some(pos + 2);
            }
            hops += 1;
            if hops > MAX_POINTER_HOPS {
                return None;
            }
            // Pointers must point strictly backwards; anything else is a loop.
            if target >= pos {
                return None;
            }
            pos = target;
            continue;
        }
        if len & 0xc0 != 0 {
            return None; // reserved label type
        }
        if len > MAX_LABEL || pos + 1 + len > buf.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        // Labels are compared case-insensitively; normalise to lower case.
        for &b in &buf[pos + 1..pos + 1 + len] {
            name.push((b as char).to_ascii_lowercase());
        }
        total += len + 1;
        if total > MAX_NAME {
            return None;
        }
        pos += 1 + len;
    }

    Some((name, after.unwrap_or(pos)))
}

/// Parse a complete DNS message from a UDP payload (or a length-stripped TCP
/// payload).
pub fn parse(buf: &[u8]) -> Option<Message> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let nscount = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let arcount = u16::from_be_bytes([buf[10], buf[11]]) as usize;

    let mut msg = Message {
        id,
        is_response: flags & 0x8000 != 0,
        rcode: (flags & 0x000f) as u8,
        truncated: flags & 0x0200 != 0,
        ..Default::default()
    };

    let mut pos = 12usize;
    for _ in 0..qdcount {
        let (name, next) = read_name(buf, pos)?;
        if next + 4 > buf.len() {
            return Some(msg);
        }
        let qtype = u16::from_be_bytes([buf[next], buf[next + 1]]);
        msg.questions.push(Question { name, qtype });
        pos = next + 4;
    }

    // Answer + authority + additional: we only mine addresses and CNAMEs.
    let rr_count = ancount + nscount + arcount;
    for _ in 0..rr_count {
        let (_name, next) = match read_name(buf, pos) {
            Some(v) => v,
            None => break,
        };
        if next + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[next], buf[next + 1]]);
        let rdlen = u16::from_be_bytes([buf[next + 8], buf[next + 9]]) as usize;
        let rdata = next + 10;
        if rdata + rdlen > buf.len() {
            break;
        }
        match rtype {
            1 if rdlen == 4 => msg.addresses.push(IpAddr::V4(Ipv4Addr::new(
                buf[rdata],
                buf[rdata + 1],
                buf[rdata + 2],
                buf[rdata + 3],
            ))),
            28 if rdlen == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&buf[rdata..rdata + 16]);
                msg.addresses.push(IpAddr::V6(Ipv6Addr::from(o)));
            }
            5 => {
                if let Some((target, _)) = read_name(buf, rdata) {
                    msg.cnames.push(target);
                }
            }
            _ => {}
        }
        pos = rdata + rdlen;
    }

    Some(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a query for `name` / `qtype`.
    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut v = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            v.push(label.len() as u8);
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0);
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes()); // IN
        v
    }

    #[test]
    fn parses_simple_query() {
        let m = parse(&query("www.Example.COM", 1)).unwrap();
        assert_eq!(m.id, 0x1234);
        assert!(!m.is_response);
        assert_eq!(m.first_name().as_deref(), Some("www.example.com"));
        assert_eq!(m.first_qtype(), 1);
    }

    #[test]
    fn parses_response_with_a_record() {
        let mut v = query("a.test", 1);
        // Turn it into a response with one answer.
        v[2] = 0x81;
        v[3] = 0x80;
        v[6] = 0;
        v[7] = 1;
        // name pointer -> offset 12
        v.extend_from_slice(&[0xc0, 0x0c]);
        v.extend_from_slice(&1u16.to_be_bytes()); // type A
        v.extend_from_slice(&1u16.to_be_bytes()); // class IN
        v.extend_from_slice(&60u32.to_be_bytes()); // ttl
        v.extend_from_slice(&4u16.to_be_bytes()); // rdlength
        v.extend_from_slice(&[192, 168, 1, 10]);
        let m = parse(&v).unwrap();
        assert!(m.is_response);
        assert_eq!(m.addresses, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))]);
    }

    #[test]
    fn parses_aaaa_and_cname() {
        let mut v = query("x.test", 28);
        v[2] = 0x81;
        v[3] = 0x80;
        v[7] = 2;
        v.extend_from_slice(&[0xc0, 0x0c]);
        v.extend_from_slice(&5u16.to_be_bytes()); // CNAME
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&60u32.to_be_bytes());
        let cname = b"\x03cdn\x04test\x00";
        v.extend_from_slice(&(cname.len() as u16).to_be_bytes());
        v.extend_from_slice(cname);
        v.extend_from_slice(&[0xc0, 0x0c]);
        v.extend_from_slice(&28u16.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&60u32.to_be_bytes());
        v.extend_from_slice(&16u16.to_be_bytes());
        v.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        let m = parse(&v).unwrap();
        assert_eq!(m.cnames, vec!["cdn.test".to_string()]);
        assert_eq!(m.addresses, vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);
    }

    #[test]
    fn rejects_truncated_and_hostile_input() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0u8; 4]).is_none());
        // Self-referential compression pointer at offset 12.
        let mut v = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        v.extend_from_slice(&[0xc0, 0x0c]);
        v.extend_from_slice(&[0, 1, 0, 1]);
        assert!(parse(&v).is_none());
        // A label that runs off the end must not panic.
        let v = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 40, b'a'];
        assert!(parse(&v).is_none());
    }

    #[test]
    fn long_name_chain_terminates() {
        // Forward pointer (illegal) must be rejected without looping.
        let mut v = vec![0u8; 12];
        v[5] = 1;
        v.extend_from_slice(&[0xc0, 0x40]);
        v.extend_from_slice(&[0, 1, 0, 1]);
        assert!(parse(&v).is_none());
    }
}
