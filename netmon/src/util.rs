//! Small shared helpers: UTF-16 handling, FILETIME conversion, formatting.

/// Number of 100 ns ticks between 1601-01-01 (FILETIME epoch) and 1970-01-01.
pub const FILETIME_UNIX_EPOCH: i64 = 116_444_736_000_000_000;

/// Convert an ETW/FILETIME timestamp (100 ns ticks since 1601) to Unix
/// milliseconds. Saturates instead of overflowing on nonsense input.
pub fn filetime_to_unix_ms(ticks: i64) -> i64 {
    ticks.saturating_sub(FILETIME_UNIX_EPOCH) / 10_000
}

/// Current time in Unix milliseconds.
pub fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Format Unix milliseconds as local `HH:MM:SS.mmm`.
pub fn fmt_time_ms(unix_ms: i64) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_millis_opt(unix_ms) {
        chrono::LocalResult::Single(dt) => dt.format("%H:%M:%S%.3f").to_string(),
        _ => "--:--:--.---".to_string(),
    }
}

/// Format Unix milliseconds as a local ISO-8601-ish timestamp for exports.
pub fn fmt_datetime_ms(unix_ms: i64) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_millis_opt(unix_ms) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        _ => String::new(),
    }
}

/// Read a NUL-terminated UTF-16LE string from `buf` starting at `offset`.
///
/// Returns the decoded string and the offset just past the terminator (or past
/// the end of the buffer if it was not terminated). Invalid surrogates are
/// replaced rather than rejected -- DNS names are attacker-controlled input and
/// must never be able to abort the capture path.
pub fn read_utf16_z(buf: &[u8], offset: usize) -> (String, usize) {
    if offset >= buf.len() {
        return (String::new(), buf.len());
    }
    let mut units: Vec<u16> = Vec::with_capacity(32);
    let mut i = offset;
    while i + 1 < buf.len() {
        let u = u16::from_le_bytes([buf[i], buf[i + 1]]);
        i += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    (String::from_utf16_lossy(&units), i)
}

/// Read a little-endian `u16` at `offset`, or `None` if out of range.
pub fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    buf.get(offset..offset + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

/// Read a little-endian `u32` at `offset`, or `None` if out of range.
pub fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Human-readable DNS record-type name.
pub fn qtype_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        17 => "RP",
        18 => "AFSDB",
        24 => "SIG",
        25 => "KEY",
        28 => "AAAA",
        29 => "LOC",
        33 => "SRV",
        35 => "NAPTR",
        36 => "KX",
        37 => "CERT",
        39 => "DNAME",
        41 => "OPT",
        42 => "APL",
        43 => "DS",
        44 => "SSHFP",
        45 => "IPSECKEY",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        49 => "DHCID",
        50 => "NSEC3",
        51 => "NSEC3PARAM",
        52 => "TLSA",
        53 => "SMIMEA",
        55 => "HIP",
        59 => "CDS",
        60 => "CDNSKEY",
        61 => "OPENPGPKEY",
        62 => "CSYNC",
        63 => "ZONEMD",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        108 => "EUI48",
        109 => "EUI64",
        249 => "TKEY",
        250 => "TSIG",
        251 => "IXFR",
        252 => "AXFR",
        255 => "ANY",
        256 => "URI",
        257 => "CAA",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_roundtrip() {
        let src = "www.example.com"; // 15 chars -> 32 bytes including the NUL
        let mut buf: Vec<u8> = src.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&[1, 0, 0, 0]);
        let (s, off) = read_utf16_z(&buf, 0);
        assert_eq!(s, "www.example.com");
        assert_eq!(off, 32);
        assert_eq!(read_u32(&buf, off), Some(1));
    }

    #[test]
    fn utf16_unterminated_reads_to_end() {
        // No NUL: every complete code unit must be returned and the offset must
        // land exactly on the buffer end, never one past it.
        let buf: Vec<u8> = "abc".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let (s, off) = read_utf16_z(&buf, 0);
        assert_eq!(s, "abc");
        assert_eq!(off, buf.len());
    }

    #[test]
    fn utf16_odd_trailing_byte_is_ignored() {
        let mut buf: Vec<u8> = "ab".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        buf.push(0x41); // dangling half of a code unit
        let (s, off) = read_utf16_z(&buf, 0);
        assert_eq!(s, "ab");
        assert_eq!(off, 4);
    }

    #[test]
    fn filetime_conversion() {
        // 1970-01-01T00:00:00Z
        assert_eq!(filetime_to_unix_ms(FILETIME_UNIX_EPOCH), 0);
    }
}

/// Append a line to the file named by `NETMON_FILTER_LOG`, if set.
///
/// A troubleshooting aid for the capture filter chain: when the tool reports
/// nothing, the question is always "which gate dropped it", and this answers
/// it directly. Silent and free when the variable is unset.
pub fn filter_log(args: std::fmt::Arguments<'_>) {
    use std::io::Write as _;
    use std::sync::OnceLock;
    static SINK: OnceLock<Option<std::sync::Mutex<std::fs::File>>> = OnceLock::new();
    let sink = SINK.get_or_init(|| {
        let path = std::env::var_os("NETMON_FILTER_LOG")?;
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()?;
        Some(std::sync::Mutex::new(f))
    });
    if let Some(m) = sink {
        if let Ok(mut f) = m.lock() {
            let _ = writeln!(f, "{:>10.3}  {}", now_unix_ms() as f64 / 1000.0, args);
        }
    }
}
