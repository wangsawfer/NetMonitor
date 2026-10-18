//! TLS ClientHello SNI extraction.
//!
//! When an application resolves names over DoH/DoT, or simply reuses a cached
//! address, there is no plaintext DNS query to observe. The `server_name`
//! extension of the TLS handshake still leaks the hostname in the clear
//! (ECH excepted), so we mine it as the best-effort fallback the task calls for.
//!
//! This is a *supplement*, never a replacement: it only fires for connections
//! that actually happen, and it is tagged with a distinct source in the UI.

/// Extract the SNI hostname from a TCP payload if it starts a TLS ClientHello.
///
/// Returns `None` for anything that is not a well-formed ClientHello carrying a
/// `server_name` extension. All lengths are validated before use.
pub fn extract_sni(payload: &[u8]) -> Option<String> {
    // TLS record: type(1) version(2) length(2)
    if payload.len() < 5 || payload[0] != 0x16 {
        return None;
    }
    // Version must be a plausible TLS/SSL major revision.
    if payload[1] != 0x03 {
        return None;
    }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let record_end = 5usize.checked_add(record_len)?;
    let body = payload.get(5..record_end.min(payload.len()))?;
    parse_handshake(body)
}

fn parse_handshake(body: &[u8]) -> Option<String> {
    // Handshake: type(1) length(3)
    if body.len() < 4 || body[0] != 0x01 {
        return None;
    }
    let hs_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize;
    let hs = body.get(4..4 + hs_len.min(body.len().saturating_sub(4)))?;

    // ClientHello: version(2) random(32) session_id_len(1)+session_id
    let mut p = 0usize;
    p = p.checked_add(2)?; // legacy_version
    p = p.checked_add(32)?; // random
    let sid_len = *hs.get(p)? as usize;
    p = p.checked_add(1 + sid_len)?;
    let cs_len = u16::from_be_bytes([*hs.get(p)?, *hs.get(p + 1)?]) as usize;
    p = p.checked_add(2 + cs_len)?;
    let comp_len = *hs.get(p)? as usize;
    p = p.checked_add(1 + comp_len)?;

    // Extensions
    if p + 2 > hs.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([hs[p], hs[p + 1]]) as usize;
    p += 2;
    let ext_end = (p + ext_total).min(hs.len());

    while p + 4 <= ext_end {
        let etype = u16::from_be_bytes([hs[p], hs[p + 1]]);
        let elen = u16::from_be_bytes([hs[p + 2], hs[p + 3]]) as usize;
        p += 4;
        if p + elen > ext_end {
            return None;
        }
        if etype == 0x0000 {
            return parse_server_name(&hs[p..p + elen]);
        }
        p += elen;
    }
    None
}

fn parse_server_name(ext: &[u8]) -> Option<String> {
    // ServerNameList: list_len(2) then entries of type(1)+len(2)+name
    if ext.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
    let list = ext.get(2..2 + list_len.min(ext.len().saturating_sub(2)))?;
    let mut p = 0usize;
    while p + 3 <= list.len() {
        let ntype = list[p];
        let nlen = u16::from_be_bytes([list[p + 1], list[p + 2]]) as usize;
        p += 3;
        if p + nlen > list.len() {
            return None;
        }
        if ntype == 0 {
            let raw = &list[p..p + nlen];
            // Hostnames are ASCII; reject anything with control bytes so a
            // malformed packet cannot smuggle junk into the UI.
            if raw.is_empty()
                || raw.len() > 255
                || !raw.iter().all(|b| b.is_ascii_graphic() || *b == b'.')
            {
                return None;
            }
            return Some(
                std::str::from_utf8(raw)
                    .ok()?
                    .trim_end_matches('.')
                    .to_ascii_lowercase(),
            );
        }
        p += nlen;
    }
    None
}

/// Decode a DNS-over-TLS (RFC 7858) length-prefixed payload into a plain message.
pub fn strip_dot_length_prefix(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    payload.get(2..2 + n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-build a minimal ClientHello carrying `sni`.
    fn client_hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);

        let mut exts = Vec::new();
        exts.extend_from_slice(&0u16.to_be_bytes());
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);

        let mut hs = Vec::new();
        hs.push(0x01);
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(1); // compression methods len
        body.push(0); // null compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_sni() {
        assert_eq!(
            extract_sni(&client_hello("www.example.com")).as_deref(),
            Some("www.example.com")
        );
        // Trailing dot and upper case are normalised.
        assert_eq!(
            extract_sni(&client_hello("API.Example.COM.")).as_deref(),
            Some("api.example.com")
        );
    }

    #[test]
    fn rejects_non_clienthello() {
        assert!(extract_sni(&[]).is_none());
        assert!(extract_sni(&[0x17, 0x03, 0x03, 0, 4]).is_none()); // app data
        assert!(extract_sni(b"GET / HTTP/1.1\r\n\r\n").is_none());
        // Truncated record must not panic.
        assert!(extract_sni(&[0x16, 0x03, 0x01, 0xff, 0xff, 0x01]).is_none());
    }

    #[test]
    fn survives_fuzzed_lengths() {
        let good = client_hello("a.b.c");
        for cut in 0..good.len() {
            let _ = extract_sni(&good[..cut]);
        }
    }
}
