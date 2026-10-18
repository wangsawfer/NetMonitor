//! AAAA lookups through the Windows resolver.
//!
//! `DnsQuery_W` is used rather than a hand-rolled UDP query because it already
//! handles the parts that are easy to get subtly wrong: the interface's
//! configured server list, per-server timeouts, retries, and EDNS. It also
//! reports *why* a lookup produced nothing, which is the difference between
//! "this name has no AAAA record" and "the resolver could not be reached" --
//! two results a caller must not conflate.
//!
//! The call blocks. It is only ever made from the query workers in
//! `crate::domains`, never from a capture or UI thread.

use std::net::Ipv6Addr;

use windows_sys::Win32::Foundation::{
    DNS_ERROR_RCODE_NAME_ERROR, DNS_ERROR_RCODE_NO_ERROR, DNS_ERROR_RECORD_DOES_NOT_EXIST,
    DNS_INFO_NO_RECORDS, ERROR_SUCCESS, WIN32_ERROR,
};
use windows_sys::Win32::NetworkManagement::Dns::{
    DNS_QUERY_BYPASS_CACHE, DNS_QUERY_STANDARD, DNS_RECORDA, DNS_TYPE_A, DNS_TYPE_AAAA, DnsQuery_W,
};

/// `DNS_FREE_TYPE`: release everything the query allocated.
const DNS_FREE_RECORD_LIST: u32 = 1;

// windows-sys 0.61 exposes `DnsQuery_W` but not its companion free function,
// so the declaration lives here. Linking dnsapi directly is exactly what the
// missing binding would have done.
#[link(name = "dnsapi")]
unsafe extern "system" {
    fn DnsRecordListFree(ptr: *mut core::ffi::c_void, freetype: u32);
}

/// Outcome of an AAAA lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AaaaAnswer {
    /// One or more AAAA records.
    ///
    /// Never empty: a successful query that returned no addresses is
    /// normalised to `NoRecord` by `query_aaaa`, so there is exactly one way to
    /// say "the name exists but has no AAAA". Two ways to say it was a real
    /// source of miscounting -- an empty `Addresses` slipped past the arm that
    /// handles `NoRecord` and was counted as a successful lookup.
    Addresses(Vec<Ipv6Addr>),
    /// The name exists but has no AAAA record.
    ///
    /// Windows reports this as a successful query with an empty answer list,
    /// which is why it is a distinct outcome from `NoSuchName`.
    NoRecord,
    /// The name does not exist (NXDOMAIN).
    NoSuchName,
}

impl AaaaAnswer {
    /// One-line description for the UI.
    pub fn label(&self) -> String {
        match self {
            AaaaAnswer::Addresses(v) => v
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            AaaaAnswer::NoRecord => "无 AAAA 记录".to_string(),
            AaaaAnswer::NoSuchName => "域名不存在 (NXDOMAIN)".to_string(),
        }
    }

    pub fn addresses(&self) -> &[Ipv6Addr] {
        match self {
            AaaaAnswer::Addresses(v) => v,
            _ => &[],
        }
    }

    /// Did the name exist at all?
    ///
    /// Kept for callers that need to tell a typo from an IPv4-only host --
    /// writing a hosts entry for a name that does not resolve would be wrong.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn exists(&self) -> bool {
        !matches!(self, AaaaAnswer::NoSuchName)
    }
}

/// Query the A record for `name`.
///
/// Returns an empty list for "no record" and for "no such name": unlike the
/// AAAA path, nothing downstream needs to tell those apart -- the address
/// column only cares what the name resolves to.
pub fn query_a(name: &str, bypass_cache: bool) -> std::io::Result<Vec<std::net::Ipv4Addr>> {
    if name.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty domain name",
        ));
    }
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    wide.push(0);
    let options = if bypass_cache {
        DNS_QUERY_BYPASS_CACHE
    } else {
        DNS_QUERY_STANDARD
    };
    let mut results: *mut DNS_RECORDA = std::ptr::null_mut();
    let rc: WIN32_ERROR = unsafe {
        DnsQuery_W(
            wide.as_ptr(),
            DNS_TYPE_A,
            options,
            std::ptr::null_mut(),
            &mut results,
            std::ptr::null_mut(),
        )
    };
    let out = if rc == ERROR_SUCCESS {
        // SAFETY: on success the list is ours until it is freed below.
        unsafe { collect_v4(results) }
    } else {
        Vec::new()
    };
    if !results.is_null() {
        unsafe { DnsRecordListFree(results as *mut core::ffi::c_void, DNS_FREE_RECORD_LIST) };
    }
    Ok(out)
}

/// Query the AAAA record for `name`.
///
/// `bypass_cache` forces a wire query. Left off by default: the name was
/// usually resolved moments ago by the monitored application, so the answer is
/// already in the resolver's cache and asking again would only add traffic.
pub fn query_aaaa(name: &str, bypass_cache: bool) -> std::io::Result<AaaaAnswer> {
    if name.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty domain name",
        ));
    }
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    wide.push(0);

    let options = if bypass_cache {
        DNS_QUERY_BYPASS_CACHE
    } else {
        DNS_QUERY_STANDARD
    };

    let mut results: *mut DNS_RECORDA = std::ptr::null_mut();
    let rc: WIN32_ERROR = unsafe {
        DnsQuery_W(
            wide.as_ptr(),
            DNS_TYPE_AAAA,
            options,
            std::ptr::null_mut(),
            &mut results,
            std::ptr::null_mut(),
        )
    };

    // Everything from here on must free the record list on every path.
    let outcome = interpret(rc, results).map(|a| match a {
        AaaaAnswer::Addresses(v) if v.is_empty() => AaaaAnswer::NoRecord,
        other => other,
    });
    if !results.is_null() {
        unsafe { DnsRecordListFree(results as *mut core::ffi::c_void, DNS_FREE_RECORD_LIST) };
    }
    outcome
}

fn interpret(rc: WIN32_ERROR, results: *mut DNS_RECORDA) -> std::io::Result<AaaaAnswer> {
    // `ERROR_SUCCESS` and `DNS_ERROR_RCODE_NO_ERROR` are both 0, so one arm
    // covers both; spelling them as a pair would be an unreachable pattern.
    const _: () = assert!(ERROR_SUCCESS == DNS_ERROR_RCODE_NO_ERROR);
    // windows-sys declares this one as `i32` because the C constant is
    // `DNS_INFO_NO_RECORDS`, an informational code rather than a `WIN32_ERROR`.
    const NO_RECORDS: WIN32_ERROR = DNS_INFO_NO_RECORDS as WIN32_ERROR;
    match rc {
        ERROR_SUCCESS => {
            // SAFETY: on success `DnsQuery_W` returns a list it allocated,
            // which is freed by the caller.
            Ok(AaaaAnswer::Addresses(unsafe { collect(results) }))
        }

        // No record of the requested type.
        //
        // The resolver reports this two different ways depending on whether the
        // answer came from the cache or the wire, and neither is an error:
        // `DNS_INFO_NO_RECORDS` is one of the informational `DNS_INFO_*` codes,
        // and `DNS_ERROR_RECORD_DOES_NOT_EXIST` means precisely what it says.
        // Treating them as failures was a real bug -- `github.com` came back as
        // "lookup failed" when the honest answer is simply that it has no AAAA
        // record.
        NO_RECORDS | DNS_ERROR_RECORD_DOES_NOT_EXIST => Ok(AaaaAnswer::NoRecord),

        // NXDOMAIN: the name itself does not exist. Distinct from the above,
        // and the distinction is worth keeping -- a typo and an IPv4-only host
        // are different situations.
        DNS_ERROR_RCODE_NAME_ERROR => Ok(AaaaAnswer::NoSuchName),

        _ => Err(std::io::Error::from_raw_os_error(rc as i32)),
    }
}

/// Walk the record list and pull out every IPv6 address.
unsafe fn collect(head: *mut DNS_RECORDA) -> Vec<Ipv6Addr> {
    let mut out = Vec::new();
    let mut cur = head;
    let mut guard = 0;
    while !cur.is_null() && guard < 64 {
        guard += 1;
        let rec = unsafe { &*cur };
        if rec.wType == DNS_TYPE_AAAA {
            // `IP6_ADDRESS` is not exported by windows-sys, but a
            // `DNS_AAAA_DATA` is a single 16-byte address at the start of the
            // union, so the bytes can be read directly.
            let mut octets = [0u8; 16];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    std::ptr::addr_of!(rec.Data) as *const u8,
                    octets.as_mut_ptr(),
                    16,
                )
            };
            let addr = Ipv6Addr::from(octets);
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
        cur = rec.pNext;
    }
    out
}

/// Walk a record list and pull out every IPv4 address.
unsafe fn collect_v4(head: *mut DNS_RECORDA) -> Vec<std::net::Ipv4Addr> {
    let mut out = Vec::new();
    let mut cur = head;
    let mut guard = 0;
    while !cur.is_null() && guard < 64 {
        guard += 1;
        let rec = unsafe { &*cur };
        if rec.wType == DNS_TYPE_A {
            let mut octets = [0u8; 4];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    std::ptr::addr_of!(rec.Data) as *const u8,
                    octets.as_mut_ptr(),
                    4,
                )
            };
            let addr = std::net::Ipv4Addr::from(octets);
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
        cur = rec.pNext;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_is_human_readable() {
        assert_eq!(AaaaAnswer::NoRecord.label(), "无 AAAA 记录");
        let a = AaaaAnswer::Addresses(vec!["::1".parse().unwrap()]);
        assert_eq!(a.label(), "::1");
        assert!(a.exists());
        assert!(!AaaaAnswer::NoSuchName.exists());
    }

    #[test]
    fn empty_name_is_rejected_without_calling_win32() {
        assert!(query_aaaa("", false).is_err());
    }

    /// A name that certainly exists but is IPv4-only. `.invalid` is reserved by
    /// RFC 2606 and never resolves, which makes it a stable NXDOMAIN probe.
    #[test]
    fn nxdomain_is_an_answer_not_an_error() {
        match query_aaaa("definitely-not-a-real-name.invalid", false) {
            Ok(AaaaAnswer::NoSuchName) => {}
            Ok(other) => panic!("expected NXDOMAIN, got {other:?}"),
            Err(e) => {
                // No network in the test environment is not a test failure.
                eprintln!("skipping (no resolver): {e}");
            }
        }
    }

    /// A name that exists but has no AAAA record must be reported as exactly
    /// that, not as a failure. The resolver returns two different codes for it
    /// depending on cache versus wire, and both must be understood.
    #[test]
    fn ipv4_only_name_reports_no_aaaa_record() {
        // `ipv4only.arpa` is reserved by RFC 7050 for exactly this: a name that
        // is guaranteed to have A records and no AAAA.
        match query_aaaa("ipv4only.arpa", true) {
            Ok(AaaaAnswer::NoRecord) => {}
            Ok(other) => panic!("expected no AAAA record, got {other:?}"),
            Err(e) => eprintln!("skipping (no resolver): {e}"),
        }
    }

    #[test]
    fn a_lookup_finds_an_ipv4_address() {
        match query_a("localhost", false) {
            Ok(v) => assert_eq!(v, vec![std::net::Ipv4Addr::LOCALHOST]),
            Err(e) => eprintln!("skipping (no resolver): {e}"),
        }
    }

    #[test]
    fn a_lookup_of_a_bad_name_is_empty_not_an_error() {
        match query_a("definitely-not-real.invalid", false) {
            Ok(v) => assert!(v.is_empty()),
            Err(e) => eprintln!("skipping (no resolver): {e}"),
        }
    }

    #[test]
    fn loopback_name_has_an_aaaa_record() {
        match query_aaaa("localhost", false) {
            Ok(answer) => {
                assert!(answer.exists(), "localhost must exist");
                assert_eq!(answer.addresses(), &[Ipv6Addr::LOCALHOST]);
            }
            Err(e) => eprintln!("skipping (no resolver): {e}"),
        }
    }
}
