//! `etwprobe` -- development probe used to discover the exact payload layout of
//! the ETW providers we consume.
//!
//! It opens a real-time trace session, enables one or more providers with all
//! keywords, and dumps every event (header fields, raw payload hex, and any
//! UTF-16 strings found in the payload). This is how `src/win/dns_payload.rs`
//! was derived; it stays in the tree because it is the tool to reach for when a
//! future Windows build changes an event template.
//!
//! Usage:
//!   etwprobe [seconds] [provider ...]
//!
//! Providers may be given by GUID or by one of the aliases below.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::*;

const DNS_CLIENT: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
const KERNEL_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const KERNEL_PROCESS: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const NT_KERNEL_LOGGER: &str = "9e814aad-3204-11d2-9a82-006008a86939";

/// GUID parser -- accepts "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
fn parse_guid(s: &str) -> Option<windows_sys::core::GUID> {
    let s = s.trim().trim_matches(|c| c == '{' || c == '}');
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return None;
    }
    let d1 = u32::from_str_radix(parts[0], 16).ok()?;
    let d2 = u16::from_str_radix(parts[1], 16).ok()?;
    let d3 = u16::from_str_radix(parts[2], 16).ok()?;
    let b: Vec<u8> = parts[3]
        .as_bytes()
        .chunks(2)
        .chain(parts[4].as_bytes().chunks(2))
        .filter_map(|c| std::str::from_utf8(c).ok())
        .filter_map(|c| u8::from_str_radix(c, 16).ok())
        .collect();
    if b.len() != 8 {
        return None;
    }
    Some(windows_sys::core::GUID {
        data1: d1,
        data2: d2,
        data3: d3,
        data4: [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]],
    })
}

static EVENTS: AtomicU64 = AtomicU64::new(0);
static SEEN: Mutex<Option<HashMap<(u16, u32), u64>>> = Mutex::new(None);

/// Best-effort extraction of NUL-terminated UTF-16LE strings from a payload.
fn utf16_strings(buf: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut cur: Vec<u16> = Vec::new();
    while i + 1 < buf.len() {
        let unit = u16::from_le_bytes([buf[i], buf[i + 1]]);
        if unit == 0 {
            if cur.len() >= 2 {
                out.push(String::from_utf16_lossy(&cur));
            }
            cur.clear();
            i += 2;
            continue;
        }
        // printable ASCII / CJK-ish range
        if (0x20..0x7f).contains(&unit) || (0x4e00..0x9fff).contains(&unit) || unit == 0x2e {
            cur.push(unit);
            i += 2;
        } else {
            cur.clear();
            i += 2;
        }
    }
    out
}

unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let rec = unsafe { &*record };
    let hdr = &rec.EventHeader;
    let n = EVENTS.fetch_add(1, Ordering::Relaxed);

    let payload: &[u8] = if rec.UserData.is_null() || rec.UserDataLength == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(rec.UserData as *const u8, rec.UserDataLength as usize) }
    };

    // Timestamp: 100ns ticks since 1601-01-01 UTC.
    let dt = chrono::DateTime::from_timestamp_nanos(
        (hdr.TimeStamp - 116_444_736_000_000_000) * 100,
    )
    .format("%H:%M:%S%.6f")
    .to_string();

    // Throttle: print the first 25 of each (id, pid, len) shape, then every 200th.
    {
        let mut g = SEEN.lock().unwrap();
        let map = g.get_or_insert_with(HashMap::new);
        let key = (hdr.EventDescriptor.Id, u32::from(rec.UserDataLength));
        let c = map.entry(key).or_insert(0);
        *c += 1;
        if *c > 25 && *c % 200 != 0 {
            return;
        }
    }

    println!(
        "\n[{}] #{} id={} ver={} opcode={} level={} task={} keyword=0x{:x} pid={} tid={} len={} ts={}",
        n,
        n,
        hdr.EventDescriptor.Id,
        hdr.EventDescriptor.Version,
        hdr.EventDescriptor.Opcode,
        hdr.EventDescriptor.Level,
        hdr.EventDescriptor.Task,
        hdr.EventDescriptor.Keyword,
        hdr.ProcessId,
        hdr.ThreadId,
        rec.UserDataLength,
        dt
    );

    let hex: String = payload
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    println!("  hex : {hex}");

    let strs = utf16_strings(payload);
    if !strs.is_empty() {
        println!("  utf16: {strs:?}");
    }
}

struct Session {
    handle: CONTROLTRACE_HANDLE,
    props: Vec<u8>,
    name: Vec<u16>,
}

impl Session {
    fn start(name: &str) -> std::io::Result<Self> {
        let mut name_w: Vec<u16> = name.encode_utf16().collect();
        name_w.push(0);

        // Buffer layout: [EVENT_TRACE_PROPERTIES][logfile name][logger name]
        let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let logger_off = props_size;
        let buf_size = props_size + name_w.len() * 2 + 8;
        let mut buf = vec![0u8; buf_size];
        let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        unsafe {
            (*props).Wnode.BufferSize = buf_size as u32;
            (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*props).BufferSize = 64; // KB per buffer
            (*props).MinimumBuffers = 32;
            (*props).MaximumBuffers = 256;
            (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*props).FlushTimer = 1;
            (*props).LogFileNameOffset = 0;
            (*props).LoggerNameOffset = logger_off as u32;

            let dst = buf.as_mut_ptr().add(logger_off) as *mut u16;
            std::ptr::copy_nonoverlapping(name_w.as_ptr(), dst, name_w.len());
        }

        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        let rc = unsafe { StartTraceW(&mut handle, name_w.as_ptr(), props) };
        if rc == ERROR_ALREADY_EXISTS {
            // Leftover session -- stop it and retry once.
            unsafe {
                ControlTraceW(
                    CONTROLTRACE_HANDLE { Value: 0 },
                    name_w.as_ptr(),
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            let rc = unsafe { StartTraceW(&mut handle, name_w.as_ptr(), props) };
            if rc != ERROR_SUCCESS {
                return Err(std::io::Error::from_raw_os_error(rc as i32));
            }
        } else if rc != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(rc as i32));
        }

        Ok(Session { handle, props: buf, name: name_w })
    }

    fn enable(&self, guid: windows_sys::core::GUID, level: u8, keyword: u64) -> std::io::Result<()> {
        let mut params = ENABLE_TRACE_PARAMETERS::default();
        params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        let rc = unsafe {
            EnableTraceEx2(
                self.handle,
                &guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                level,
                keyword,
                0,
                0,
                &params,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(rc as i32));
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            ControlTraceW(
                self.handle,
                self.name.as_ptr(),
                self.props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let seconds: u64 = args
        .first()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    let aliases = [
        ("dns", DNS_CLIENT),
        ("net", KERNEL_NETWORK),
        ("proc", KERNEL_PROCESS),
        ("kernel", NT_KERNEL_LOGGER),
    ];

    let spec: Vec<(String, windows_sys::core::GUID)> = if args.len() > 1 {
        args[1..]
            .iter()
            .filter_map(|a| {
                let lower = a.to_lowercase();
                let g = aliases
                    .iter()
                    .find(|(n, _)| *n == lower)
                    .and_then(|(_, g)| parse_guid(g))
                    .or_else(|| parse_guid(&lower))?;
                Some((lower, g))
            })
            .collect()
    } else {
        vec![
            ("dns".into(), parse_guid(DNS_CLIENT).unwrap()),
            ("net".into(), parse_guid(KERNEL_NETWORK).unwrap()),
        ]
    };

    let session = match Session::start("NetMonProbe") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to start ETW session: {e} (are you elevated?)");
            std::process::exit(2);
        }
    };

    for (name, guid) in &spec {
        match session.enable(*guid, TRACE_LEVEL_VERBOSE as u8, u64::MAX) {
            Ok(()) => println!("enabled provider {name}"),
            Err(e) => eprintln!("failed to enable {name}: {e}"),
        }
    }

    // Real-time consumer.
    let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
    let mut logger_name: Vec<u16> = "NetMonProbe".encode_utf16().collect();
    logger_name.push(0);
    logfile.LoggerName = logger_name.as_mut_ptr();
    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(on_event);

    let trace = unsafe { OpenTraceW(&mut logfile) };
    if trace.Value == 0 || trace.Value == u64::MAX {
        eprintln!("OpenTrace failed: {}", std::io::Error::last_os_error());
        std::process::exit(3);
    }

    // ProcessTrace blocks; run it on a worker so we can time out.
    let h = trace;
    let worker = std::thread::spawn(move || unsafe {
        let rc = ProcessTrace(&h, 1, std::ptr::null(), std::ptr::null());
        if rc != ERROR_SUCCESS {
            eprintln!("ProcessTrace: {}", std::io::Error::from_raw_os_error(rc as i32));
        }
    });

    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(seconds) {
        std::thread::sleep(Duration::from_millis(500));
        let n = EVENTS.load(Ordering::Relaxed);
        eprint!("\r  ... {n} events, {:.0}s", started.elapsed().as_secs_f64());
        if n > 0 && started.elapsed().as_secs() > 3 && n > 4000 {
            break;
        }
    }
    eprintln!();

    unsafe { CloseTrace(trace) };
    let _ = worker.join();
    drop(session);
    println!("\ntotal events: {}", EVENTS.load(Ordering::Relaxed));
    let _ = std::ptr::null::<c_void>();
}
