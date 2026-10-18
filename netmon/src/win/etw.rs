//! Minimal, allocation-free ETW (Event Tracing for Windows) real-time consumer.
//!
//! Only the parts the monitor needs are implemented:
//!
//! * a real-time trace session (`StartTraceW` / `ControlTraceW`),
//! * provider enablement at a chosen level and keyword mask (`EnableTraceEx2`),
//! * a real-time consumer that blocks in `ProcessTrace` and delivers events
//!   through a callback (`OpenTraceW` + `PROCESS_TRACE_MODE_EVENT_RECORD`).
//!
//! The consumer callback runs on the `ProcessTrace` thread. It must be fast,
//! must never block, and must never panic across the FFI boundary -- a panic is
//! caught and counted rather than allowed to unwind into Windows.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS, WIN32_ERROR};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, ENABLE_TRACE_PARAMETERS,
    ENABLE_TRACE_PARAMETERS_VERSION_2, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
    EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
    ProcessTrace, QueryAllTracesW, StartTraceW, WNODE_FLAG_TRACED_GUID,
};

/// Borrowed view over one ETW event. Valid only for the duration of the
/// callback; copying out of it is the callback's job.
pub struct EventView<'a> {
    pub id: u16,
    pub pid: u32,
    /// 100 ns ticks since 1601-01-01 UTC.
    pub ts_100ns: i64,
    pub payload: &'a [u8],
}

/// Callback shape used by `EtwConsumer`.
pub type EventFn = dyn Fn(&EventView<'_>) + Send + Sync + 'static;

/// Storage for `EVENT_TRACE_PROPERTIES` plus the trailing logger-name string
/// that `StartTraceW` requires to live inside the same allocation.
///
/// `EVENT_TRACE_PROPERTIES` has 8-byte alignment (it embeds a `HANDLE`), so a
/// `Vec<u64>` is already correctly aligned and needs no manual fix-up.
struct PropsBlock {
    words: Vec<u64>,
}

impl PropsBlock {
    fn new(byte_len: usize) -> Self {
        let words = byte_len.div_ceil(8) + 1;
        Self {
            words: vec![0u64; words],
        }
    }

    fn as_props_mut(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.words.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
    }

    fn byte_ptr(&mut self, offset: usize) -> *mut u8 {
        // SAFETY: offset is validated by the caller against `byte_capacity`.
        unsafe { (self.words.as_mut_ptr() as *mut u8).add(offset) }
    }

    fn byte_capacity(&self) -> usize {
        self.words.len() * 8
    }

    /// Read back a `u32` field of the properties block.
    fn read_u32(&self, byte_offset: usize) -> u32 {
        debug_assert!(byte_offset + 4 <= self.byte_capacity());
        unsafe { *((self.words.as_ptr() as *const u8).add(byte_offset) as *const u32) }
    }
}

// ---------------------------------------------------------------------------
// Trace session (the controller side)
// ---------------------------------------------------------------------------

/// Byte offset of `EventsLost` inside `EVENT_TRACE_PROPERTIES`; used to read the
/// drop counter back after an `EVENT_TRACE_CONTROL_QUERY`.
const OFFSET_EVENTS_LOST: usize = std::mem::offset_of!(EVENT_TRACE_PROPERTIES, EventsLost);

/// A real-time ETW trace session. Dropping it stops the session.
pub struct EtwSession {
    handle: CONTROLTRACE_HANDLE,
    name: Vec<u16>,
    props: PropsBlock,
}

impl EtwSession {
    /// Start a session with the given name.
    ///
    /// `buffer_kb` / `min_buffers` / `max_buffers` size the kernel-side ring.
    /// Oversizing is cheap (the buffers are paged, not resident) and is the
    /// single most effective defence against `EventsLost` during a burst.
    pub fn start(
        name: &str,
        buffer_kb: u32,
        min_buffers: u32,
        max_buffers: u32,
    ) -> std::io::Result<Self> {
        let _ = &name;
        Self::start_inner(name, buffer_kb, min_buffers, max_buffers)
    }

    /// # Why this is not a private logger
    ///
    /// An ordinary real-time session outlives the process that started it: kill
    /// NetMonitor (Task Manager, a closed window, a crash) and the session stays
    /// registered, holding kernel ETW resources. Enough of them accumulate and
    /// `EnableTraceEx2` starts failing with `ERROR_NO_SYSTEM_RESOURCES` (1450),
    /// at which point the primary data source is dead and the tool looks like it
    /// produces nothing at all.
    ///
    /// `EVENT_TRACE_PRIVATE_LOGGER_MODE` is the documented cure -- the kernel
    /// tears the session down with the process. It was tried and **rejected**:
    /// on Windows 11 26100 `StartTraceW` refuses every private-mode combination
    /// with `ERROR_INVALID_PARAMETER` (87), alone, with
    /// `EVENT_TRACE_PRIVATE_IN_PROC`, and with an explicit session GUID.
    /// `etw::tests::probe_accepted_logfile_modes` reproduces that measurement.
    ///
    /// The leak is instead handled by `stop_stale_sessions`, which removes
    /// sessions whose owning process is gone, and by retrying once after a
    /// resource-exhaustion failure.
    fn start_inner(
        name: &str,
        buffer_kb: u32,
        min_buffers: u32,
        max_buffers: u32,
    ) -> std::io::Result<Self> {
        let mut name_w: Vec<u16> = name.encode_utf16().collect();
        name_w.push(0);

        let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let logger_off = props_size;
        let total = props_size + name_w.len() * 2 + 8;
        let mut props = PropsBlock::new(total);

        {
            let p = props.as_props_mut();
            unsafe {
                (*p).Wnode.BufferSize = total as u32;
                (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
                (*p).BufferSize = buffer_kb;
                (*p).MinimumBuffers = min_buffers;
                (*p).MaximumBuffers = max_buffers;
                (*p).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
                (*p).FlushTimer = 1; // seconds; bounds how long an event can sit
                (*p).LogFileNameOffset = 0; // real-time only
                (*p).LoggerNameOffset = logger_off as u32;
            }
        }
        let dst = props.byte_ptr(logger_off) as *mut u16;
        // SAFETY: `logger_off + name_w.len()*2` is inside the block allocated
        // above (total = props_size + name_w.len()*2 + 8), and `dst` is derived
        // from the same allocation.
        unsafe { std::ptr::copy_nonoverlapping(name_w.as_ptr(), dst, name_w.len()) };

        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        let mut rc: WIN32_ERROR =
            unsafe { StartTraceW(&mut handle, name_w.as_ptr(), props.as_props_mut()) };
        if rc == ERROR_ALREADY_EXISTS {
            // A previous run (possibly a crashed one) left the session behind.
            // Stop it and retry once -- this makes the tool self-healing.
            unsafe {
                ControlTraceW(
                    CONTROLTRACE_HANDLE { Value: 0 },
                    name_w.as_ptr(),
                    props.as_props_mut(),
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            rc = unsafe { StartTraceW(&mut handle, name_w.as_ptr(), props.as_props_mut()) };
        }
        if rc != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(rc as i32));
        }

        Ok(Self {
            handle,
            name: name_w,
            props,
        })
    }

    /// Enable a provider by GUID. `keyword` is a bit mask; `u64::MAX` means
    /// "everything this provider emits".
    pub fn enable(
        &self,
        guid: &windows_sys::core::GUID,
        level: u8,
        keyword: u64,
    ) -> std::io::Result<()> {
        let mut params = ENABLE_TRACE_PARAMETERS::default();
        params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        let rc = unsafe {
            EnableTraceEx2(
                self.handle,
                guid,
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

    pub fn stop(&mut self) {
        if self.handle.Value == 0 {
            return;
        }
        unsafe {
            ControlTraceW(
                self.handle,
                self.name.as_ptr(),
                self.props.as_props_mut(),
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        self.handle = CONTROLTRACE_HANDLE { Value: 0 };
    }

    /// Number of events the kernel dropped because the consumer could not keep
    /// up. Queried live so the UI can show an honest health indicator.
    ///
    /// Note: the query rewrites the properties block, so callers must not hold
    /// on to anything read from it.
    pub fn events_lost(&mut self) -> u32 {
        if self.handle.Value == 0 {
            return 0;
        }
        let rc = unsafe {
            ControlTraceW(
                self.handle,
                std::ptr::null(),
                self.props.as_props_mut(),
                EVENT_TRACE_CONTROL_QUERY,
            )
        };
        if rc == ERROR_SUCCESS {
            self.props.read_u32(OFFSET_EVENTS_LOST)
        } else {
            0
        }
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        self.stop();
    }
}

// ---------------------------------------------------------------------------
// Consumer
// ---------------------------------------------------------------------------

/// Runs `ProcessTrace` on a dedicated thread and forwards events to a callback.
pub struct EtwConsumer {
    logfile: Box<EVENT_TRACE_LOGFILEW>,
    /// Heap buffer that `logfile.LoggerName` points into. Boxed so the address
    /// stays stable even when this struct moves.
    logger_name: Box<[u16]>,
    handle: PROCESSTRACE_HANDLE,
    thread: Option<std::thread::JoinHandle<()>>,
    /// Owned callback; `logfile.Context` points at it and it stays valid until
    /// `stop()` has joined the delivery thread. Never read directly -- its job
    /// is to own the allocation the trampoline dereferences.
    _callback: Box<CallbackSlot>,
    started: Arc<AtomicBool>,
}

struct CallbackSlot {
    f: Box<EventFn>,
}

unsafe extern "system" fn trampoline(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let rec = unsafe { &*record };
    let ctx = rec.UserContext as *const CallbackSlot;
    if ctx.is_null() {
        return;
    }
    let payload = if rec.UserData.is_null() || rec.UserDataLength == 0 {
        &[][..]
    } else {
        unsafe {
            std::slice::from_raw_parts(rec.UserData as *const u8, rec.UserDataLength as usize)
        }
    };
    let h = &rec.EventHeader;
    let view = EventView {
        id: h.EventDescriptor.Id,
        pid: h.ProcessId,
        ts_100ns: h.TimeStamp,
        payload,
    };
    // Never let a panic unwind into Windows.
    let slot = unsafe { &*ctx };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (slot.f)(&view)));
}

impl EtwConsumer {
    /// Open a real-time consumer for the session called `name`.
    pub fn start<F>(name: &str, callback: F) -> std::io::Result<Self>
    where
        F: Fn(&EventView<'_>) + Send + Sync + 'static,
    {
        let mut name_w: Vec<u16> = name.encode_utf16().collect();
        name_w.push(0);

        let callback = Box::new(CallbackSlot {
            f: Box::new(callback),
        });
        let logger_name = name_w.into_boxed_slice();
        let mut logfile: Box<EVENT_TRACE_LOGFILEW> = Box::new(unsafe { std::mem::zeroed() });
        logfile.LoggerName = logger_name.as_ptr() as *mut u16;
        logfile.Context = (&*callback as *const CallbackSlot) as *mut core::ffi::c_void;
        // Writing a union field is safe; only reading one is not.
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(trampoline);

        let handle = unsafe { OpenTraceW(&mut *logfile) };
        if handle.Value == 0 || handle.Value == u64::MAX {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            logfile,
            logger_name,
            handle,
            thread: None,
            _callback: callback,
            started: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Begin consuming. `ProcessTrace` blocks the calling thread until
    /// `stop()` is called, so it gets a thread of its own.
    pub fn spawn(&mut self) {
        let handle = self.handle;
        let started = self.started.clone();
        self.thread = Some(std::thread::spawn(move || {
            started.store(true, Ordering::SeqCst);
            let rc = unsafe { ProcessTrace(&handle, 1, std::ptr::null(), std::ptr::null()) };
            // ERROR_CANCELLED (1223) is the normal shutdown path.
            if rc != ERROR_SUCCESS && rc != 1223 {
                eprintln!("[etw] ProcessTrace ended with 0x{rc:x}");
            }
        }));
        // Give ProcessTrace a moment to enter its wait loop so that an
        // immediate `stop()` cannot race it.
        for _ in 0..500 {
            if self.started.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// Close the consumer and join the delivery thread. Idempotent.
    pub fn stop(&mut self) {
        if self.handle.Value == 0 {
            return;
        }
        unsafe { CloseTrace(self.handle) };
        self.handle = PROCESSTRACE_HANDLE { Value: 0 };
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for EtwConsumer {
    fn drop(&mut self) {
        self.stop();
        // `logger_name` and `callback` are owned boxes; dropping them here is
        // safe because the ProcessTrace thread has been joined above.
        self.logfile.LoggerName = std::ptr::null_mut();
        let _ = &self.logger_name;
    }
}

/// Every session name this program creates is `<prefix>-<pid>`, so a leftover
/// session can be tied back to the process that made it.
pub const SESSION_NAME_PREFIX: &str = "NetMonitor";

/// Enumerate the trace sessions this program could have created.
///
/// Returns `(name, owning_pid)` for every session whose name matches
/// `<prefix>-<digits>`.
fn enumerate_own_sessions(prefix: &str) -> Vec<(String, u32)> {
    /// Room for EVENT_TRACE_PROPERTIES plus a 128-character logger name.
    const BLOCK: usize = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 512;
    const MAX_SESSIONS: u32 = 256;

    let mut found = Vec::new();
    let mut blocks: Vec<Vec<u64>> = (0..MAX_SESSIONS)
        .map(|_| vec![0u64; BLOCK.div_ceil(8)])
        .collect();
    // QueryAllTracesW requires the caller to size every entry up front; leaving
    // Wnode.BufferSize at zero makes the call report no sessions at all, which
    // is exactly how the first version of this sweep silently did nothing.
    for b in blocks.iter_mut() {
        let p = b.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        unsafe {
            (*p).Wnode.BufferSize = BLOCK as u32;
        }
    }
    let mut pointers: Vec<*mut EVENT_TRACE_PROPERTIES> = blocks
        .iter_mut()
        .map(|b| b.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES)
        .collect();

    let mut count: u32 = 0;
    let rc = unsafe { QueryAllTracesW(pointers.as_mut_ptr(), MAX_SESSIONS, &mut count) };
    if rc != ERROR_SUCCESS {
        eprintln!("[etw] session enumeration failed: rc={rc}");
        return found;
    }

    for block in blocks.iter_mut().take(count as usize) {
        // SAFETY: the block was filled in by QueryAllTracesW.
        let name = unsafe {
            let props = block.as_ptr() as *const EVENT_TRACE_PROPERTIES;
            let off = (*props).LoggerNameOffset as usize;
            if off == 0 || off + 2 >= block.len() * 8 {
                continue;
            }
            let base = block.as_ptr() as *const u8;
            let mut len = 0usize;
            while len < 128 {
                let lo = *base.add(off + len * 2);
                let hi = *base.add(off + len * 2 + 1);
                if lo == 0 && hi == 0 {
                    break;
                }
                len += 1;
            }
            let units = std::slice::from_raw_parts(base.add(off) as *const u16, len);
            String::from_utf16_lossy(units)
        };

        if let Some(pid) = parse_session_pid(prefix, &name) {
            found.push((name, pid));
        }
    }
    found
}

/// `<prefix>-<pid>` or `<prefix><tag>-<pid>` -> `Some(pid)`.
///
/// The looser form matters: a caller that passes its own `--session-name`
/// (the GUI used to do exactly that) creates `NetMonitorGUI-1234`, and a
/// stricter parse silently excluded those from the stale-session sweep --
/// which is how they accumulated until ETW started refusing to start at all.
/// The liveness check below is what keeps this safe, not the name shape.
fn parse_session_pid(prefix: &str, name: &str) -> Option<u32> {
    let rest = name.strip_prefix(prefix)?;
    rest.rsplit('-').next()?.parse::<u32>().ok()
}

/// Stop trace sessions left behind by NetMonitor runs that ended without
/// cleaning up -- a kill from Task Manager, a closed window, a crash.
///
/// A leftover session is not merely untidy: an ordinary real-time session
/// survives its creator, keeps consuming kernel ETW resources, and once enough
/// have piled up `EnableTraceEx2` fails with `ERROR_NO_SYSTEM_RESOURCES`
/// (1450). At that point the primary data source is dead and the tool appears
/// to produce nothing at all -- an empty list with no obvious cause.
///
/// # Safety of the liveness test
///
/// A session is only stopped when the process named in it is **gone**, or when
/// it is alive but is not `netmon.exe` (a recycled PID). A second instance the
/// user is deliberately running is therefore left alone. When `force` is set,
/// nothing is spared -- that is the explicit `--clean-sessions` request.
///
/// Returns the names actually stopped. Requires elevation.
pub fn stop_stale_sessions(prefix: &str, keep: &str, force: bool) -> Vec<String> {
    let mut stopped = Vec::new();
    for (name, pid) in enumerate_own_sessions(prefix) {
        if name == keep {
            continue;
        }
        if !force {
            let alive = crate::win::proctree::image_name(pid)
                .is_some_and(|n| n.eq_ignore_ascii_case("netmon.exe"));
            if alive {
                continue;
            }
        }
        if stop_session_by_name(&name) {
            stopped.push(name);
        }
    }
    stopped
}

fn stop_session_by_name(name: &str) -> bool {
    let mut name_w: Vec<u16> = name.encode_utf16().collect();
    name_w.push(0);
    let total = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + name_w.len() * 2 + 8;
    let mut words = vec![0u64; total.div_ceil(8) + 1];
    let p = words.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*p).Wnode.BufferSize = total as u32;
        (*p).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        let rc = ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            name_w.as_ptr(),
            p,
            EVENT_TRACE_CONTROL_STOP,
        );
        rc == ERROR_SUCCESS
    }
}

/// Well-known provider GUIDs used by the monitor.
pub mod providers {
    use windows_sys::core::GUID;

    /// `Microsoft-Windows-DNS-Client`.
    ///
    /// Emits event 3006 ("a DNS query is being issued") and 3008 ("the query
    /// completed") *in the context of the calling process*, so
    /// `EVENT_HEADER.ProcessId` is the PID that asked for the name. Verified on
    /// Windows 11 26100 against `ping.exe` and `msedge.exe`.
    pub const DNS_CLIENT: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);

    /// `Microsoft-Windows-Kernel-Network`.
    ///
    /// Not subscribed by the default build. It is documented here because it is
    /// the provider to reach for when per-connection attribution is needed: its
    /// events carry the owning PID for TCP/UDP flows. `etwprobe` can subscribe
    /// to it via the `net` alias.
    #[cfg_attr(not(test), allow(dead_code))]
    pub const KERNEL_NETWORK: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn props_block_layout_is_sane() {
        let mut b = PropsBlock::new(4096);
        assert!(b.byte_capacity() >= 4096);
        assert_eq!(b.as_props_mut() as usize % 8, 0);
        assert!(OFFSET_EVENTS_LOST + 4 <= std::mem::size_of::<EVENT_TRACE_PROPERTIES>());
    }

    #[test]
    fn session_lifecycle() {
        // Requires elevation; skips quietly for unprivileged developers.
        let name = format!("NetMonTest-{}", std::process::id());
        let mut s = match EtwSession::start(&name, 64, 8, 64) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping (needs elevation): {e}");
                return;
            }
        };
        s.enable(&providers::DNS_CLIENT, 5, u64::MAX).unwrap();
        assert_eq!(s.events_lost(), 0);

        let seen = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let seen2 = seen.clone();
        let mut c = EtwConsumer::start(&name, move |_e| {
            seen2.fetch_add(1, Ordering::Relaxed);
        })
        .unwrap();
        c.spawn();
        std::thread::sleep(std::time::Duration::from_millis(300));
        c.stop();
        drop(c);
        s.stop();
    }
}

#[cfg(test)]
mod mode_probe {
    //! Temporary diagnostic: find which LogFileMode combinations `StartTraceW`
    //! actually accepts on this build. Run with:
    //!   cargo test --bin netmon mode_probe -- --nocapture --test-threads=1
    use super::*;
    use windows_sys::Win32::System::Diagnostics::Etw::*;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;

    fn try_mode(label: &str, mode: u32, with_guid: bool) {
        let name = format!("NetMonProbe-{:x}-{}", mode, std::process::id());
        let mut name_w: Vec<u16> = name.encode_utf16().collect();
        name_w.push(0);

        let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let total = props_size + name_w.len() * 2 + 8;
        let mut words = vec![0u64; total.div_ceil(8) + 1];
        let p = words.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        unsafe {
            (*p).Wnode.BufferSize = total as u32;
            (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            if with_guid {
                (*p).Wnode.Guid = windows_sys::core::GUID::from_u128(
                    0x4d3f7a10_0001_4000_8000_000000000001,
                );
            }
            (*p).BufferSize = 64;
            (*p).MinimumBuffers = 8;
            (*p).MaximumBuffers = 64;
            (*p).LogFileMode = mode;
            (*p).FlushTimer = 1;
            (*p).LoggerNameOffset = props_size as u32;
            let dst = (words.as_mut_ptr() as *mut u8).add(props_size) as *mut u16;
            std::ptr::copy_nonoverlapping(name_w.as_ptr(), dst, name_w.len());
        }
        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        let rc = unsafe { StartTraceW(&mut handle, name_w.as_ptr(), p) };
        if rc == ERROR_SUCCESS {
            println!("  {label:<52} OK");
            unsafe {
                ControlTraceW(handle, name_w.as_ptr(), p, EVENT_TRACE_CONTROL_STOP);
            }
        } else {
            println!("  {label:<52} FAIL rc={rc} ({})", std::io::Error::from_raw_os_error(rc as i32));
        }
    }

    #[test]
    fn which_logfile_modes_are_accepted() {
        println!("LogFileMode probe:");
        try_mode("REAL_TIME", EVENT_TRACE_REAL_TIME_MODE, false);
        try_mode("REAL_TIME|PRIVATE_LOGGER", EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_PRIVATE_LOGGER_MODE, false);
        try_mode("REAL_TIME|PRIVATE_LOGGER|GUID", EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_PRIVATE_LOGGER_MODE, true);
        try_mode("REAL_TIME|PRIVATE_IN_PROC", EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_PRIVATE_IN_PROC, false);
        try_mode(
            "REAL_TIME|PRIVATE_LOGGER|PRIVATE_IN_PROC",
            EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_PRIVATE_LOGGER_MODE | EVENT_TRACE_PRIVATE_IN_PROC,
            false,
        );
        try_mode(
            "REAL_TIME|PRIVATE_LOGGER|PRIVATE_IN_PROC|GUID",
            EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_PRIVATE_LOGGER_MODE | EVENT_TRACE_PRIVATE_IN_PROC,
            true,
        );
    }
}
