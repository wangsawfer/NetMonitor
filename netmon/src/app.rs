//! Session orchestration: capture lifecycle, target launch, background watcher.
//!
//! The ordering rule the task calls out -- *start monitoring, then start the
//! application* -- is enforced structurally: `Session::start_capture` must
//! succeed before `Session::launch_target` is allowed to run.
//!
//! The terminal front-end that used to consume parts of this API has been
//! removed. What remains is used by headless mode, by the graphical front-end
//! through the command channel, or by the tests at the bottom of this file; the
//! diagnostic accessors are kept because they are the session's own surface and
//! a future front-end would otherwise have to re-derive them.
#![allow(dead_code)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crossbeam_channel::{Sender, bounded};

use crate::capture::etw_dns::EtwDnsSource;
use crate::capture::pcap_capture::PcapSource;
use crate::model::RawEvent;
use crate::pipeline::{Pipeline, QUEUE_CAPACITY};
use crate::store::Store;
use crate::win::proctree::{SWEEP_INTERVAL_MS, TreeTracker};

/// A note surfaced to the user (a degraded source, a warning, ...).
#[derive(Clone, Debug)]
pub struct Note {
    pub at: Instant,
    pub level: NoteLevel,
    pub text: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NoteLevel {
    Info,
    Warn,
    Error,
}

/// Which sources the user wants. Both are on by default; the fallback exists so
/// a machine without Npcap (or without elevation) still produces useful data.
#[derive(Clone, Debug)]
pub struct SourceOptions {
    pub use_etw: bool,
    pub use_npcap: bool,
    pub include_loopback: bool,
    /// Operator-supplied BPF program; `None` uses the built-in candidates.
    pub bpf_override: Option<String>,
}

impl Default for SourceOptions {
    fn default() -> Self {
        Self {
            use_etw: true,
            use_npcap: true,
            include_loopback: false,
            bpf_override: None,
        }
    }
}

/// The whole monitor, minus the UI.
pub struct Session {
    pub store: Arc<Mutex<Store>>,
    pub tree: Arc<Mutex<TreeTracker>>,
    /// PIDs proven foreign; shared with the ETW callback as a negative filter.
    foreign: Arc<RwLock<HashSet<u32>>>,
    tx: Option<Sender<RawEvent>>,
    etw: Option<EtwDnsSource>,
    pcap: Option<PcapSource>,
    pipeline: Option<Pipeline>,
    watcher: Option<std::thread::JoinHandle<()>>,
    watcher_stop: Arc<AtomicBool>,
    /// Mirrors `ViewFilter::show_unattributed` into the pipeline, so rows with
    /// no identifiable owner are rejected at the source rather than merely
    /// hidden by the view.
    pub include_unattributed: Arc<AtomicBool>,

    pub target_paths: Vec<PathBuf>,
    pub target_args: Vec<String>,
    /// Every process this session launched. More than one when several targets
    /// were given; each one becomes a root of the same monitored tree.
    pub children: Vec<Child>,
    pub child_pids: Vec<u32>,
    pub started_at: Option<Instant>,
    pub notes: Vec<Note>,
    pub options: SourceOptions,
    pub etw_session_name: String,
    pub cpu: CpuMeter,
    /// Per-process domain tables and their AAAA lookups.
    ///
    /// Built once for the session rather than per capture run, so the tables
    /// survive a stop/start cycle and stay comparable across runs.
    pub domains: Arc<crate::domains::DomainIntel>,
    /// Whether newly seen domains are handed to the AAAA querier.
    pub aaaa_enabled: bool,
    /// Override for the hosts file path (tests, and unusual layouts).
    pub hosts_file: Option<std::path::PathBuf>,
    /// Override for the backup directory.
    pub hosts_backup_dir: Option<std::path::PathBuf>,
    /// What to do with domains that have no usable IPv6 address.
    pub no_aaaa_policy: crate::hosts::NoAaaaPolicy,
    /// Automatic mode: when on, the selected process's domain table is written
    /// to the hosts file whenever it changes.
    pub hosts_auto: HostsAuto,
    /// Image names to attach to at startup, for processes already running.
    pub attach_names: Vec<String>,
    /// Image names to adopt on sight, for the whole session. See
    /// `Session::set_watch_names`.
    pub watch_names: Vec<String>,
    /// Image names of the processes we launched, used to notice a hand-off to
    /// an already-running instance (see `detect_handoff`).
    launched_images: Vec<String>,
    /// Hand-off already reported, per image name, so it is said once.
    handoff_reported: HashSet<String>,
    /// Detach the target's standard handles from our console. See
    /// `launch_target` for why this matters.
    pub silence_child: bool,
    /// Where the domain-table snapshot and the hosts change log live.
    ///
    /// `None` disables persistence entirely, which is what tests get: they must
    /// not write into the executable's directory.
    pub data_dir: Option<PathBuf>,
    /// When the snapshot was last written, for the periodic save.
    last_cache_save: Option<Instant>,
}

impl Session {
    pub fn new(options: SourceOptions, etw_session_name: String) -> Self {
        let aaaa_workers = crate::domains::DEFAULT_WORKERS;
        let aaaa_bypass_cache = false;
        let aaaa_enabled = true;
        Self {
            store: Arc::new(Mutex::new(Store::new(crate::store::DEFAULT_CAPACITY))),
            tree: Arc::new(Mutex::new(TreeTracker::new())),
            foreign: Arc::new(RwLock::new(HashSet::new())),
            tx: None,
            etw: None,
            pcap: None,
            pipeline: None,
            watcher: None,
            watcher_stop: Arc::new(AtomicBool::new(false)),
            include_unattributed: Arc::new(AtomicBool::new(false)),
            target_paths: Vec::new(),
            target_args: Vec::new(),
            children: Vec::new(),
            child_pids: Vec::new(),
            started_at: None,
            notes: Vec::new(),
            options,
            etw_session_name,
            cpu: CpuMeter::new(),
            domains: crate::domains::DomainIntel::start(
                aaaa_workers.max(1),
                aaaa_bypass_cache,
            ),
            aaaa_enabled: aaaa_enabled && aaaa_workers > 0,
            hosts_file: None,
            hosts_backup_dir: None,
            no_aaaa_policy: crate::hosts::NoAaaaPolicy::default(),
            hosts_auto: HostsAuto::default(),
            attach_names: Vec::new(),
            watch_names: Vec::new(),
            launched_images: Vec::new(),
            handoff_reported: HashSet::new(),
            silence_child: true,
            data_dir: None,
            last_cache_save: None,
        }
    }

    /// Choose how the AAAA lookups run. `workers` of 0 disables them.
    ///
    /// A builder step rather than constructor arguments, because almost every
    /// caller wants the defaults and the interesting case is turning them off.
    pub fn with_aaaa(mut self, workers: usize, bypass_cache: bool) -> Self {
        self.domains = crate::domains::DomainIntel::start(workers.max(1), bypass_cache);
        self.aaaa_enabled = workers > 0;
        self
    }

    pub fn note(&mut self, level: NoteLevel, text: impl Into<String>) {
        self.notes.push(Note {
            at: Instant::now(),
            level,
            text: text.into(),
        });
        // Keep the log bounded.
        if self.notes.len() > 200 {
            self.notes.drain(0..100);
        }
    }

    /// Is the ETW source up? A false here means the primary data source is
    /// dead, which is the difference between "nothing happened" and "we could
    /// not see what happened".
    pub fn has_etw(&self) -> bool {
        self.etw.is_some()
    }

    pub fn has_pcap(&self) -> bool {
        self.pcap.is_some()
    }

    pub fn is_capturing(&self) -> bool {
        self.pipeline.is_some()
    }

    pub fn elapsed_secs(&self) -> u64 {
        self.started_at.map(|t| t.elapsed().as_secs()).unwrap_or(0)
    }

    /// Bring up the pipeline and every requested capture source.
    ///
    /// Failure of one source is not fatal: the session continues with whatever
    /// came up and the shortfall is recorded as a note, because a partially
    /// working monitor is far more useful than none.
    pub fn start_capture(&mut self) -> anyhow::Result<()> {
        if self.is_capturing() {
            return Ok(());
        }
        let (tx, rx) = bounded(QUEUE_CAPACITY);
        self.tx = Some(tx.clone());

        self.pipeline = Some(Pipeline::spawn(
            rx,
            self.store.clone(),
            self.tree.clone(),
            self.include_unattributed.clone(),
            self.domains.clone(),
            self.aaaa_enabled,
        ));

        // --- process-tree watcher -------------------------------------------
        {
            let tree = self.tree.clone();
            let foreign = self.foreign.clone();
            let stop = self.watcher_stop.clone();
            stop.store(false, Ordering::SeqCst);
            self.watcher = Some(std::thread::spawn(move || {
                // The tracker publishes the foreign set itself, under the same
                // lock that guards membership -- see `publish_foreign`.
                tree.lock().unwrap().set_foreign_sink(foreign);
                while !stop.load(Ordering::SeqCst) {
                    {
                        let mut t = tree.lock().unwrap();
                        // Sweep when there is a root, and also while watching by
                        // name: that is precisely the case where no process has
                        // been adopted yet and one may appear at any moment.
                        if t.root().is_some() || !t.watch_names().is_empty() {
                            t.refresh();
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(SWEEP_INTERVAL_MS));
                }
            }));
        }

        // --- ETW (primary) ---------------------------------------------------
        if self.aaaa_enabled {
            self.note(
                NoteLevel::Info,
                format!(
                    "AAAA lookups: {} worker(s), {}",
                    self.domains.worker_count(),
                    if self.domains.bypass_cache() {
                        "bypassing the resolver cache"
                    } else {
                        "using the resolver cache"
                    }
                ),
            );
        } else {
            self.note(NoteLevel::Info, "AAAA lookups disabled");
        }

        if self.options.use_etw {
            match EtwDnsSource::start(&self.etw_session_name, tx.clone(), self.foreign.clone()) {
                Ok((src, cleared)) => {
                    self.etw = Some(src);
                    if !cleared.is_empty() {
                        // Worth saying out loud: the user's previous run was
                        // killed, and that is why the tool looked broken.
                        self.note(
                            NoteLevel::Warn,
                            format!(
                                "cleared {} trace session(s) left behind by a terminated run: {}",
                                cleared.len(),
                                cleared.join(", ")
                            ),
                        );
                    }
                    self.note(
                        NoteLevel::Info,
                        "ETW Microsoft-Windows-DNS-Client subscribed (event 3006/3008)",
                    );
                }
                Err(e) => self.note(NoteLevel::Error, format!("ETW source unavailable: {e}")),
            }
        } else {
            self.note(NoteLevel::Info, "ETW source disabled by configuration");
        }

        // --- Npcap (fallback / supplement) -----------------------------------
        if self.options.use_npcap {
            match PcapSource::start_with_filter(
                tx.clone(),
                self.options.include_loopback,
                self.options.bpf_override.as_deref(),
            ) {
                Ok(src) => {
                    self.note(
                        NoteLevel::Info,
                        format!(
                            "Npcap capturing on {} interface(s): {}",
                            src.devices.len(),
                            src.devices.join(", ")
                        ),
                    );
                    self.note(NoteLevel::Info, format!("BPF filter: {}", src.filter));
                    self.pcap = Some(src);
                }
                Err(e) => self.note(NoteLevel::Warn, format!("Npcap source unavailable: {e}")),
            }
        } else {
            self.note(NoteLevel::Info, "Npcap source disabled by configuration");
        }

        if self.etw.is_none() && self.pcap.is_none() {
            self.stop_capture();
            anyhow::bail!("no capture source could be started -- nothing to monitor");
        }

        self.started_at = Some(Instant::now());

        // Watch-by-name mode. Applied after the sources are up so that nothing
        // that starts during startup is missed.
        if !self.watch_names.is_empty() {
            let names = self.watch_names.clone();
            self.set_watch_names(names.clone());
            let live = self.tree.lock().unwrap().live_member_count();
            self.note(
                NoteLevel::Info,
                format!(
                    "watching for process name(s): {} -- currently {} matching process(es); \
                     new ones are adopted as they start",
                    names.join(", "),
                    live
                ),
            );
        }

        // Attach mode: adopt every process with each given image name.
        //
        // All of them, not just the first: a browser is a set of peer
        // processes rather than one parent with children, and adopting a
        // single one would show a fraction of its traffic. Several names can
        // be given at once, and every match becomes a root of the same tree.
        if !self.attach_names.is_empty() {
            let mut adopted: Vec<u32> = Vec::new();
            for name in self.attach_names.clone() {
                let found = TreeTracker::find_by_image_name(&name);
                if found.is_empty() {
                    self.note(
                        NoteLevel::Warn,
                        format!("no running process named {name}; monitoring will stay idle"),
                    );
                    continue;
                }
                self.note(
                    NoteLevel::Info,
                    format!(
                        "attached to {} already-running {name} process(es): {}",
                        found.len(),
                        found
                            .iter()
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                );
                adopted.extend(found);
            }
            adopted.sort_unstable();
            adopted.dedup();
            if !adopted.is_empty() {
                self.set_target_pids(&adopted);
            }
        }
        Ok(())
    }

    /// Adopt a set of processes as the roots of the monitored tree.
    ///
    /// Replaces whatever roots were there; used for attach mode, where the set
    /// is known in one go.
    pub fn set_target_pids(&mut self, pids: &[u32]) {
        let mut t = self.tree.lock().unwrap();
        t.set_roots(pids);
        // refresh() republishes the foreign set from the new membership, so no
        // separate clear is needed -- and a separate clear would race.
        t.refresh();
        self.child_pids = pids.to_vec();
    }

    /// Add roots to the monitored tree, keeping the existing ones.
    ///
    /// This is what launching several targets uses: each launched process
    /// joins the tree as another root, so one run can cover, say, a browser and
    /// an updater at the same time.
    pub fn add_target_pids(&mut self, pids: &[u32]) {
        if pids.is_empty() {
            return;
        }
        let mut t = self.tree.lock().unwrap();
        t.add_roots(pids);
        t.refresh();
        for pid in pids {
            if !self.child_pids.contains(pid) {
                self.child_pids.push(*pid);
            }
        }
    }

    /// Watch for processes by image name, for the whole session.
    ///
    /// Unlike `--attach`, which adopts whatever is running at that instant,
    /// this keeps matching on every sweep: a helper process that starts ten
    /// minutes into a download is picked up the moment it appears.
    pub fn set_watch_names(&mut self, names: Vec<String>) {
        self.watch_names = names
            .into_iter()
            .map(|n| n.trim().to_ascii_lowercase())
            .filter(|n| !n.is_empty())
            .collect();
        let mut t = self.tree.lock().unwrap();
        t.set_watch_names(self.watch_names.clone());
        // An immediate sweep so something already running is adopted without
        // waiting for the first tick. It also republishes the foreign set.
        t.refresh();
    }

    /// Launch the target application. Capture must already be running.
    ///
    /// # Multiple targets
    ///
    /// Each call appends another launched process as a root of the same tree;
    /// the arguments are shared by every target (see `--arg`). A failure is
    /// reported to the caller, which decides whether it is fatal: one bad path
    /// among several should not cancel the others.
    ///
    /// # Console ownership
    ///
    /// A child started from a console parent inherits that console. In
    /// `--stream-json` mode one line of the target's output would corrupt the
    /// protocol, so `silence_child` points the child's standard handles at the
    /// null device; plain text output leaves them inherited so the target's
    /// own output stays visible.
    pub fn launch_target(&mut self, path: &Path, args: &[String]) -> anyhow::Result<u32> {
        if !self.is_capturing() {
            anyhow::bail!("internal ordering error: capture must start before the target");
        }
        if !path.is_file() {
            anyhow::bail!("{} is not a file", path.display());
        }
        let mut cmd = Command::new(path);
        cmd.args(args);
        if let Some(dir) = path.parent() {
            cmd.current_dir(dir);
        }
        if self.silence_child {
            cmd.stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
        }
        let child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("could not start {}: {e}", path.display()))?;
        let pid = child.id();
        self.children.push(child);
        if let Some(name) = path.file_name() {
            self.launched_images
                .push(name.to_string_lossy().to_ascii_lowercase());
            // A new launch of an image whose hand-off was already reported can
            // legitimately be reported again: this is a different process.
            self.handoff_reported.remove(&name.to_string_lossy().to_ascii_lowercase());
        }
        self.target_paths.push(path.to_path_buf());
        self.target_args = args.to_vec();
        self.add_target_pids(&[pid]);
        self.note(
            NoteLevel::Info,
            format!("launched {} as pid {pid}", path.display()),
        );
        Ok(pid)
    }

    /// Has a launched target exited while its namesakes keep running?
    ///
    /// This is the signature of a single-instance application. `msedge.exe`
    /// started while Edge is already open hands its command line to the
    /// existing browser and exits within a second; the real browser processes
    /// are not its children, so the tree stays empty and nothing is captured
    /// no matter how long the monitor runs.
    ///
    /// Returns the image name and the live PIDs that are *not* in the tree.
    /// With several targets, each image is reported once.
    pub fn detect_handoff(&mut self) -> Option<(String, Vec<u32>)> {
        if !self.attach_names.is_empty() || !self.watch_names.is_empty() {
            return None;
        }
        let images = self.launched_images.clone();
        for (index, image) in images.iter().enumerate() {
            if self.handoff_reported.contains(image) {
                continue;
            }
            // Only once the process we started has actually gone. Indexes stay
            // aligned because a launch only ever appends. (`try_wait` needs a
            // mutable borrow, so it cannot live in a match guard.)
            let still_running = match self.children.get_mut(index) {
                Some(c) => matches!(c.try_wait(), Ok(None)),
                None => continue,
            };
            if still_running {
                continue;
            }
            let live: Vec<u32> = TreeTracker::find_by_image_name(image)
                .into_iter()
                .filter(|pid| !self.tree.lock().unwrap().contains(*pid))
                .collect();
            if live.is_empty() {
                continue;
            }
            self.handoff_reported.insert(image.clone());
            return Some((image.clone(), live));
        }
        None
    }

    /// Is anything left to watch? False when every launched process is gone and
    /// no live member of the tree remains.
    ///
    /// Used to decide when a one-shot run is finished. It deliberately looks at
    /// the whole tree, not just the processes we launched: a launcher that exits
    /// while its children keep working is a normal shape.
    pub fn target_finished(&mut self) -> bool {
        if self.child_running() {
            return false;
        }
        // In watch mode nothing was ever launched, so "the child has exited"
        // says nothing; the session runs until the user stops it.
        if !self.watch_names.is_empty() {
            return false;
        }
        self.tree.lock().unwrap().live_member_count() == 0
    }

    /// Refresh CPU usage of this process.
    pub fn tick_cpu(&mut self) {
        self.cpu.sample();
    }

    /// Is at least one launched child still alive?
    pub fn child_running(&mut self) -> bool {
        self.children
            .iter_mut()
            .any(|c| matches!(c.try_wait(), Ok(None)))
    }

    pub fn stop_capture(&mut self) {
        self.watcher_stop.store(true, Ordering::SeqCst);
        if let Some(w) = self.watcher.take() {
            let _ = w.join();
        }
        if let Some(mut p) = self.pcap.take() {
            p.stop();
        }
        if let Some(mut e) = self.etw.take() {
            e.stop();
        }
        // Drop the sender *before* stopping the pipeline so `recv` sees the
        // disconnect promptly; the pipeline also stops on its own flag.
        self.tx = None;
        if let Some(mut p) = self.pipeline.take() {
            p.stop();
        }
        self.started_at = None;
        {
            let mut t = self.tree.lock().unwrap();
            t.clear();
        }
        if let Ok(mut f) = self.foreign.write() {
            f.clear();
        }
    }

    /// Terminate every launched child (used when the user picks "stop and
    /// close target").
    pub fn kill_child(&mut self) {
        for mut c in self.children.drain(..) {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.child_pids.clear();
    }

    /// Aggregate drop counters from every layer.
    pub fn kernel_dropped(&mut self) -> u64 {
        let etw = self.etw.as_mut().map(|e| e.events_lost() as u64).unwrap_or(0);
        let pcap = self
            .pcap
            .as_ref()
            .map(|p| p.stats.kernel_dropped.load(Ordering::Relaxed))
            .unwrap_or(0);
        etw + pcap
    }

    /// Snapshot of the packet-capture counters, for diagnostics.
    pub fn pcap_counters(&self) -> Option<(u64, u64, u64, u64, u64)> {
        self.pcap.as_ref().map(|p| {
            (
                p.stats.packets.load(Ordering::Relaxed),
                p.stats.dns_queries.load(Ordering::Relaxed),
                p.stats.dns_responses.load(Ordering::Relaxed),
                p.stats.sni_names.load(Ordering::Relaxed),
                p.stats.suppressed_service.load(Ordering::Relaxed),
            )
        })
    }

    /// Per-source counters rendered by the statistics panel. Presenting these
    /// is what turns "no rows appeared" into an answerable question: a zero
    /// `queries` with a non-zero `malformed`, or a zero `packets`, says exactly
    /// which stage is not working.
    pub fn source_diagnostics(&self) -> Vec<(String, String)> {
        let mut v = Vec::new();
        match &self.etw {
            Some(e) => {
                let s = &e.stats;
                v.push(("ETW session".into(), "active".into()));
                v.push((
                    "ETW queries parsed".into(),
                    s.queries.load(Ordering::Relaxed).to_string(),
                ));
                v.push((
                    "ETW responses seen".into(),
                    s.responses.load(Ordering::Relaxed).to_string(),
                ));
                v.push((
                    "ETW rejected (foreign pid)".into(),
                    s.filtered_foreign.load(Ordering::Relaxed).to_string(),
                ));
                v.push((
                    "ETW rejected (malformed)".into(),
                    s.malformed.load(Ordering::Relaxed).to_string(),
                ));
            }
            None => v.push(("ETW session".into(), "not running".into())),
        }
        match &self.pcap {
            Some(p) => {
                let s = &p.stats;
                v.push((
                    "PCAP interfaces".into(),
                    p.devices.len().to_string(),
                ));
                v.push(("PCAP filter".into(), p.filter.clone()));
                v.push((
                    "PCAP packets matched".into(),
                    s.packets.load(Ordering::Relaxed).to_string(),
                ));
                v.push((
                    "PCAP DNS queries".into(),
                    s.dns_queries.load(Ordering::Relaxed).to_string(),
                ));
                v.push((
                    "PCAP DNS answers".into(),
                    s.dns_responses.load(Ordering::Relaxed).to_string(),
                ));
                v.push((
                    "PCAP SNI names".into(),
                    s.sni_names.load(Ordering::Relaxed).to_string(),
                ));
                v.push((
                    "PCAP svchost rows suppressed".into(),
                    s.suppressed_service.load(Ordering::Relaxed).to_string(),
                ));
            }
            None => v.push(("PCAP capture".into(), "not running".into())),
        }
        v
    }

    pub fn queue_dropped(&self) -> u64 {
        self.pipeline
            .as_ref()
            .map(|p| p.stats.queue_dropped.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop_capture();
        // A crash loses at most the last periodic save; a clean exit loses
        // nothing. Setting no `data_dir` (tests) disables this entirely.
        self.save_domain_cache_now();
    }
}

// ---------------------------------------------------------------------------
// hosts file operations
// ---------------------------------------------------------------------------

/// State of the automatic hosts writer.
#[derive(Clone, Debug)]
pub struct HostsAuto {
    pub enabled: bool,
    /// Which process's domain table is kept in step.
    pub process: String,
    pub policy: crate::hosts::NoAaaaPolicy,
    /// The plan we are waiting to settle, and when it last changed.
    pending: Option<(u64, std::time::Instant)>,
    /// Successful automatic writes this session.
    pub writes: u64,
    pub last_note: String,
}

impl Default for HostsAuto {
    fn default() -> Self {
        Self {
            enabled: false,
            process: String::new(),
            policy: crate::hosts::NoAaaaPolicy::default(),
            pending: None,
            writes: 0,
            last_note: String::new(),
        }
    }
}

/// What a hosts operation did, for reporting back.
#[derive(Clone, Debug, Default)]
pub struct HostsOutcome {
    pub path: std::path::PathBuf,
    pub backup: Option<std::path::PathBuf>,
    /// Lines added to the block.
    pub appended: usize,
    /// Lines whose block address became a real IPv6 address.
    pub upgraded: usize,
    /// Lines that gained this process's name.
    pub claimed: usize,
    /// Rows already exactly right, left untouched.
    pub kept: usize,
    /// Rows not written at all (policy, or the user's own line).
    pub skipped: usize,
    /// Lines removed by a per-process removal.
    pub removed: usize,
    /// Lines kept by a per-process removal because another process shares them.
    pub shared: usize,
    /// The file did not need changing, so nothing was written and no backup was
    /// taken.
    pub unchanged: bool,
    pub note: String,
}

/// One line of the managed block, as it currently stands in the file.
///
/// The viewer groups these by owner, so a line two processes asked for shows
/// up under both of them -- that is what "this process's entries" means, and
/// the counts are allowed to add up to more than the number of lines.
#[derive(Clone, Debug)]
pub struct HostsLine {
    pub address: String,
    pub domain: String,
    /// The processes whose domain tables asked for this line. Empty for a line
    /// written by an older version, before entries recorded an owner.
    pub owners: Vec<String>,
    /// The line exactly as it sits in the file, for "copy this line".
    pub line: String,
}

/// A read of the hosts file, for the viewer.
#[derive(Clone, Debug, Default)]
pub struct HostsView {
    pub path: std::path::PathBuf,
    pub text: String,
    pub managed_entries: usize,
    pub total_entries: usize,
    /// How many entries each process has in the block, most first. An empty
    /// name is a line with no process recorded (written by an older version).
    pub by_owner: Vec<(String, usize)>,
    /// The managed block itself, with owners, for the "current entries" view.
    pub entries: Vec<HostsLine>,
    pub backup_dir: std::path::PathBuf,
    pub backups: Vec<std::path::PathBuf>,
}

/// One line describing what a merge did, for the status line.
fn write_note(m: &crate::hosts::Merge) -> String {
    let mut parts: Vec<String> = Vec::new();
    if m.appended > 0 {
        parts.push(format!("新增 {} 条", m.appended));
    }
    if m.upgraded > 0 {
        parts.push(format!("{} 条由 127.0.0.1 更新为 IPv6", m.upgraded));
    }
    if m.claimed > 0 {
        parts.push(format!("{} 条登记到本进程", m.claimed));
    }
    if m.kept > 0 {
        parts.push(format!("{} 条保持原样", m.kept));
    }
    if m.skipped > 0 {
        parts.push(format!("{} 条按策略跳过", m.skipped));
    }
    if parts.is_empty() {
        "没有需要写入的改动".to_string()
    } else {
        parts.join("，")
    }
}

impl Session {
    /// Where backups go: beside the executable unless told otherwise.
    ///
    /// Not under the system drive: the hosts file has to live there, but
    /// nothing else about this tool does.
    pub fn hosts_backup_dir(&self) -> std::path::PathBuf {
        if let Some(d) = &self.hosts_backup_dir {
            return d.clone();
        }
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("hosts-backups")))
            .unwrap_or_else(|| std::path::PathBuf::from("hosts-backups"))
    }

    pub fn hosts_path(&self) -> std::path::PathBuf {
        self.hosts_file
            .clone()
            .unwrap_or_else(crate::hosts::HostsFile::default_path)
    }

    fn load_hosts(&self) -> anyhow::Result<crate::hosts::HostsFile> {
        Ok(crate::hosts::HostsFile::load(&self.hosts_path())?)
    }

    /// What would be written for one process, without touching anything.
    ///
    /// Includes the previous session's rows when there are any, marked as such:
    /// that is what makes it possible to see and undo entries written by a
    /// process that is no longer running.
    pub fn hosts_preview(
        &self,
        process: &str,
        policy: crate::hosts::NoAaaaPolicy,
    ) -> anyhow::Result<Vec<crate::hosts::PlannedEntry>> {
        Ok(Self::plan_rows(&self.domains.rows_for(process), policy))
    }

    fn plan_rows(
        rows: &[(String, crate::domains::AaaaEntry)],
        policy: crate::hosts::NoAaaaPolicy,
    ) -> Vec<crate::hosts::PlannedEntry> {
        let pairs: Vec<(&str, &[std::net::Ipv6Addr])> = rows
            .iter()
            .map(|(d, e)| (d.as_str(), e.addresses()))
            .collect();
        let mut entries = crate::hosts::plan(pairs, policy);
        // An address that came from the cache is labelled, because writing it
        // re-asserts an answer that may be days old.
        for e in &mut entries {
            e.previous_session = rows
                .iter()
                .any(|(d, x)| x.archived && d.eq_ignore_ascii_case(&e.domain));
        }
        entries
    }

    /// Fold one process's domain table into the managed block.
    ///
    /// Additive by construction: [`crate::hosts::merge`] only ever adds a line,
    /// corrects a blocked line that now has an IPv6 answer, or records this
    /// process on a line another process already wrote. Nothing is removed and
    /// nothing already written has its address changed, so a write can never
    /// take away what an earlier one put there. Clearing is a separate action
    /// (`hosts_remove`) with its own confirmation.
    pub fn hosts_write(
        &mut self,
        process: &str,
        policy: crate::hosts::NoAaaaPolicy,
    ) -> anyhow::Result<HostsOutcome> {
        self.hosts_write_impl(process, policy, false, None)
    }

    /// Write only the named domains of one process's table.
    ///
    /// The selection narrows *which* rows are planned; every rule that decides
    /// what a row becomes is unchanged, so a selected name with no usable IPv6
    /// is still blocked or skipped according to the policy, and a name another
    /// process wrote is still only claimed. Nothing outside the selection is
    /// touched, and automatic mode keeps writing the whole table.
    pub fn hosts_write_selected(
        &mut self,
        process: &str,
        policy: crate::hosts::NoAaaaPolicy,
        domains: &[String],
    ) -> anyhow::Result<HostsOutcome> {
        self.hosts_write_impl(process, policy, false, Some(domains))
    }

    /// `auto` only changes what the change log says the write was: the merge
    /// itself is the same one the user gets, so automatic and manual writes can
    /// never drift apart.
    fn hosts_write_impl(
        &mut self,
        process: &str,
        policy: crate::hosts::NoAaaaPolicy,
        auto: bool,
        only: Option<&[String]>,
    ) -> anyhow::Result<HostsOutcome> {
        let mut rows = self.hosts_preview(process, policy)?;
        if let Some(selected) = only {
            rows.retain(|e| {
                selected
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case(&e.domain))
            });
        }
        let file = self.load_hosts()?;
        let m = crate::hosts::merge(&file, process, &rows);
        if !m.changed {
            let note = if rows.is_empty() {
                if only.is_some() {
                    "所选域名没有可写入的条目，hosts 未做改动".to_string()
                } else {
                    format!("{process} 目前没有可写入的域名，hosts 未做改动")
                }
            } else {
                format!(
                    "{process}：没有需要写入的改动（{} 条已写入的域名保持原样，{} 条按策略跳过）",
                    m.kept, m.skipped
                )
            };
            return Ok(HostsOutcome {
                path: self.hosts_path(),
                kept: m.kept,
                skipped: m.skipped,
                unchanged: true,
                note,
                ..Default::default()
            });
        }
        let backup = file.write(&m.bytes, &self.hosts_backup_dir()).ok();

        let out = HostsOutcome {
            path: self.hosts_path(),
            backup,
            appended: m.appended,
            upgraded: m.upgraded,
            claimed: m.claimed,
            kept: m.kept,
            skipped: m.skipped,
            note: format!("{process}：{}", write_note(&m)),
            ..Default::default()
        };
        self.log_hosts_change(if auto { "auto_write" } else { "write" }, process, &out);
        self.note(NoteLevel::Info, out.note.clone());
        Ok(out)
    }

    /// Remove entries from the managed block.
    ///
    /// `None` removes the whole block. `Some(process)` removes only the lines
    /// that process alone asked for; a line it shares with another process
    /// stays, with the other process's name still on it. Both are things the
    /// user asks for by name -- nothing removes entries on its own.
    pub fn hosts_remove(&mut self, process: Option<&str>) -> anyhow::Result<HostsOutcome> {
        let file = self.load_hosts()?;
        match process {
            None => {
                if !file.has_managed_block() {
                    return Ok(HostsOutcome {
                        path: self.hosts_path(),
                        unchanged: true,
                        note: "hosts 文件中没有本程序写入的条目".into(),
                        ..Default::default()
                    });
                }
                let removed = file.managed_entries().len();
                let bytes = file.render_without();
                let backup = file.write(&bytes, &self.hosts_backup_dir()).ok();
                let out = HostsOutcome {
                    path: self.hosts_path(),
                    backup,
                    removed,
                    note: format!("已移除全部 {removed} 条本程序写入的条目"),
                    ..Default::default()
                };
                self.log_hosts_change("remove_all", "", &out);
                self.note(NoteLevel::Info, out.note.clone());
                Ok(out)
            }
            Some(process) => {
                let r = crate::hosts::unclaim(&file, process);
                if !r.changed {
                    return Ok(HostsOutcome {
                        path: self.hosts_path(),
                        note: format!("hosts 里没有 {process} 写入的条目，未做改动"),
                        unchanged: true,
                        ..Default::default()
                    });
                }
                let backup = file.write(&r.bytes, &self.hosts_backup_dir()).ok();
                let note = if r.shared > 0 {
                    format!(
                        "已移除 {process} 的 {} 条条目；另有 {} 条与其它进程共用，只去掉了它的名字",
                        r.removed, r.shared
                    )
                } else {
                    format!("已移除 {process} 的 {} 条条目", r.removed)
                };
                let out = HostsOutcome {
                    path: self.hosts_path(),
                    backup,
                    removed: r.removed,
                    shared: r.shared,
                    note,
                    ..Default::default()
                };
                self.log_hosts_change("remove_process", process, &out);
                self.note(NoteLevel::Info, out.note.clone());
                Ok(out)
            }
        }
    }

    /// Delete one line from the managed block.
    ///
    /// `process` is only a label for the change log and the status line; the
    /// line is identified by its address and domain, which is what the viewer
    /// shows. This removes the line even if other processes also asked for that
    /// name -- deleting a single row is an explicit instruction about that row.
    pub fn hosts_remove_entry(
        &mut self,
        domain: &str,
        address: &str,
        process: &str,
    ) -> anyhow::Result<HostsOutcome> {
        let file = self.load_hosts()?;
        let r = crate::hosts::remove_entry(&file, domain, address);
        if !r.changed {
            return Ok(HostsOutcome {
                path: self.hosts_path(),
                note: format!("hosts 里没有 {domain} 这一行（可能已被删掉），未做改动"),
                unchanged: true,
                ..Default::default()
            });
        }
        let backup = file.write(&r.bytes, &self.hosts_backup_dir()).ok();
        let out = HostsOutcome {
            path: self.hosts_path(),
            backup,
            removed: r.removed,
            note: format!("已删除 {domain}（{address}）这一行"),
            ..Default::default()
        };
        let label = if process.is_empty() { "-" } else { process };
        self.log_hosts_change("remove_entry", label, &out);
        self.note(NoteLevel::Info, out.note.clone());
        Ok(out)
    }

    /// The preview, with each row marked as already written or not.
    pub fn hosts_preview_annotated(
        &self,
        process: &str,
        policy: crate::hosts::NoAaaaPolicy,
    ) -> Vec<(crate::hosts::PlannedEntry, crate::hosts::RowPlan)> {
        let plan = self.hosts_preview(process, policy).unwrap_or_default();
        match self.load_hosts() {
            Ok(f) => {
                let rows =
                    crate::hosts::classify(&plan, &f.block_entries(), &f.all_entries(), process);
                plan.into_iter().zip(rows).collect()
            }
            // No file, or unreadable: everything would be a new line.
            Err(_) => plan
                .into_iter()
                .map(|e| {
                    let action = crate::hosts::RowAction::Append;
                    (e, crate::hosts::RowPlan { state: crate::hosts::WrittenState::Absent, action })
                })
                .collect(),
        }
    }

    /// Turn automatic mode on or off.
    pub fn set_hosts_auto(&mut self, on: bool, process: Option<String>) {
        self.hosts_auto.enabled = on;
        if let Some(p) = process {
            self.hosts_auto.process = p;
        }
        // A fresh decision: forget any plan that was mid-debounce.
        self.hosts_auto.pending = None;
        let m = if on {
            format!(
                "自动写入已开启：{} 的域名表变化后将自动写入 hosts（无 IPv6 的域名：{}）",
                if self.hosts_auto.process.is_empty() {
                    "(未选择进程)"
                } else {
                    &self.hosts_auto.process
                },
                self.hosts_auto.policy.label()
            )
        } else {
            "自动写入已关闭".to_string()
        };
        self.note(NoteLevel::Info, m.clone());
        self.hosts_auto.last_note = m;
    }

    /// One tick of automatic mode. Returns the outcome when it wrote.
    ///
    /// Called from the UI tick and from the streaming loop; cheap when disabled
    /// or when nothing has changed.
    pub fn hosts_auto_tick(&mut self) -> Option<HostsOutcome> {
        if !self.hosts_auto.enabled || self.hosts_auto.process.is_empty() {
            return None;
        }
        let process = self.hosts_auto.process.clone();
        let policy = self.hosts_auto.policy;

        // Wait for the lookups. A name whose AAAA answer has not arrived would
        // otherwise be written as 127.0.0.1 and corrected a moment later.
        //
        // Only rows observed in *this* session count. A restored table is a
        // record of what happened last time, not evidence about now; writing it
        // back would re-assert addresses that may be days old without anything
        // having resolved them.
        let live: Vec<(String, crate::domains::AaaaEntry)> = self
            .domains
            .rows_for(&process)
            .into_iter()
            .filter(|(_, e)| !e.archived)
            .collect();
        if live.is_empty() || live.iter().any(|(_, e)| !e.settled()) {
            return None;
        }

        let plan = Self::plan_rows(&live, policy);
        if plan.is_empty() {
            // Never remove automatically. Clearing the block stays a deliberate
            // action, so a missing domain table cannot silently wipe it.
            return None;
        }

        // Ask the merge itself whether there is anything to do, rather than
        // comparing the whole block with this process's plan: the block holds
        // other processes' entries too, and comparing the two would report a
        // difference on every tick and rewrite the file forever.
        let file = self.load_hosts().ok()?;
        if !crate::hosts::merge(&file, &process, &plan).changed {
            self.hosts_auto.pending = None;
            return None;
        }

        // Debounce: only write once the plan has held still.
        let fingerprint = fingerprint(&plan);
        match &self.hosts_auto.pending {
            Some((fp, since)) if *fp == fingerprint => {
                if since.elapsed() < crate::hosts::AUTO_DEBOUNCE {
                    return None;
                }
            }
            _ => {
                self.hosts_auto.pending = Some((fingerprint, std::time::Instant::now()));
                return None;
            }
        }

        let outcome = self.hosts_write_impl(&process, policy, true, None).ok()?;
        self.hosts_auto.pending = None;
        self.hosts_auto.writes += 1;
        self.hosts_auto.last_note = format!("自动写入：{}", outcome.note);
        // Backups are not pruned here any more. Deleting files is the user's
        // decision; automatic mode only adds them, and the count is shown so
        // the accumulation is visible rather than surprising.
        self.note(NoteLevel::Info, self.hosts_auto.last_note.clone());
        Some(outcome)
    }

    /// Read the file for display.
    pub fn hosts_view(&self) -> HostsView {
        let path = self.hosts_path();
        let backups = crate::hosts::list_backups(&self.hosts_backup_dir());
        match crate::hosts::HostsFile::load(&path) {
            Ok(f) => HostsView {
                path,
                managed_entries: f.managed_entries().len(),
                total_entries: f.all_entries().len(),
                by_owner: f.owners_summary(),
                entries: f
                    .block_entries()
                    .into_iter()
                    .map(|e| HostsLine {
                        address: e.address.clone(),
                        domain: e.domain.clone(),
                        owners: e.owners.clone(),
                        line: e.line(),
                    })
                    .collect(),
                text: f.contents(),
                backup_dir: self.hosts_backup_dir(),
                backups,
            },
            Err(e) => HostsView {
                path,
                text: format!("(无法读取: {e})"),
                backup_dir: self.hosts_backup_dir(),
                backups,
                ..Default::default()
            },
        }
    }

    /// Replace the file with the user's edited text.
    ///
    /// The whole file is replaced because that is what editing means; the
    /// backup taken first is what makes it safe. Our markers are left alone --
    /// if the user removed them, the block simply becomes ordinary lines and
    /// `hosts_remove` will no longer find it, which is their call to make.
    pub fn hosts_replace_text(&mut self, text: &str) -> anyhow::Result<HostsOutcome> {
        let file = self.load_hosts()?;
        let backup = file.write(text.as_bytes(), &self.hosts_backup_dir()).ok();
        let out = HostsOutcome {
            path: self.hosts_path(),
            backup,
            note: "已保存 hosts 文件".to_string(),
            ..Default::default()
        };
        self.log_hosts_change("edit", "", &out);
        self.note(NoteLevel::Info, out.note.clone());
        Ok(out)
    }

    /// Delete old backups, keeping the newest `keep`.
    ///
    /// Only ever called because the user asked. Nothing prunes automatically:
    /// the backup most likely to matter is the oldest, which a count-based rule
    /// would discard first.
    pub fn hosts_prune_backups(&mut self, keep: usize) -> usize {
        let removed = crate::hosts::prune_backups(&self.hosts_backup_dir(), keep);
        self.note(
            NoteLevel::Info,
            format!("已清理 {removed} 个旧备份，保留最新 {keep} 个"),
        );
        removed
    }

    pub fn hosts_backup_now(&mut self) -> anyhow::Result<std::path::PathBuf> {
        let path = self.hosts_path();
        if !path.exists() {
            anyhow::bail!("hosts 文件不存在：{}", path.display());
        }
        let b = crate::hosts::backup(&path, &self.hosts_backup_dir())?;
        self.note(NoteLevel::Info, format!("已备份 hosts 到 {}", b.display()));
        Ok(b)
    }

    pub fn hosts_restore_backup(
        &mut self,
        from: &std::path::Path,
    ) -> anyhow::Result<HostsOutcome> {
        let safety = crate::hosts::restore(from, &self.hosts_path(), &self.hosts_backup_dir())?;
        let out = HostsOutcome {
            path: self.hosts_path(),
            backup: if safety.as_os_str().is_empty() {
                None
            } else {
                Some(safety)
            },
            note: format!("已从 {} 恢复", from.display()),
            ..Default::default()
        };
        self.log_hosts_change("restore", "", &out);
        self.note(NoteLevel::Info, out.note.clone());
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // local cache
    // -----------------------------------------------------------------------

    /// Load the previous session's domain tables.
    ///
    /// Restored rows are marked archived: they appear in the tables and can be
    /// used to manage the hosts entries of a process that is not running any
    /// more, but automatic writing never touches them.
    pub fn load_domain_cache(&mut self) -> usize {
        let Some(dir) = self.data_dir.clone() else {
            return 0;
        };
        let Some(snap) = crate::persist::load_snapshot(&dir) else {
            return 0;
        };
        let n = self.domains.restore(&snap);
        if n > 0 {
            let when = crate::persist::format_time(snap.saved_at_ms);
            self.note(
                NoteLevel::Info,
                format!("已载入上次会话的域名表：{n} 条（保存于 {when}），标为「上次会话」"),
            );
        }
        n
    }

    /// Write the domain tables where the next run will find them.
    ///
    /// Rows are kept for [`crate::persist::CACHE_MAX_AGE_DAYS`] days, and every
    /// domain that still has a line in the hosts file is kept regardless of
    /// age -- the cache exists to manage those entries, so ageing them out
    /// would defeat its purpose.
    pub fn save_domain_cache_now(&mut self) -> Option<std::path::PathBuf> {
        let dir = self.data_dir.clone()?;
        let mut snap = self.domains.snapshot();
        if snap.processes.is_empty() {
            // Nothing to remember; leave an older snapshot alone.
            return None;
        }
        let pinned = self.hosts_domains();
        let cutoff = crate::util::now_unix_ms()
            - crate::persist::CACHE_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;
        for p in &mut snap.processes {
            // A row that was still waiting for its lookup when the snapshot was
            // taken has no query time of its own; the process's last sighting
            // is the honest age for it.
            let seen = p.last_seen_ms;
            p.domains.retain(|d| {
                let at = if d.queried_at_ms == 0 {
                    seen
                } else {
                    d.queried_at_ms
                };
                at >= cutoff || pinned.contains(&d.domain.to_ascii_lowercase())
            });
        }
        snap.processes.retain(|p| !p.domains.is_empty());
        if snap.processes.is_empty() {
            return None;
        }
        match crate::persist::save_snapshot(&dir, &snap) {
            Ok(path) => {
                self.last_cache_save = Some(Instant::now());
                Some(path)
            }
            Err(e) => {
                self.note(NoteLevel::Warn, format!("域名表缓存写入失败：{e}"));
                None
            }
        }
    }

    /// Save at most every 30 seconds. A crash then costs at most half a minute
    /// of table history.
    pub fn save_domain_cache_if_due(&mut self) {
        if self.data_dir.is_none() {
            return;
        }
        let due = self
            .last_cache_save
            .map(|t| t.elapsed() >= std::time::Duration::from_secs(30))
            .unwrap_or(true);
        if due {
            self.save_domain_cache_now();
        }
    }

    /// Domains that currently have a line in the managed block.
    fn hosts_domains(&self) -> HashSet<String> {
        self.load_hosts()
            .map(|f| {
                f.managed_entries()
                    .into_iter()
                    .map(|(_, d)| d.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The hosts change log, oldest first.
    pub fn hosts_history(&self, limit: usize) -> Vec<crate::persist::HistoryEntry> {
        match &self.data_dir {
            Some(dir) => crate::persist::load_history(dir, limit),
            None => Vec::new(),
        }
    }

    /// Append one change to the log. Only called when the file really changed.
    fn log_hosts_change(&self, action: &str, process: &str, o: &HostsOutcome) {
        let Some(dir) = &self.data_dir else {
            return;
        };
        let record = crate::persist::HistoryEntry {
            at_ms: crate::util::now_unix_ms(),
            action: action.to_string(),
            process: process.to_string(),
            appended: o.appended,
            upgraded: o.upgraded,
            claimed: o.claimed,
            removed: o.removed,
            shared: o.shared,
            backup: o
                .backup
                .as_ref()
                .map(|b| b.display().to_string())
                .unwrap_or_default(),
            note: o.note.clone(),
        };
        // A failed append is not worth interrupting the user for: the hosts file
        // has already changed, and that is the part that matters.
        let _ = crate::persist::append_history(dir, &record);
    }
}

// ---------------------------------------------------------------------------
// Command channel
// ---------------------------------------------------------------------------

/// A command sent to a running engine over stdin.
///
/// Named `EngineCommand` rather than `Command` because `std::process::Command`
/// is already in scope here for launching the target.
#[derive(Clone, Debug)]
pub enum EngineCommand {
    /// Re-resolve domains. `failed_only` restricts it to lookups that errored.
    Requery { failed_only: bool },
    /// Write the domain tables to a file.
    ExportDomains { path: std::path::PathBuf },
    /// End the session cleanly.
    Stop,
    /// Work out what a hosts write would do, without doing it.
    HostsPreview {
        process: String,
        policy: crate::hosts::NoAaaaPolicy,
    },
    /// Write one process's domains into the managed block.
    ///
    /// `domains` narrows the write to those names (the preview window's
    /// multi-select); `None` means the whole table, which is what the plain
    /// "write" button and automatic mode use.
    HostsWrite {
        process: String,
        policy: crate::hosts::NoAaaaPolicy,
        domains: Option<Vec<String>>,
    },
    /// Remove entries from the managed block: one process's, or `None` for all
    /// of them.
    HostsRemove { process: Option<String> },
    /// Delete one displayed line (address + domain), whoever else owns it.
    HostsRemoveEntry {
        domain: String,
        address: String,
        /// Only used as a label in the change log and status line.
        process: String,
    },
    /// Read the file for the viewer.
    HostsRead,
    /// Read the hosts change log (the newest `limit` records).
    HostsHistory { limit: usize },
    /// Replace the file with edited text.
    HostsEdit { text: String },
    HostsBackup,
    HostsRestore { path: std::path::PathBuf },
    /// Delete old backups, keeping `keep` of them.
    HostsPruneBackups { keep: usize },
    /// Turn automatic writing on or off.
    HostsAuto {
        on: bool,
        process: Option<String>,
        policy: crate::hosts::NoAaaaPolicy,
    },
}

/// A cheap fingerprint of a plan, used to notice that it stopped changing.
fn fingerprint(plan: &[crate::hosts::PlannedEntry]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for e in plan {
        e.address.hash(&mut h);
        e.domain.hash(&mut h);
    }
    h.finish()
}

/// Parse the `policy` field shared by the hosts commands.
fn parse_policy(v: &serde_json::Value) -> crate::hosts::NoAaaaPolicy {
    match v.get("policy").and_then(|p| p.as_str()) {
        Some("skip") => crate::hosts::NoAaaaPolicy::Skip,
        _ => crate::hosts::NoAaaaPolicy::Block,
    }
}

/// Parse the optional `domains` field of a `hosts_write` command.
///
/// Three states, and the difference matters: absent means "the whole table"
/// (the plain write button and automatic mode), a list means "only these", and
/// an empty list means "the user selected nothing" -- a write that must do
/// nothing at all, not a write of everything.
fn parse_selected_domains(v: &serde_json::Value) -> Option<Vec<String>> {
    v.get("domains").and_then(|d| d.as_array()).map(|a| {
        a.iter()
            .filter_map(|x| x.as_str())
            .map(|s| s.to_string())
            .collect()
    })
}

/// Start reading commands from stdin.
///
/// Returns `None` when stdin is not usable (a terminal, or closed): there is
/// nobody to send commands, and reading would either block forever or steal
/// input from the terminal UI.
///
/// The reader is a daemon thread that exits on EOF, so a GUI that simply closes
/// the pipe does not leave anything behind.
pub fn spawn_command_reader() -> Option<crossbeam_channel::Receiver<EngineCommand>> {
    use std::io::BufRead;

    let (tx, rx) = crossbeam_channel::bounded(64);
    std::thread::Builder::new()
        .name("netmon-cmd".into())
        .spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let Ok(line) = line else { break };
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                let cmd = match v.get("cmd").and_then(|c| c.as_str()) {
                    Some("requery") => EngineCommand::Requery {
                        failed_only: v
                            .get("failed_only")
                            .and_then(|b| b.as_bool())
                            .unwrap_or(true),
                    },
                    Some("export_domains") => match v.get("path").and_then(|p| p.as_str()) {
                        Some(p) => EngineCommand::ExportDomains {
                            path: std::path::PathBuf::from(p),
                        },
                        None => continue,
                    },
                    Some("stop") => EngineCommand::Stop,
                    Some("hosts_preview") => EngineCommand::HostsPreview {
                        process: v
                            .get("process")
                            .and_then(|p| p.as_str())
                            .unwrap_or_default()
                            .to_string(),
                        policy: parse_policy(&v),
                    },
                    Some("hosts_write") => EngineCommand::HostsWrite {
                        process: v
                            .get("process")
                            .and_then(|p| p.as_str())
                            .unwrap_or_default()
                            .to_string(),
                        policy: parse_policy(&v),
                        // Only present when the GUI asks for a subset. An empty
                        // array is a real selection of nothing, so it is kept as
                        // `Some(vec![])` rather than collapsed into "all".
                        domains: parse_selected_domains(&v),
                    },
                    // Without a process, the whole block goes; with one, only
                    // that process's entries.
                    Some("hosts_remove") => EngineCommand::HostsRemove {
                        process: v
                            .get("process")
                            .and_then(|p| p.as_str())
                            .filter(|p| !p.is_empty())
                            .map(|s| s.to_string()),
                    },
                    Some("hosts_read") => EngineCommand::HostsRead,
                    Some("hosts_remove_entry") => {
                        let domain = v
                            .get("domain")
                            .and_then(|d| d.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let address = v
                            .get("address")
                            .and_then(|a| a.as_str())
                            .unwrap_or_default()
                            .to_string();
                        if domain.is_empty() || address.is_empty() {
                            continue;
                        }
                        EngineCommand::HostsRemoveEntry {
                            domain,
                            address,
                            process: v
                                .get("process")
                                .and_then(|p| p.as_str())
                                .unwrap_or_default()
                                .to_string(),
                        }
                    }
                    Some("hosts_history") => EngineCommand::HostsHistory {
                        limit: v
                            .get("limit")
                            .and_then(|l| l.as_u64())
                            .unwrap_or(crate::persist::HISTORY_DISPLAY_LIMIT as u64)
                            as usize,
                    },
                    Some("hosts_edit") => match v.get("text").and_then(|t| t.as_str()) {
                        Some(t) => EngineCommand::HostsEdit {
                            text: t.to_string(),
                        },
                        None => continue,
                    },
                    Some("hosts_auto") => EngineCommand::HostsAuto {
                        on: v.get("on").and_then(|b| b.as_bool()).unwrap_or(false),
                        process: v
                            .get("process")
                            .and_then(|p| p.as_str())
                            .map(|s| s.to_string()),
                        policy: parse_policy(&v),
                    },
                    Some("hosts_backup") => EngineCommand::HostsBackup,
                    Some("hosts_prune_backups") => EngineCommand::HostsPruneBackups {
                        keep: v.get("keep").and_then(|k| k.as_u64()).unwrap_or(50) as usize,
                    },
                    Some("hosts_restore") => match v.get("path").and_then(|p| p.as_str()) {
                        Some(p) => EngineCommand::HostsRestore {
                            path: std::path::PathBuf::from(p),
                        },
                        None => continue,
                    },
                    _ => continue,
                };
                if tx.send(cmd).is_err() {
                    break;
                }
            }
        })
        .ok()?;
    Some(rx)
}

// ---------------------------------------------------------------------------
// CPU metering
// ---------------------------------------------------------------------------

/// Samples this process's CPU time from `GetProcessTimes` and reports the
/// percentage of one core used since the previous sample.
pub struct CpuMeter {
    last_kernel: u64,
    last_user: u64,
    last_at: Option<Instant>,
    pub percent: f32,
    pub total_secs: f64,
}

impl CpuMeter {
    pub fn new() -> Self {
        Self {
            last_kernel: 0,
            last_user: 0,
            last_at: None,
            percent: 0.0,
            total_secs: 0.0,
        }
    }

    pub fn sample(&mut self) {
        let (k, u) = process_cpu_time_100ns();
        let now = Instant::now();
        self.total_secs = (k + u) as f64 / 10_000_000.0;
        if let Some(prev) = self.last_at {
            let dt = now.duration_since(prev).as_secs_f64();
            if dt > 0.0 {
                let dk = k.saturating_sub(self.last_kernel) as f64;
                let du = u.saturating_sub(self.last_user) as f64;
                self.percent = (((dk + du) / 10_000_000.0) / dt * 100.0) as f32;
            }
        }
        self.last_kernel = k;
        self.last_user = u;
        self.last_at = Some(now);
    }
}

impl Default for CpuMeter {
    fn default() -> Self {
        Self::new()
    }
}

fn process_cpu_time_100ns() -> (u64, u64) {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    let mut create = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let ok = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut create,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    if ok == 0 {
        return (0, 0);
    }
    let to_u64 = |f: &FILETIME| ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64;
    (to_u64(&kernel), to_u64(&user))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session pointed at a throwaway hosts file, with a block already in it.
    fn session_with_block(name: &str) -> (Session, std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("netmon-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let hosts = dir.join("hosts");
        std::fs::write(&hosts, "# sample\n\r\n127.0.0.1 localhost\r\n\r\n").unwrap();

        let mut session = Session::new(SourceOptions::default(), format!("NetMon{name}"));
        session.hosts_file = Some(hosts.clone());
        session.hosts_backup_dir = Some(dir.join("bak"));

        // Pretend a previous run left entries behind, one per process.
        let made = |address: &str, domain: &str| crate::hosts::PlannedEntry {
            address: address.into(),
            domain: domain.into(),
            reason: crate::hosts::PlanReason::Ipv6,
            previous_session: false,
        };
        for (process, entry) in [
            ("Keep.exe", made("2606:4700::1", "keep.example.com")),
            ("Other.exe", made("2606:4700::2", "other.example.com")),
        ] {
            let f = crate::hosts::HostsFile::load(&hosts).unwrap();
            let bytes = crate::hosts::merge(&f, process, &[entry]).bytes;
            std::fs::write(&hosts, bytes).unwrap();
        }
        (session, hosts, dir)
    }

    /// A write with nothing to write must not erase what is already there.
    ///
    /// Reported as "the hosts file keeps reverting itself": a write for a
    /// process whose domain table was still empty rendered an empty block over
    /// the existing one, silently deleting every entry. Pressing write right
    /// after a restart -- before any domains had been captured -- did it every
    /// time. A merge cannot do that: it only ever adds.
    #[test]
    fn an_empty_write_leaves_every_entry_alone() {
        let (mut session, hosts, _dir) = session_with_block("nowipe");
        let before = std::fs::read(&hosts).unwrap();

        // No process has any domains, so the plan is empty.
        let out = session
            .hosts_write("Ghost.exe", crate::hosts::NoAaaaPolicy::Block)
            .unwrap();
        assert!(out.unchanged, "nothing to write means nothing to do");
        assert!(out.backup.is_none(), "and no backup, since nothing was written");
        assert_eq!(
            std::fs::read(&hosts).unwrap(),
            before,
            "the file must be untouched"
        );

        // Writing for a process with nothing to add is the same thing again.
        let out = session
            .hosts_write("Keep.exe", crate::hosts::NoAaaaPolicy::Block)
            .unwrap();
        assert!(out.unchanged);
        assert_eq!(session.hosts_view().managed_entries, 2);
    }

    /// Removing is per process, and only ever because someone asked.
    #[test]
    fn removal_takes_one_process_entries_at_a_time() {
        let (mut session, hosts, _dir) = session_with_block("perproc");
        let before = std::fs::read(&hosts).unwrap();

        // A process that wrote nothing changes nothing.
        let out = session.hosts_remove(Some("Ghost.exe")).unwrap();
        assert!(out.unchanged && out.removed == 0);
        assert_eq!(std::fs::read(&hosts).unwrap(), before);

        // Only Keep.exe's line goes; the other process's stays.
        let out = session.hosts_remove(Some("Keep.exe")).unwrap();
        assert_eq!(out.removed, 1);
        let left = String::from_utf8_lossy(&std::fs::read(&hosts).unwrap()).into_owned();
        assert!(!left.contains("keep.example.com"));
        assert!(left.contains("other.example.com"), "another process's line must stay");
        assert_eq!(
            session.hosts_view().by_owner,
            vec![("Other.exe".to_string(), 1)]
        );

        // And the rest is still there to be removed explicitly.
        let out = session.hosts_remove(None).unwrap();
        assert_eq!(out.removed, 1);
        assert!(!String::from_utf8_lossy(&std::fs::read(&hosts).unwrap())
            .contains("other.example.com"));
    }

    /// Nothing prunes backups unless asked.
    #[test]
    fn backups_are_only_removed_when_the_user_asks() {
        let dir = std::env::temp_dir().join(format!("netmon-prunetest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let bak = dir.join("bak");
        std::fs::create_dir_all(&bak).unwrap();
        let hosts = dir.join("hosts");
        std::fs::write(&hosts, "x

").unwrap();
        for i in 0..8 {
            std::fs::write(bak.join(format!("hosts-2026010{i}-000000_000.bak")), b"x").unwrap();
        }

        let mut session = Session::new(SourceOptions::default(), "NetMonPrune".into());
        session.hosts_file = Some(hosts);
        session.hosts_backup_dir = Some(bak.clone());

        // Opening and reading touches nothing.
        let _ = session.hosts_view();
        assert_eq!(crate::hosts::list_backups(&bak).len(), 8);

        // Asking removes, and keeps the newest.
        assert_eq!(session.hosts_prune_backups(3), 5);
        assert_eq!(crate::hosts::list_backups(&bak).len(), 3);
    }

    /// A data directory holding one previous session's table for `edge.exe`,
    /// plus a hosts file to manage.
    fn cache_fixture(name: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!("netmon-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let data = base.join("data");
        let hosts = base.join("hosts");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(&hosts, "# sample\r\n127.0.0.1 localhost\r\n").unwrap();
        let now = crate::util::now_unix_ms();
        let snap = crate::persist::Snapshot {
            version: crate::persist::SNAPSHOT_VERSION,
            saved_at_ms: now,
            processes: vec![crate::persist::SavedProcess {
                process: "edge.exe".into(),
                pid: 1234,
                first_seen_ms: now,
                last_seen_ms: now,
                domains: vec![
                    crate::persist::SavedDomain {
                        domain: "old.example.com".into(),
                        answer: "found".into(),
                        aaaa: vec!["2606:4700::7".into()],
                        own: Vec::new(),
                        error: String::new(),
                        queried_at_ms: now,
                    },
                    crate::persist::SavedDomain {
                        domain: "gone.example.com".into(),
                        answer: "none".into(),
                        aaaa: Vec::new(),
                        own: Vec::new(),
                        error: String::new(),
                        queried_at_ms: now,
                    },
                ],
            }],
        };
        crate::persist::save_snapshot(&data, &snap).unwrap();
        (base, data, hosts)
    }

    fn session_with_cache(base: &Path, data: &Path, hosts: &Path, name: &str) -> Session {
        let mut s = Session::new(SourceOptions::default(), name.into());
        s.hosts_file = Some(hosts.to_path_buf());
        s.hosts_backup_dir = Some(base.join("bak"));
        s.data_dir = Some(data.to_path_buf());
        s
    }

    /// The point of the cache: after a restart, last session's domains are
    /// still known, and the hosts entries they produced are still manageable.
    #[test]
    fn the_previous_sessions_tables_come_back_and_can_be_managed() {
        let (base, data, hosts) = cache_fixture("cache");
        let mut s = session_with_cache(&base, &data, &hosts, "NetMonCache1");
        assert_eq!(s.load_domain_cache(), 2);
        assert!(
            s.domains.rows_for("edge.exe").iter().all(|(_, e)| e.archived),
            "restored rows are history, not live data"
        );
        let preview = s.hosts_preview("edge.exe", crate::hosts::NoAaaaPolicy::Block).unwrap();
        assert_eq!(preview.len(), 2);
        assert!(preview.iter().all(|e| e.previous_session), "rows are labelled");

        // Writing from the cached table still works, and is logged.
        let out = s
            .hosts_write("edge.exe", crate::hosts::NoAaaaPolicy::Block)
            .unwrap();
        assert_eq!(out.appended, 2);
        let text = std::fs::read_to_string(&hosts).unwrap();
        assert!(text.contains("2606:4700::7") && text.contains("old.example.com"));
        assert!(text.contains("gone.example.com"));
        let hist = s.hosts_history(10);
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].action, "write");
        assert_eq!(hist[0].process, "edge.exe");
        assert_eq!(hist[0].appended, 2);
        drop(s);

        // A fresh session, as after closing and reopening the program.
        let mut next = session_with_cache(&base, &data, &hosts, "NetMonCache2");
        assert_eq!(next.load_domain_cache(), 2);
        assert_eq!(
            next.hosts_view().by_owner,
            vec![("edge.exe".to_string(), 2)],
            "the window can still list the process that wrote the entries"
        );
        let out = next.hosts_remove(Some("edge.exe")).unwrap();
        assert_eq!(out.removed, 2, "and can remove them per process");
        let hist = next.hosts_history(10);
        assert_eq!(hist.len(), 2, "the removal is recorded too");
        assert_eq!(hist[1].action, "remove_process");
    }

    /// A subset write narrows *which* rows are planned, not the rules applied to
    /// them: everything outside the selection must stay untouched.
    ///
    /// This is the engine side of the preview window's Ctrl-select + right-click
    /// action. The selection is a list of domain names, never of addresses, so a
    /// name that now resolves somewhere else is still judged by the current
    /// answer rather than by whatever the user saw when they selected it.
    #[test]
    fn a_selected_write_touches_only_the_named_domains() {
        let (base, data, hosts) = cache_fixture("subset");
        let mut s = session_with_cache(&base, &data, &hosts, "NetMonSubset");
        assert_eq!(s.load_domain_cache(), 2);

        let out = s
            .hosts_write_selected(
                "edge.exe",
                crate::hosts::NoAaaaPolicy::Block,
                &["old.example.com".to_string()],
            )
            .unwrap();
        assert_eq!(out.appended, 1);
        let text = std::fs::read_to_string(&hosts).unwrap();
        assert!(text.contains("old.example.com"));
        assert!(
            !text.contains("gone.example.com"),
            "a domain that was not selected must not be written"
        );

        // The read model the "current entries" tab displays: the line, with the
        // process that asked for it.
        let view = s.hosts_view();
        assert_eq!(view.entries.len(), 1);
        assert_eq!(view.entries[0].domain, "old.example.com");
        assert_eq!(view.entries[0].owners, vec!["edge.exe".to_string()]);

        // Selecting nothing is a real request to write nothing, not a request to
        // fall back to writing everything.
        let before = std::fs::read(&hosts).unwrap();
        let out = s
            .hosts_write_selected("edge.exe", crate::hosts::NoAaaaPolicy::Block, &[])
            .unwrap();
        assert!(out.unchanged);
        assert_eq!(std::fs::read(&hosts).unwrap(), before);
    }

    /// Deleting one displayed line removes exactly that line, and the viewer
    /// gets the raw text back so it can copy it.
    #[test]
    fn deleting_one_line_removes_it_and_the_view_has_its_raw_text() {
        let (mut s, hosts, _dir) = session_with_block("entrydel");
        let view = s.hosts_view();
        assert_eq!(view.entries.len(), 2);
        let keep = view
            .entries
            .iter()
            .find(|e| e.domain == "keep.example.com")
            .expect("the fixture writes this line")
            .clone();
        assert!(
            keep.line.contains("# nm Keep.exe"),
            "the raw line keeps its owner tag: {:?}",
            keep.line
        );

        let out = s
            .hosts_remove_entry("keep.example.com", &keep.address, "Keep.exe")
            .unwrap();
        assert_eq!(out.removed, 1);
        let text = std::fs::read_to_string(&hosts).unwrap();
        assert!(!text.contains("keep.example.com"));
        assert!(text.contains("other.example.com"), "other lines stay");

        // Deleting what is already gone reports "nothing changed" rather than
        // rewriting the file and taking a pointless backup.
        let out = s
            .hosts_remove_entry("keep.example.com", &keep.address, "Keep.exe")
            .unwrap();
        assert!(out.unchanged);
        assert!(out.backup.is_none());
    }

    /// Automatic writing must not re-assert an answer nothing resolved today.
    #[test]
    fn automatic_writing_ignores_previous_session_rows() {
        let (base, data, hosts) = cache_fixture("autocache");
        let mut s = session_with_cache(&base, &data, &hosts, "NetMonAutoCache");
        s.load_domain_cache();
        s.set_hosts_auto(true, Some("edge.exe".into()));
        for _ in 0..5 {
            assert!(s.hosts_auto_tick().is_none());
        }
        assert!(
            !std::fs::read_to_string(&hosts).unwrap().contains("old.example.com"),
            "a cached answer must not be written back without a live observation"
        );
        assert_eq!(s.hosts_auto.writes, 0);
    }

    /// The presence/absence distinction the subset write depends on.
    #[test]
    fn the_subset_field_distinguishes_absent_from_empty() {
        let whole_table = serde_json::json!({"cmd": "hosts_write", "process": "a.exe"});
        assert_eq!(parse_selected_domains(&whole_table), None);

        let selected_nothing = serde_json::json!({"domains": []});
        assert_eq!(parse_selected_domains(&selected_nothing), Some(Vec::new()));

        let some = serde_json::json!({"domains": ["a.example.com", "b.example.com", 7]});
        assert_eq!(
            parse_selected_domains(&some),
            Some(vec!["a.example.com".to_string(), "b.example.com".to_string()])
        );
    }

    #[test]
    fn cpu_meter_is_finite() {
        let mut m = CpuMeter::new();
        m.sample();
        std::thread::sleep(std::time::Duration::from_millis(60));
        m.sample();
        assert!(m.percent.is_finite());
        assert!(m.total_secs >= 0.0);
    }

    #[test]
    fn launch_requires_capture_first() {
        let mut s = Session::new(SourceOptions::default(), "NetMonTest".into());
        let exe = std::env::current_exe().unwrap();
        let err = s.launch_target(&exe, &["--help".to_string()]);
        assert!(err.is_err(), "launching before capture must be refused");
    }
}
