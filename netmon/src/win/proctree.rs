//! Target process-tree tracking.
//!
//! The monitor must accept an executable path, not a PID, and must cover every
//! descendant the target spawns (browsers are the canonical example: one
//! `chrome.exe` becomes dozens of children, each with its own network stack).
//!
//! Strategy:
//!
//! * A background thread takes a `CreateToolhelp32Snapshot` (TH32CS_SNAPPROCESS)
//!   every `SWEEP_INTERVAL_MS` and recomputes the descendant closure of the
//!   root PID. A full sweep costs tens of microseconds, so this is far cheaper
//!   than it sounds -- and it never touches the capture threads.
//! * Membership is *sticky for a grace period*: when a PID leaves the snapshot
//!   it is remembered for `RECENT_TTL_MS`. Short-lived helpers (`git`, `curl`,
//!   a one-shot updater) can resolve a name and exit between two sweeps; their
//!   events still land inside the window and must not be dropped.
//! * If an event arrives from a PID we have never seen, `contains_or_adopt`
//!   forces an immediate re-sweep and walks the ancestor chain. That closes the
//!   remaining race for children that are still alive but younger than the last
//!   sweep.
//!
//! Everything here is deliberately cheap and allocation-light: it runs often.

use std::collections::{HashMap, HashSet, VecDeque};

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};

/// How often the sweeper thread re-reads the process list.
pub const SWEEP_INTERVAL_MS: u64 = 150;

/// How long an exited PID keeps its membership / name.
const RECENT_TTL_MS: i64 = 20_000;

/// One row of a process snapshot.
#[derive(Clone, Debug)]
pub struct ProcEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
}

/// Take a full process snapshot. Returns an empty vector on failure; callers
/// treat that as "no information" rather than as an error, so a transient
/// failure can never tear down the monitor.
pub fn snapshot() -> Vec<ProcEntry> {
    let mut out = Vec::with_capacity(256);
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE || snap.is_null() {
            return out;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                out.push(ProcEntry {
                    pid: entry.th32ProcessID,
                    ppid: entry.th32ParentProcessID,
                    name: String::from_utf16_lossy(&entry.szExeFile[..len]),
                });
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

/// Resolve a single PID to its image name (``"chrome.exe"``), if it is alive.
pub fn image_name(pid: u32) -> Option<String> {
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut buf = vec![0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(h);
        if ok == 0 {
            return None;
        }
        let full = String::from_utf16_lossy(&buf[..size as usize]);
        Some(
            full.rsplit(['\\', '/'])
                .next()
                .unwrap_or(&full)
                .to_string(),
        )
    }
}

/// Tracks the root process and all of its descendants.
#[derive(Default)]
pub struct TreeTracker {
    /// Processes the user explicitly named -- launched, attached, or matched at
    /// startup.
    ///
    /// Never retired automatically. A sweep that happens not to see one (it
    /// exited between the spawn and the snapshot, or the snapshot raced the
    /// spawn) must not silently end the session; only a new `set_roots` call
    /// replaces this list.
    explicit_roots: Vec<u32>,
    /// Processes adopted because their image name matched a `--watch` pattern.
    ///
    /// These *are* retired once they are gone and have no living children: the
    /// pattern will adopt them again if they come back, so holding on to a dead
    /// PID would only make the root list grow all session.
    discovered_roots: Vec<u32>,
    /// PIDs currently believed to belong to the target tree.
    members: HashSet<u32>,
    /// pid -> image name for everything we have ever seen in the tree.
    names: HashMap<u32, String>,
    /// pid -> unix-ms when it last appeared in a sweep, for exited members.
    recently_exited: HashMap<u32, i64>,
    /// PIDs that a full sweep proved are *not* descendants of the root. Used
    /// only as a negative filter on the ETW hot path: an unknown PID is always
    /// forwarded, so a freshly spawned child can never be lost.
    foreign: HashSet<u32>,
    /// Image names adopted on sight, lower-cased. Empty outside `--watch`.
    watch_names: Vec<String>,
    /// Where `publish_foreign` writes the negative filter. Shared with the ETW
    /// callback; see `publish_foreign` for why the write happens in here.
    foreign_sink: Option<std::sync::Arc<std::sync::RwLock<HashSet<u32>>>>,
    /// Set when no root is left alive, so the UI can report it.
    pub root_exited: bool,
    pub sweeps: u64,
}

impl TreeTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every root, explicit ones first.
    fn all_roots(&self) -> Vec<u32> {
        let mut v = self.explicit_roots.clone();
        v.extend(self.discovered_roots.iter().copied());
        v
    }

    /// The first root, for logging and display.
    pub fn root(&self) -> Option<u32> {
        self.explicit_roots
            .first()
            .or_else(|| self.discovered_roots.first())
            .copied()
    }

    /// Single-root convenience wrapper. The binary uses `set_roots`; this
    /// exists because most tests care about one root.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn set_root(&mut self, pid: u32) {
        self.set_roots(&[pid]);
    }

    /// Adopt a whole set of processes as roots.
    pub fn set_roots(&mut self, pids: &[u32]) {
        self.explicit_roots = pids.to_vec();
        self.discovered_roots.clear();
        self.root_exited = false;
        self.members.clear();
        self.recently_exited.clear();
        for pid in &self.explicit_roots {
            self.members.insert(*pid);
            if let Some(n) = image_name(*pid) {
                self.names.insert(*pid, n);
            }
        }
    }

    /// Adopt additional roots without dropping the ones already watched.
    ///
    /// Used when several targets are launched one after another: each launch
    /// adds its process to the same tree, so a child of the first target and a
    /// child of the third are both attributed. Roots discovered by name
    /// (`--watch`) are left alone, since they are re-derived every sweep.
    pub fn add_roots(&mut self, pids: &[u32]) {
        for pid in pids {
            if *pid == 0 || self.explicit_roots.contains(pid) {
                continue;
            }
            self.explicit_roots.push(*pid);
            self.members.insert(*pid);
            if let Some(n) = image_name(*pid) {
                self.names.insert(*pid, n);
            }
        }
        self.root_exited = false;
    }

    pub fn clear(&mut self) {
        self.explicit_roots.clear();
        self.discovered_roots.clear();
        self.members.clear();
        self.names.clear();
        self.recently_exited.clear();
        self.foreign.clear();
        self.root_exited = false;
    }

    /// Root list, for the diagnostics log.
    pub fn debug_roots(&self) -> Vec<u32> {
        self.all_roots()
    }

    /// PIDs proven to be outside the target tree by the most recent sweep.
    ///
    /// The binary reads this through the shared sink rather than directly; this
    /// accessor is what the invariant tests assert against.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn foreign(&self) -> &HashSet<u32> {
        &self.foreign
    }

    pub fn member_count(&self) -> usize {
        self.members.len() + self.recently_exited.len()
    }

    /// Members believed to be alive right now, ignoring the grace period for
    /// recently-exited ones. This is the honest "is anything still running?"
    /// test, used to decide whether a session has anything left to watch.
    pub fn live_member_count(&self) -> usize {
        self.members.len()
    }

    /// Image name for a PID, falling back to a placeholder.
    pub fn name_of(&self, pid: u32) -> String {
        if let Some(n) = self.names.get(&pid) {
            return n.clone();
        }
        image_name(pid).unwrap_or_else(|| format!("pid:{pid}"))
    }

    /// Adopt processes by image name, continuously.
    ///
    /// Set this to watch for processes that do not exist yet: the sweep adopts
    /// any process whose image name matches, the moment it appears, and traces
    /// its descendants. That is what a program with a separate download helper
    /// needs -- the helper is spawned on demand, long after monitoring starts.
    ///
    /// Matching is by image name only. A process is included if its own name
    /// matches; the main application is therefore excluded automatically, as
    /// long as it goes by a different name than the helper.
    /// Share the ETW callback's negative filter with this tracker. Set once,
    /// before the first sweep.
    pub fn set_foreign_sink(
        &mut self,
        sink: std::sync::Arc<std::sync::RwLock<HashSet<u32>>>,
    ) {
        self.foreign_sink = Some(sink);
    }

    pub fn set_watch_names(&mut self, names: Vec<String>) {
        self.watch_names = names
            .into_iter()
            .map(|n| n.trim().to_ascii_lowercase())
            .filter(|n| !n.is_empty())
            .collect();
    }

    pub fn watch_names(&self) -> &[String] {
        &self.watch_names
    }

    /// Recompute the descendant closure from a fresh snapshot.
    pub fn refresh(&mut self) {
        self.sweeps += 1;
        let entries = snapshot();
        let now = crate::util::now_unix_ms();

        // Adopt anything matching a watched image name. Done against the
        // snapshot we already took, so watching costs nothing extra.
        if !self.watch_names.is_empty() {
            for e in &entries {
                let name = e.name.to_ascii_lowercase();
                if self.watch_names.iter().any(|w| *w == name)
                    && !self.explicit_roots.contains(&e.pid)
                    && !self.discovered_roots.contains(&e.pid)
                {
                    self.discovered_roots.push(e.pid);
                    self.names.insert(e.pid, e.name.clone());
                }
            }
        }

        if self.explicit_roots.is_empty() && self.discovered_roots.is_empty() {
            // Nothing adopted yet -- the normal state while `--watch` waits for
            // the helper to start. Clear stale membership so the UI reports an
            // empty tree rather than the last one forever, but still refresh
            // `foreign`: without it every unrelated process's events would fall
            // through to the expensive per-event path below.
            self.members.clear();
            self.recently_exited.clear();
            self.foreign = entries.iter().map(|e| e.pid).collect();
            self.root_exited = true;
            self.publish_foreign();
            return;
        }

        let roots = self.all_roots();

        let mut children: HashMap<u32, Vec<u32>> = HashMap::with_capacity(entries.len());
        let mut alive: HashSet<u32> = HashSet::with_capacity(entries.len());
        for e in &entries {
            alive.insert(e.pid);
            children.entry(e.ppid).or_default().push(e.pid);
            // Only remember names for PIDs we care about, to bound memory.
            if roots.contains(&e.pid) || self.members.contains(&e.pid) {
                self.names.insert(e.pid, e.name.clone());
            }
        }
        if !roots.iter().any(|r| alive.contains(r)) {
            self.root_exited = true;
        }

        let mut next: HashSet<u32> = HashSet::new();
        let mut queue: VecDeque<u32> = VecDeque::new();
        for r in &roots {
            if next.insert(*r) {
                queue.push_back(*r);
            }
        }
        while let Some(p) = queue.pop_front() {
            if let Some(kids) = children.get(&p) {
                for &k in kids {
                    if next.insert(k) {
                        queue.push_back(k);
                    }
                }
            }
        }

        // Remember names for every new member.
        for e in &entries {
            if next.contains(&e.pid) {
                self.names.insert(e.pid, e.name.clone());
            }
        }

        // Age out exited members, but keep them visible for a grace period so
        // late events from processes that just died are still attributed.
        for pid in self.members.difference(&next) {
            self.recently_exited.insert(*pid, now);
            if let Some(n) = self.names.get(pid) {
                let n = n.clone();
                self.names.entry(*pid).or_insert(n);
            }
        }
        self.recently_exited
            .retain(|_, seen| now - *seen < RECENT_TTL_MS);
        for pid in next.iter() {
            self.recently_exited.remove(pid);
        }

        // Everything alive that is not a member is, by construction, provably
        // outside the tree.
        self.foreign.clear();
        for e in &entries {
            if !next.contains(&e.pid) {
                self.foreign.insert(e.pid);
            }
        }

        // Retire *discovered* roots that are gone for good.
        //
        // A dead root must be kept while it still has living children -- the
        // closure is walked *from* the roots, so dropping it would drop its
        // whole subtree. Once nothing references it any more it is just a PID
        // that will never come back and the watch pattern will re-adopt the
        // name if it does.
        //
        // Explicit roots are never retired here. Doing so was a real bug: the
        // target is adopted immediately after CreateProcess, and if that sweep's
        // snapshot happened not to include the brand-new process yet, the root
        // was dropped, the next sweep cleared membership, and the session
        // captured nothing at all from a target that was running fine.
        self.discovered_roots
            .retain(|r| alive.contains(r) || children.contains_key(r));

        self.members = next;
        self.publish_foreign();
    }

    /// Push the negative filter out to the capture hot path.
    ///
    /// # Why this lives inside the tracker
    ///
    /// The foreign set used to be assembled by the caller *after* releasing the
    /// tree lock, which opened a race with a consequence that is hard to see
    /// and easy to blame on something else:
    ///
    /// 1. the watcher takes a snapshot while nothing is adopted yet, so every
    ///    running process looks foreign;
    /// 2. the target is launched and adopted in the meantime;
    /// 3. the watcher publishes its stale set, which names the target as
    ///    foreign;
    /// 4. the target's first DNS queries arrive and are dropped by the cheap
    ///    negative filter, before any attribution logic ever sees them.
    ///
    /// The result was a short-lived target producing *nothing at all*, which is
    /// exactly what it looks like when the tool is broken. Computing and
    /// publishing under the caller's tree lock makes the set consistent with
    /// the membership it was derived from.
    fn publish_foreign(&self) {
        let Some(sink) = &self.foreign_sink else {
            return;
        };
        if let Ok(mut f) = sink.write() {
            *f = self.foreign.clone();
        }
    }

    /// Is `pid` part of the target tree?
    pub fn contains(&self, pid: u32) -> bool {
        if self.members.contains(&pid) {
            return true;
        }
        if let Some(seen) = self.recently_exited.get(&pid) {
            return crate::util::now_unix_ms() - *seen < RECENT_TTL_MS;
        }
        false
    }

    /// Membership test that forces a fresh sweep for unknown PIDs and walks the
    /// ancestor chain, then adopts the PID if the root turns out to be an
    /// ancestor. This is what makes the very first DNS query of a
    /// just-spawned child reliable.
    pub fn contains_or_adopt(&mut self, pid: u32) -> bool {
        if self.contains(pid) {
            return true;
        }
        // Nothing to walk up to *and* nothing to match by name: this PID is
        // outside the tree by definition.
        if self.explicit_roots.is_empty()
            && self.discovered_roots.is_empty()
            && self.watch_names.is_empty()
        {
            return false;
        }
        let roots = self.all_roots();
        let entries = snapshot();
        let mut parent: HashMap<u32, u32> = HashMap::with_capacity(entries.len());
        let mut names: HashMap<u32, String> = HashMap::with_capacity(entries.len());
        for e in &entries {
            parent.insert(e.pid, e.ppid);
            names.insert(e.pid, e.name.clone());
        }

        // A watched name is a root in its own right, so it is adopted here
        // rather than waiting for the next sweep. Without this the helper's
        // first queries -- the ones issued the instant it starts, which is
        // exactly when a download helper resolves its server -- arrive inside
        // the sweep interval and are discarded before it is ever a member.
        if !self.watch_names.is_empty() {
            if let Some(name) = names.get(&pid) {
                if self
                    .watch_names
                    .iter()
                    .any(|w| *w == name.to_ascii_lowercase())
                {
                    if !self.explicit_roots.contains(&pid)
                        && !self.discovered_roots.contains(&pid)
                    {
                        self.discovered_roots.push(pid);
                    }
                    self.members.insert(pid);
                    self.names.insert(pid, name.clone());
                    return true;
                }
            }
        }
        // Walk up from `pid` looking for the root.
        let mut cur = pid;
        let mut hops = 0;
        while hops < 64 {
            if roots.contains(&cur) {
                self.members.insert(pid);
                if let Some(n) = names.get(&pid) {
                    self.names.insert(pid, n.clone());
                }
                return true;
            }
            match parent.get(&cur) {
                Some(&p) if p != 0 && p != cur => {
                    cur = p;
                    hops += 1;
                }
                _ => return false,
            }
        }
        false
    }

    /// Attach to an already-running process selected by image name. Returns the
    /// PIDs that matched.
    pub fn find_by_image_name(name: &str) -> Vec<u32> {
        let want = name.to_ascii_lowercase();
        snapshot()
            .into_iter()
            .filter(|e| e.name.to_ascii_lowercase() == want)
            .map(|e| e.pid)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_contains_self() {
        let me = std::process::id();
        let snap = snapshot();
        assert!(snap.iter().any(|e| e.pid == me), "own pid must be in snapshot");
    }

    #[test]
    fn own_image_name_resolves() {
        let n = image_name(std::process::id());
        assert!(n.is_some());
        assert!(n.unwrap().to_ascii_lowercase().ends_with(".exe"));
    }

    /// The negative filter must never name a process we have adopted.
    ///
    /// A stale set used to be able to: the watcher snapshotted the process list
    /// before the target was launched, adopted the target in the meantime, and
    /// then published its stale set naming the target as foreign. Every query
    /// the target made was then dropped by the cheap filter, and a working
    /// monitor looked like a broken one.
    #[test]
    fn adopted_roots_are_never_published_as_foreign() {
        let me = std::process::id();
        let sink = std::sync::Arc::new(std::sync::RwLock::new(HashSet::new()));

        let mut t = TreeTracker::new();
        t.set_foreign_sink(sink.clone());
        t.set_root(me);
        t.refresh();

        let published = sink.read().unwrap().clone();
        assert!(
            !published.contains(&me),
            "an adopted root must never be published as foreign"
        );
        assert!(!published.is_empty(), "other processes should still be listed");
        assert!(t.contains(me));
    }

    /// Before anything is adopted, `--watch` is waiting for a process to
    /// appear; everything currently running is legitimately foreign.
    #[test]
    fn nothing_adopted_publishes_every_process_as_foreign() {
        let sink = std::sync::Arc::new(std::sync::RwLock::new(HashSet::new()));
        let mut t = TreeTracker::new();
        t.set_foreign_sink(sink.clone());
        t.refresh();
        let published = sink.read().unwrap().clone();
        assert!(
            published.contains(&std::process::id()),
            "with no roots adopted, even this process is outside the tree"
        );
        assert_eq!(t.member_count(), 0);
    }

    /// `--watch` adopts a process the instant it sees the name, and traces its
    /// descendants -- which is the whole point: the helper does not exist yet
    /// when monitoring is armed.
    #[test]
    fn watch_names_are_adopted_and_traced() {
        let me = std::process::id();
        let my_name = image_name(me).expect("own image name");
        let mut t = TreeTracker::new();
        t.set_watch_names(vec![my_name.to_ascii_uppercase()]);
        t.refresh();
        assert!(t.contains(me), "watched name must be adopted on sight");
        assert!(t.contains_or_adopt(me));
    }

    #[test]
    fn tracker_adopts_self_as_root() {
        let me = std::process::id();
        let mut t = TreeTracker::new();
        t.set_root(me);
        t.refresh();
        assert!(t.contains(me));
        assert!(t.contains_or_adopt(me));
        assert!(!t.contains_or_adopt(u32::MAX));
    }

    /// Adding roots is how several launched targets share one tree: the second
    /// launch must not drop the first, and re-adopting the same PID must not
    /// duplicate it.
    #[test]
    fn added_roots_accumulate() {
        let me = std::process::id();
        let other = std::process::id().wrapping_add(1);
        let mut t = TreeTracker::new();
        t.add_roots(&[me]);
        t.refresh();
        t.add_roots(&[me, other]);
        t.refresh();
        assert!(t.contains(me), "the first root survives");
        assert_eq!(
            t.debug_roots().iter().filter(|p| **p == me).count(),
            1,
            "re-adding a root does not duplicate it"
        );
    }
}

#[cfg(test)]
mod prune_probe {
    use super::*;

    /// An explicitly adopted root must survive a sweep, even one where it does
    /// not appear in the snapshot.
    #[test]
    fn explicit_root_survives_a_sweep_without_it() {
        // A PID that certainly does not exist.
        let ghost = u32::MAX - 7;
        let mut t = TreeTracker::new();
        t.set_root(ghost);
        assert_eq!(t.root(), Some(ghost));
        t.refresh();
        assert_eq!(
            t.root(),
            Some(ghost),
            "the adopted root was pruned by a sweep that did not see it"
        );
        assert!(t.contains(ghost), "and it must still count as a member");
    }
}
