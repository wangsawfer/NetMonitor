//! The local cache: domain tables and the hosts change log.
//!
//! Both exist for the same reason: a hosts entry outlives the session that
//! wrote it. After a restart the program must still be able to answer "which
//! processes have entries in the file, what did they resolve at the time, and
//! when was this written" -- otherwise the only way to undo an entry is to
//! delete the whole block.
//!
//! Two files, both beside the executable by default (`--data-dir` moves them):
//!
//! * `domain-tables.json` -- the last snapshot of every process's domain table.
//!   Rewritten atomically, so a crash cannot leave half a JSON document.
//! * `hosts-history.ndjson` -- one JSON object per line, appended and never
//!   rewritten. A crash can at worst truncate the last line, and the reader
//!   skips lines it cannot parse instead of failing the whole file.
//!
//! Nothing here is required for the program to work: a missing, unreadable or
//! corrupt cache is treated as "no history yet", never as an error the user has
//! to deal with.

use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Bumped when the snapshot layout changes. An older or newer file is ignored
/// rather than guessed at -- losing one session's history is better than
/// misreading it.
pub const SNAPSHOT_VERSION: u32 = 1;

/// How many history records the UI shows at once.
pub const HISTORY_DISPLAY_LIMIT: usize = 500;

/// How long a domain row stays in the snapshot.
///
/// Browsers touch thousands of names a session; keeping every one forever would
/// make the snapshot grow without bound. Ninety days of history is enough to
/// recognise what an entry was for, and a domain that still has a line in the
/// hosts file is kept regardless of age -- those are the ones the cache exists
/// to manage.
pub const CACHE_MAX_AGE_DAYS: i64 = 90;

/// The domain-table snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub saved_at_ms: i64,
    pub processes: Vec<SavedProcess>,
}

/// One process's table in the snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedProcess {
    pub process: String,
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub first_seen_ms: i64,
    #[serde(default)]
    pub last_seen_ms: i64,
    pub domains: Vec<SavedDomain>,
}

/// One domain row in the snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedDomain {
    pub domain: String,
    /// `found`, `none`, `nxdomain` or `failed`.
    pub answer: String,
    /// The AAAA addresses, when the answer was `found`.
    #[serde(default)]
    pub aaaa: Vec<String>,
    /// What this program resolved itself (A plus AAAA).
    #[serde(default)]
    pub own: Vec<String>,
    /// Why the lookup failed, when `answer` is `failed`.
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub queried_at_ms: i64,
}

/// One line of the hosts change log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub at_ms: i64,
    /// `write`, `auto_write`, `remove_process`, `remove_all`, `remove_entry`,
    /// `restore`, `edit`.
    pub action: String,
    #[serde(default)]
    pub process: String,
    #[serde(default)]
    pub appended: usize,
    #[serde(default)]
    pub upgraded: usize,
    #[serde(default)]
    pub claimed: usize,
    #[serde(default)]
    pub removed: usize,
    #[serde(default)]
    pub shared: usize,
    #[serde(default)]
    pub backup: String,
    #[serde(default)]
    pub note: String,
}

impl HistoryEntry {
    /// Short label for the list.
    pub fn action_label(&self) -> &'static str {
        match self.action.as_str() {
            "write" => "写入",
            "auto_write" => "自动写入",
            "remove_process" => "移除该进程",
            "remove_all" => "移除全部",
            "remove_entry" => "删除条目",
            "restore" => "恢复备份",
            "edit" => "编辑保存",
            _ => "其它",
        }
    }

    /// What changed, in one phrase.
    pub fn detail(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.appended > 0 {
            parts.push(format!("新增 {}", self.appended));
        }
        if self.upgraded > 0 {
            parts.push(format!("更新为 IPv6 {}", self.upgraded));
        }
        if self.claimed > 0 {
            parts.push(format!("登记 {}", self.claimed));
        }
        if self.removed > 0 {
            parts.push(format!("删除 {}", self.removed));
        }
        if self.shared > 0 {
            parts.push(format!("共用保留 {}", self.shared));
        }
        if parts.is_empty() {
            "无改动".to_string()
        } else {
            parts.join("，")
        }
    }
}

/// Directory holding the cache. Beside the executable by default, which keeps
/// it off the system drive; `--data-dir` overrides it.
pub fn default_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("netmon-data")))
        .unwrap_or_else(|| PathBuf::from("netmon-data"))
}

/// Local wall-clock text for a millisecond timestamp.
pub fn format_time(ms: i64) -> String {
    use chrono::TimeZone as _;
    chrono::Local
        .timestamp_millis_opt(ms)
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "?".to_string())
}

pub fn snapshot_path(dir: &Path) -> PathBuf {
    dir.join("domain-tables.json")
}

pub fn history_path(dir: &Path) -> PathBuf {
    dir.join("hosts-history.ndjson")
}

/// Write the snapshot atomically.
pub fn save_snapshot(dir: &Path, snap: &Snapshot) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = snapshot_path(dir);
    let tmp = dir.join(format!(".domain-tables-{}.tmp", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        serde_json::to_writer(&mut f, snap).map_err(std::io::Error::other)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e
    })?;
    Ok(path)
}

/// Read the snapshot, or `None` when there is nothing usable.
///
/// Every failure mode -- missing file, unreadable, not JSON, wrong version --
/// means the same thing to the caller: start with an empty history.
pub fn load_snapshot(dir: &Path) -> Option<Snapshot> {
    let bytes = std::fs::read(snapshot_path(dir)).ok()?;
    let snap: Snapshot = serde_json::from_slice(&bytes).ok()?;
    if snap.version != SNAPSHOT_VERSION {
        return None;
    }
    Some(snap)
}

/// Append one change-log record.
///
/// If the file does not end with a newline -- which is what a crash in the
/// middle of a write leaves behind -- one is written first. Otherwise the new
/// record would be glued onto the truncated one and lost with it.
pub fn append_history(dir: &Path, entry: &HistoryEntry) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};

    std::fs::create_dir_all(dir)?;
    let path = history_path(dir);
    let needs_newline = match std::fs::File::open(&path) {
        Ok(mut f) => {
            let len = f.metadata()?.len();
            if len == 0 {
                false
            } else {
                f.seek(SeekFrom::End(-1))?;
                let mut last = [0u8; 1];
                f.read_exact(&mut last)?;
                last[0] != b'\n'
            }
        }
        Err(_) => false,
    };

    let mut line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
    line.push('\n');
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    if needs_newline {
        f.write_all(b"\n")?;
    }
    f.write_all(line.as_bytes())?;
    f.sync_data().ok();
    Ok(())
}

/// Read the change log, oldest first, keeping at most `limit` records.
///
/// Unparsable lines are skipped: after a crash the final line may be truncated,
/// and one damaged line must not hide the rest of the history.
pub fn load_history(dir: &Path, limit: usize) -> Vec<HistoryEntry> {
    let Ok(text) = std::fs::read_to_string(history_path(dir)) else {
        return Vec::new();
    };
    let mut out: Vec<HistoryEntry> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<HistoryEntry>(l).ok())
        .collect();
    if out.len() > limit {
        out.drain(..out.len() - limit);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "netmon-persist-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn sample_snapshot() -> Snapshot {
        Snapshot {
            version: SNAPSHOT_VERSION,
            saved_at_ms: 1_760_000_000_000,
            processes: vec![SavedProcess {
                process: "msedge.exe".into(),
                pid: 42,
                first_seen_ms: 1,
                last_seen_ms: 2,
                domains: vec![SavedDomain {
                    domain: "www.example.com".into(),
                    answer: "found".into(),
                    aaaa: vec!["2606:4700::1".into()],
                    own: vec!["93.184.216.34".into()],
                    error: String::new(),
                    queried_at_ms: 3,
                }],
            }],
        }
    }

    #[test]
    fn a_snapshot_survives_a_round_trip() {
        let d = dir("roundtrip");
        save_snapshot(&d, &sample_snapshot()).unwrap();
        let back = load_snapshot(&d).expect("snapshot must load");
        assert_eq!(back.version, SNAPSHOT_VERSION);
        assert_eq!(back.processes.len(), 1);
        assert_eq!(back.processes[0].process, "msedge.exe");
        assert_eq!(back.processes[0].domains[0].aaaa, vec!["2606:4700::1"]);
        assert_eq!(back.processes[0].domains[0].own, vec!["93.184.216.34"]);
    }

    #[test]
    fn a_missing_snapshot_is_not_an_error() {
        assert!(load_snapshot(&dir("missing")).is_none());
    }

    #[test]
    fn a_corrupt_or_future_snapshot_is_ignored() {
        let d = dir("corrupt");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(snapshot_path(&d), b"{ not json").unwrap();
        assert!(load_snapshot(&d).is_none());

        let mut future = sample_snapshot();
        future.version = SNAPSHOT_VERSION + 1;
        save_snapshot(&d, &future).unwrap();
        assert!(load_snapshot(&d).is_none(), "an unknown version is not guessed at");
    }

    fn rec(action: &str, process: &str) -> HistoryEntry {
        HistoryEntry {
            at_ms: 1,
            action: action.into(),
            process: process.into(),
            appended: 1,
            upgraded: 0,
            claimed: 0,
            removed: 0,
            shared: 0,
            backup: "b".into(),
            note: "n".into(),
        }
    }

    #[test]
    fn history_keeps_order_and_honours_the_limit() {
        let d = dir("history");
        for i in 0..5 {
            let mut r = rec("write", &format!("p{i}.exe"));
            r.at_ms = i;
            append_history(&d, &r).unwrap();
        }
        let all = load_history(&d, 100);
        assert_eq!(all.len(), 5);
        assert_eq!(all[0].process, "p0.exe");
        assert_eq!(all[4].process, "p4.exe");

        let tail = load_history(&d, 2);
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].process, "p3.exe", "the newest records are kept");
        assert_eq!(tail[1].process, "p4.exe");
    }

    #[test]
    fn a_truncated_history_line_does_not_hide_the_rest() {
        let d = dir("truncated");
        append_history(&d, &rec("write", "a.exe")).unwrap();
        // Simulate a crash in the middle of the next write.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(history_path(&d))
            .unwrap();
        f.write_all(b"{\"at_ms\":2,\"action\":\"rem").unwrap();
        drop(f);
        append_history(&d, &rec("remove_all", "b.exe")).unwrap();

        let all = load_history(&d, 100);
        assert_eq!(all.len(), 2, "the damaged line is skipped, not fatal");
        assert_eq!(all[0].action, "write");
        assert_eq!(all[1].action, "remove_all");
    }

    #[test]
    fn labels_cover_the_actions_the_program_writes() {
        for (a, label) in [
            ("write", "写入"),
            ("auto_write", "自动写入"),
            ("remove_process", "移除该进程"),
            ("remove_all", "移除全部"),
            ("remove_entry", "删除条目"),
            ("restore", "恢复备份"),
            ("edit", "编辑保存"),
        ] {
            assert_eq!(rec(a, "").action_label(), label);
        }
        assert_eq!(rec("write", "").detail(), "新增 1");
    }
}
