//! Writing the hosts file, safely and reversibly.
//!
//! This is the one part of the program that modifies a system file, so the
//! rules are strict and each one is tested:
//!
//! * **Nothing outside our own block is ever touched.** The file is handled as
//!   raw bytes; the only region that changes is the one between the markers.
//!   Line endings, encoding, comments and stray whitespace elsewhere survive
//!   byte for byte.
//! * **Every entry is marked**, individually as well as by the block, so a
//!   entry can still be identified and removed if the block markers are lost.
//! * **Every entry names the processes that put it there.** Writing and
//!   removing are per-process operations: writing one process's table adds to
//!   the block and replaces nothing, and removing one process's entries takes
//!   only the lines that process alone asked for. A line two processes share
//!   stays until the second one's entries go too.
//! * **Writes are atomic.** Content goes to a temporary file in the same
//!   directory and then replaces the original in one operation, so a crash
//!   mid-write cannot leave a half-written hosts file behind.
//! * **A backup is taken before every change**, and restoring takes one first
//!   too.
//!
//! The block looks like this:
//!
//! ```text
//! # === NetMonitor managed entries (do not edit inside the markers) ===
//! 2606:4700:10::6814:179a  www.example.com    # nm msedge.exe
//! 127.0.0.1                ads.example.com    # nm msedge.exe,baidunetdisk.exe
//! # === NetMonitor managed entries end ===
//! ```

use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// Line that opens the managed block.
///
/// The two markers must not be prefixes of one another. An earlier version used
/// "...managed entries" and "...managed entries end ===", so the end line also
/// matched the *begin* prefix -- which would mislocate the block in a file where
/// the opening line had been lost.
pub const MARK_BEGIN: &str = "# === NetMonitor managed entries begin ===";
/// Line that closes the managed block.
pub const MARK_END: &str = "# === NetMonitor managed entries end ===";
/// Appended to every entry we write, so a stray line is still identifiable.
pub const ENTRY_TAG: &str = "# nm";

/// The address a domain with no usable IPv6 record is pointed at, when the user
/// chooses to disable it rather than skip it.
pub const BLOCK_ADDRESS: &str = "127.0.0.1";

/// What to do with a domain that has no usable IPv6 address.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum NoAaaaPolicy {
    /// Skip it: leave the name resolving however it did before.
    Skip,
    /// Point it at the loopback address, which effectively disables it over
    /// IPv4 and IPv6 alike. This is the default: for a name with no IPv6, the
    /// point of writing it at all is usually to get it out of the way.
    #[default]
    Block,
}

impl NoAaaaPolicy {
    pub fn label(self) -> &'static str {
        match self {
            NoAaaaPolicy::Skip => "不写入（保持原解析）",
            NoAaaaPolicy::Block => "指向 127.0.0.1（禁用该域名）",
        }
    }

    /// The other policy. Kept for callers that toggle a setting in place.
    #[allow(dead_code)]
    pub fn toggled(self) -> Self {
        match self {
            NoAaaaPolicy::Skip => NoAaaaPolicy::Block,
            NoAaaaPolicy::Block => NoAaaaPolicy::Skip,
        }
    }
}

/// One line we intend to write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedEntry {
    pub address: String,
    pub domain: String,
    /// Why this line is what it is, for the preview.
    pub reason: PlanReason,
    /// The address comes from the previous session's cached table rather than
    /// a lookup made now. Shown next to the row, never hidden: re-writing such
    /// a row writes an answer that may be days old.
    pub previous_session: bool,
    /// The address already in the block for this domain was probed and did not
    /// answer, so this row may replace it even though an address is present.
    /// Only a write sets this; a preview without probing leaves it false.
    pub replace_existing: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PlanReason {
    /// A usable IPv6 address was found.
    Ipv6,
    /// No usable IPv6; pointed at the loopback address by policy.
    BlockedNoIpv6,
    /// No usable IPv6; left alone by policy.
    SkippedNoIpv6,
}

impl PlanReason {
    pub fn short(self) -> &'static str {
        match self {
            PlanReason::Ipv6 => "IPv6",
            PlanReason::BlockedNoIpv6 => "无 IPv6 → 127.0.0.1",
            PlanReason::SkippedNoIpv6 => "无 IPv6 → 跳过",
        }
    }
}

/// Pick the best address to put in a hosts file.
///
/// "Best" here means "most likely to work", ranked by scope, because a hosts
/// file has no way to express a scope id or a fallback:
///
/// 1. **Global unicast** (`2000::/3`) -- routable, which is the whole point.
/// 2. **Unique local** (`fc00::/7`) -- not globally routable but perfectly
///    valid on a private network, and better than nothing.
/// 3. **Loopback and anything else** -- an answer is an answer.
///
/// Link-local (`fe80::/10`), the unspecified address and IPv4-mapped addresses
/// are rejected outright: a link-local address in a hosts file cannot be used
/// without a scope id, so writing one would break the name rather than help it.
///
/// Ties are broken by the order the resolver returned, which reflects the
/// server's own preference (and, for CDNs, usually proximity). Measuring
/// latency would be better and is not done -- see the manual's limitations.
pub fn best_ipv6(addrs: &[Ipv6Addr]) -> Option<Ipv6Addr> {
    fn rank(a: &Ipv6Addr) -> Option<u8> {
        let o = a.octets();
        if a.is_unspecified() || a.is_unicast_link_local() {
            return None;
        }
        // ::ffff:0:0/96 -- an IPv4 address wearing an IPv6 hat.
        if o[..10].iter().all(|b| *b == 0) && o[10] == 0xff && o[11] == 0xff {
            return None;
        }
        if o[0] & 0xe0 == 0x20 {
            Some(3) // 2000::/3 global unicast
        } else if o[0] & 0xfe == 0xfc {
            Some(2) // fc00::/7 unique local
        } else {
            Some(1)
        }
    }
    // Kept as an explicit scan: `max_by_key` returns the *last* maximum, which
    // would silently prefer the end of the resolver's list on a tie.
    let mut best: Option<(u8, Ipv6Addr)> = None;
    for a in addrs {
        let Some(r) = rank(a) else { continue };
        if best.map(|(br, _)| r > br).unwrap_or(true) {
            best = Some((r, *a));
        }
    }
    best.map(|(_, a)| a)
}

/// Build the lines to write for one process's domain table.
///
/// `rows` is `(domain, addresses)`; the address list comes from the AAAA
/// lookups already recorded in the domain table.
pub fn plan<'a, I>(rows: I, policy: NoAaaaPolicy) -> Vec<PlannedEntry>
where
    I: IntoIterator<Item = (&'a str, &'a [Ipv6Addr])>,
{
    let mut out = Vec::new();
    for (domain, addrs) in rows {
        if domain.is_empty() || domain.contains(char::is_whitespace) {
            // A name with whitespace in it cannot be written to a hosts file at
            // all; silently dropping it is better than producing a broken line.
            continue;
        }
        match best_ipv6(addrs) {
            Some(addr) => out.push(PlannedEntry {
                address: addr.to_string(),
                domain: domain.to_string(),
                reason: PlanReason::Ipv6,
                previous_session: false,
                replace_existing: false,
            }),
            None => match policy {
                NoAaaaPolicy::Skip => out.push(PlannedEntry {
                    address: String::new(),
                    domain: domain.to_string(),
                    reason: PlanReason::SkippedNoIpv6,
                    previous_session: false,
                    replace_existing: false,
                }),
                NoAaaaPolicy::Block => out.push(PlannedEntry {
                    address: BLOCK_ADDRESS.to_string(),
                    domain: domain.to_string(),
                    reason: PlanReason::BlockedNoIpv6,
                    previous_session: false,
                    replace_existing: false,
                }),
            },
        }
    }
    out.sort_by(|a, b| a.domain.cmp(&b.domain));
    out.dedup_by(|a, b| a.domain == b.domain);
    out
}

/// Whether a domain is already in the hosts file, and how it got there.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WrittenState {
    /// Not in the file at all.
    Absent,
    /// In our block, with the address we would write, recorded against this
    /// process.
    Same,
    /// In our block with the address we would write, but recorded against some
    /// other process -- it got there first, or asks for the same name.
    OtherOwner,
    /// In our block, with no process recorded: a line an older version of this
    /// program wrote, before entries carried an owner.
    Unrecorded,
    /// In our block pointing at the loopback block address, while a usable IPv6
    /// address is now available.
    Upgrade,
    /// In our block, pointing somewhere else. Left alone unless a probe found
    /// that the address no longer answers.
    OtherAddress,
    /// In our block with a different address, and that address failed the
    /// usability probe made just before this write.
    StaleAddress,
    /// In the file, but outside our block -- the user put it there.
    OutsideOurBlock,
}

impl WrittenState {
    /// Short label for the preview.
    pub fn label(self) -> &'static str {
        match self {
            WrittenState::Absent => "未写入",
            WrittenState::Same => "已写入",
            WrittenState::OtherOwner => "已写入(其它进程)",
            WrittenState::Unrecorded => "已写入(未记录进程)",
            WrittenState::Upgrade => "已写入(127.0.0.1)",
            WrittenState::OtherAddress => "已写入(地址不同)",
            WrittenState::StaleAddress => "已写入(地址失效)",
            WrittenState::OutsideOurBlock => "文件里已有(非本程序)",
        }
    }
}

/// What a write would do with one row.
///
/// Derived from the same decision the write itself uses, so the preview cannot
/// promise something the write does not do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RowAction {
    /// Add a line to the block.
    Append,
    /// Put the IPv6 address we now have in place of the loopback block address.
    Update,
    /// Replace an address that failed the usability probe with the fresh one.
    Replace,
    /// Leave the address alone and record this process on the line, so removing
    /// this process's entries later knows the line is shared with another one.
    Claim,
    /// Already exactly what we would write.
    Keep,
    /// Not written at all: policy skip, or the user's own line already covers
    /// the name and a second copy behind it would never be reached.
    Skip,
}

impl RowAction {
    pub fn label(self) -> &'static str {
        match self {
            RowAction::Append => "追加",
            RowAction::Update => "更新为 IPv6",
            RowAction::Replace => "替换失效地址",
            RowAction::Claim => "登记本进程",
            RowAction::Keep => "不动",
            RowAction::Skip => "跳过",
        }
    }

    /// Does this row leave the file different from what is on disk?
    pub fn changes_file(self) -> bool {
        matches!(
            self,
            RowAction::Append | RowAction::Update | RowAction::Replace | RowAction::Claim
        )
    }
}

/// One previewed row: what the file holds now, and what a write would do.
#[derive(Clone, Copy, Debug)]
pub struct RowPlan {
    pub state: WrittenState,
    pub action: RowAction,
}

impl RowPlan {
    fn new(state: WrittenState, action: RowAction) -> Self {
        Self { state, action }
    }
}

/// A line inside the managed block.
///
/// `owners` is what makes writes and removals per-process: it names the
/// processes whose domain tables asked for the line. A line written by an older
/// version, or edited in by hand, has no owners at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockEntry {
    pub address: String,
    pub domain: String,
    pub owners: Vec<String>,
    /// The line as it sits in the file, kept so a line nobody is changing is
    /// re-emitted byte for byte. Cleared when the line changes.
    raw: Option<String>,
}

impl BlockEntry {
    fn new(address: String, domain: String, owners: Vec<String>) -> Self {
        Self {
            address,
            domain,
            owners,
            raw: None,
        }
    }

    pub fn is_owned_by(&self, process: &str) -> bool {
        self.owners.iter().any(|o| o.eq_ignore_ascii_case(process))
    }

    /// Record `process` as also relying on this line.
    fn claim(&mut self, process: &str) {
        if !self.is_owned_by(process) {
            self.owners.push(process.to_string());
            self.raw = None;
        }
    }

    fn tag(&self) -> String {
        if self.owners.is_empty() {
            ENTRY_TAG.to_string()
        } else {
            format!("{ENTRY_TAG} {}", self.owners.join(","))
        }
    }

    /// The line to write: the original bytes when nothing changed, a freshly
    /// formatted line otherwise.
    fn text(&self) -> String {
        match &self.raw {
            Some(r) => r.clone(),
            None => format!("{:<39} {:<40} {}", self.address, self.domain, self.tag())
                .trim_end()
                .to_string(),
        }
    }

    /// The line as it currently reads in the file, for the viewer and for
    /// "copy this line".
    pub fn line(&self) -> String {
        self.text()
    }
}

/// What folding one process's plan into the block did.
#[derive(Clone, Debug, Default)]
pub struct Merge {
    /// The file as it should be. Equal to the current content when `changed` is
    /// false.
    pub bytes: Vec<u8>,
    pub appended: usize,
    pub upgraded: usize,
    /// Lines whose previous address failed the usability probe.
    pub replaced: usize,
    pub claimed: usize,
    /// Rows already exactly right, left untouched.
    pub kept: usize,
    /// Rows not written at all.
    pub skipped: usize,
    pub changed: bool,
}

/// What taking one process's name off the block did.
#[derive(Clone, Debug, Default)]
pub struct Removal {
    pub bytes: Vec<u8>,
    /// Lines that were only this process's, and are gone.
    pub removed: usize,
    /// Lines shared with another process: kept, with this one unrecorded.
    pub shared: usize,
    pub changed: bool,
}

/// How long the plan must stop changing before an automatic write happens.
///
/// A browser resolves names in bursts of dozens within a few hundred
/// milliseconds. Writing on every individual change would mean dozens of
/// rewrites -- and dozens of backups -- for one page load.
pub const AUTO_DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(1500);

/// How many backups a manual cleanup keeps.
///
/// Nothing prunes automatically: deleting a user's files behind their back is
/// not this program's call, and a backup taken during an incident is exactly
/// the one an automatic rule would throw away first. The count is surfaced in
/// the UI so the accumulation is visible, and cleanup is an explicit action.
#[allow(dead_code)] // the GUI shows this default; kept as the single source of it
pub const BACKUPS_TO_KEEP: usize = 50;

/// The hosts file as it exists on disk, kept as bytes.
pub struct HostsFile {
    pub path: PathBuf,
    raw: Vec<u8>,
    line_ending: Vec<u8>,
}

impl HostsFile {
    pub fn default_path() -> PathBuf {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        Path::new(&root)
            .join("System32")
            .join("drivers")
            .join("etc")
            .join("hosts")
    }

    /// Read the file. A missing file is treated as empty rather than as an
    /// error: that is a legitimate state, and refusing to proceed would be
    /// unhelpful.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let raw = match std::fs::read(path) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        let line_ending = if raw.windows(2).any(|w| w == b"\r\n") {
            b"\r\n".to_vec()
        } else {
            b"\n".to_vec()
        };
        let had_trailing_newline = raw.ends_with(b"\n");
        let _ = had_trailing_newline;
        Ok(Self {
            path: path.to_path_buf(),
            raw,
            line_ending,
        })
    }

    pub fn contents(&self) -> String {
        String::from_utf8_lossy(&self.raw).into_owned()
    }

    /// The file's exact bytes. Used by the tests that assert nothing outside
    /// the managed block changes.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Byte range of the managed block, inclusive of its markers and their
    /// trailing line endings.
    pub fn managed_block(&self) -> Option<(usize, usize)> {
        let text = String::from_utf8_lossy(&self.raw);
        let begin = text.find(MARK_BEGIN)?;
        // Start of that line, not of the marker itself.
        let start = text[..begin].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let end_at = text[begin..].find(MARK_END)? + begin;
        let end_line = text[end_at..]
            .find('\n')
            .map(|i| end_at + i + 1)
            .unwrap_or(text.len());
        Some((start, end_line))
    }

    pub fn has_managed_block(&self) -> bool {
        self.managed_block().is_some()
    }

    /// Entries inside the managed block, as `(address, name)`.
    pub fn managed_entries(&self) -> Vec<(String, String)> {
        self.block_entries()
            .into_iter()
            .map(|e| (e.address, e.domain))
            .collect()
    }

    /// The lines of our block, in file order, with the processes that own them.
    pub fn block_entries(&self) -> Vec<BlockEntry> {
        let mut out = Vec::new();
        let Some((s, e)) = self.managed_block() else {
            return out;
        };
        let block = String::from_utf8_lossy(&self.raw[s..e]).into_owned();
        for line in block.lines() {
            let Some((address, domain)) = parse_host_line(line) else {
                continue;
            };
            out.push(BlockEntry {
                address,
                domain,
                owners: parse_owners(line),
                // `str::lines` has already dropped the line ending, so this is
                // the line's text exactly as written.
                raw: Some(line.to_string()),
            });
        }
        out
    }

    /// How many entries each process has in the block, most first.
    ///
    /// A line two processes asked for counts for both of them -- it is a line
    /// each of them relies on, and counting it once would hide it from the
    /// other. The totals therefore need not add up to the number of lines.
    /// Entries written before ownership was recorded have no name to report and
    /// are counted under an empty string.
    pub fn owners_summary(&self) -> Vec<(String, usize)> {
        let mut counts: Vec<(String, usize)> = Vec::new();
        for e in self.block_entries() {
            let names: Vec<&str> = if e.owners.is_empty() {
                vec![""]
            } else {
                e.owners.iter().map(|o| o.as_str()).collect()
            };
            for name in names {
                match counts.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
                    Some(slot) => slot.1 += 1,
                    // The wording of the first entry seen is the one reported.
                    None => counts.push((name.to_string(), 1)),
                }
            }
        }
        counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        counts
    }

    /// Every entry in the file, marked or not.
    pub fn all_entries(&self) -> Vec<(String, String)> {
        String::from_utf8_lossy(&self.raw)
            .lines()
            .filter_map(parse_host_line)
            .collect()
    }

    /// The whole file with our block rebuilt from `entries`.
    ///
    /// Every byte outside the block is copied through untouched, and inside it
    /// every line that is not being changed is re-emitted from its original
    /// text rather than reformatted.
    fn render_block(&self, entries: &[BlockEntry]) -> Vec<u8> {
        let mut block: Vec<u8> = Vec::new();
        let line = |block: &mut Vec<u8>, text: &str| {
            block.extend_from_slice(text.as_bytes());
            block.extend_from_slice(&self.line_ending);
        };

        line(
            &mut block,
            &format!("{MARK_BEGIN} (do not edit inside the markers) ==="),
        );
        if entries.is_empty() {
            line(&mut block, "# (no entries)");
        }
        for e in entries {
            line(&mut block, &e.text());
        }
        line(&mut block, MARK_END);

        match self.managed_block() {
            Some((s, e)) => {
                let mut out = Vec::with_capacity(self.raw.len() + block.len());
                out.extend_from_slice(&self.raw[..s]);
                out.extend_from_slice(&block);
                out.extend_from_slice(&self.raw[e..]);
                out
            }
            None => {
                let mut out = self.raw.clone();
                if !out.is_empty() {
                    if !out.ends_with(b"\n") {
                        out.extend_from_slice(&self.line_ending);
                    }
                    // One blank line between whatever was there and our block.
                    out.extend_from_slice(&self.line_ending);
                }
                out.extend_from_slice(&block);
                out
            }
        }
    }

    /// The file with our block removed and nothing else changed.
    ///
    /// When the block sits at the end of the file, the blank separator line
    /// that `render_with` inserted ahead of it goes too -- otherwise removing
    /// would leave a stray empty line behind.
    pub fn render_without(&self) -> Vec<u8> {
        let Some((s, e)) = self.managed_block() else {
            return self.raw.clone();
        };
        let tail = &self.raw[e..];
        let mut out = Vec::with_capacity(self.raw.len());
        out.extend_from_slice(&self.raw[..s]);
        out.extend_from_slice(tail);
        if tail.is_empty() {
            let le = self.line_ending.clone();
            if out.ends_with(&le)
                && out.len() >= le.len() * 2
                && out[..out.len() - le.len()].ends_with(&le)
            {
                out.truncate(out.len() - le.len());
            }
        }
        out
    }

    /// Replace the file's contents, atomically, keeping a backup first.
    pub fn write(&self, bytes: &[u8], backup_dir: &Path) -> anyhow::Result<PathBuf> {
        let backup = if self.path.exists() {
            let b = backup(&self.path, backup_dir)?;
            Some(b)
        } else {
            None
        };
        write_atomic(&self.path, bytes)?;
        Ok(backup.unwrap_or_default())
    }
}

/// Work out, for each planned row, what the file holds and what a write would do.
///
/// `managed` is our own block, with its owners; `all` is every entry in the
/// file, so a line the user maintains by hand is reported as theirs rather than
/// as something we could overwrite. `process` is the one asking, which is what
/// makes an entry someone else's rather than ours.
///
/// This is the single place the decision is made: the preview shows it and
/// [`merge`] applies it, so the two cannot disagree.
pub fn classify(
    plan: &[PlannedEntry],
    managed: &[BlockEntry],
    all: &[(String, String)],
    process: &str,
) -> Vec<RowPlan> {
    plan.iter()
        .map(|e| {
            if e.reason == PlanReason::SkippedNoIpv6 {
                // The policy says this name is not written at all.
                return RowPlan::new(WrittenState::Absent, RowAction::Skip);
            }
            if let Some(b) = managed
                .iter()
                .find(|b| b.domain.eq_ignore_ascii_case(&e.domain))
            {
                if b.address.eq_ignore_ascii_case(&e.address) {
                    return if b.is_owned_by(process) {
                        RowPlan::new(WrittenState::Same, RowAction::Keep)
                    } else if b.owners.is_empty() {
                        // Written before entries recorded who asked for them.
                        RowPlan::new(WrittenState::Unrecorded, RowAction::Claim)
                    } else {
                        RowPlan::new(WrittenState::OtherOwner, RowAction::Claim)
                    };
                }
                // One direction is corrected, and only one: a name blocked for
                // want of an IPv6 answer starts working as soon as there is one.
                if b.address == BLOCK_ADDRESS && e.address != BLOCK_ADDRESS {
                    return RowPlan::new(WrittenState::Upgrade, RowAction::Update);
                }
                if e.replace_existing
                    && !e.address.is_empty()
                    && !e.address.eq_ignore_ascii_case(BLOCK_ADDRESS)
                {
                    return RowPlan::new(WrittenState::StaleAddress, RowAction::Replace);
                }
                return RowPlan::new(WrittenState::OtherAddress, RowAction::Keep);
            }
            if all.iter().any(|(_, n)| n.eq_ignore_ascii_case(&e.domain)) {
                // The user's own line, ahead of ours, already decides where this
                // name goes; a second copy behind it would never be reached.
                return RowPlan::new(WrittenState::OutsideOurBlock, RowAction::Skip);
            }
            RowPlan::new(WrittenState::Absent, RowAction::Append)
        })
        .collect()
}

/// Fold one process's plan into the managed block.
///
/// This is the only way entries get into the file, and it never takes one out:
/// a write adds what is missing and, where a name was blocked for want of an
/// IPv6 answer and now has one, replaces the block address. Everything already
/// written -- by this process, by another one, or by hand -- keeps its address
/// and its bytes. Lines that nothing changes come back out exactly as they went
/// in.
///
/// The result is compared with the file rather than with remembered state, so a
/// file edited by hand is noticed instead of being overwritten on a stale
/// assumption.
pub fn merge(file: &HostsFile, process: &str, plan: &[PlannedEntry]) -> Merge {
    let mut entries = file.block_entries();
    let rows = classify(plan, &entries, &file.all_entries(), process);
    let mut out = Merge {
        bytes: file.raw.clone(),
        ..Default::default()
    };
    for (p, row) in plan.iter().zip(&rows) {
        let at = entries
            .iter()
            .position(|b| b.domain.eq_ignore_ascii_case(&p.domain));
        match row.action {
            RowAction::Append => {
                entries.push(BlockEntry::new(
                    p.address.clone(),
                    p.domain.clone(),
                    vec![process.to_string()],
                ));
                out.appended += 1;
            }
            RowAction::Update => {
                if let Some(e) = at.map(|i| &mut entries[i]) {
                    e.address = p.address.clone();
                    e.raw = None;
                    e.claim(process);
                    out.upgraded += 1;
                }
            }
            RowAction::Replace => {
                if let Some(e) = at.map(|i| &mut entries[i]) {
                    e.address = p.address.clone();
                    e.raw = None;
                    e.claim(process);
                    out.replaced += 1;
                }
            }
            RowAction::Claim => {
                if let Some(e) = at.map(|i| &mut entries[i]) {
                    e.claim(process);
                    out.claimed += 1;
                }
            }
            RowAction::Keep => out.kept += 1,
            RowAction::Skip => out.skipped += 1,
        }
    }
    out.changed = out.appended + out.upgraded + out.replaced + out.claimed > 0;
    if out.changed {
        out.bytes = file.render_block(&entries);
    }
    out
}

/// Fold several processes' plans into the block in one pass.
///
/// This exists for the case where two processes resolved the same name: their
/// rows are merged beforehand into one row with both owners, and this writes
/// that row once, with one backup. Calling [`merge`] twice would produce the
/// same lines but two rewrites of the file -- and, in automatic mode, two
/// debounce cycles for one page load.
///
/// An address already in the block is never replaced by a different *working*
/// address, exactly as in [`merge`]. The two corrections are the block address
/// becoming a real IPv6 one, and an address the caller's probe marked dead.
pub fn merge_owned(file: &HostsFile, rows: &[(Vec<String>, PlannedEntry)]) -> Merge {
    let mut entries = file.block_entries();
    let all = file.all_entries();
    let mut out = Merge {
        bytes: file.raw.clone(),
        ..Default::default()
    };
    for (owners, p) in rows {
        if p.reason == PlanReason::SkippedNoIpv6 {
            out.skipped += 1;
            continue;
        }
        match entries
            .iter()
            .position(|b| b.domain.eq_ignore_ascii_case(&p.domain))
        {
            None => {
                if all.iter().any(|(_, n)| n.eq_ignore_ascii_case(&p.domain)) {
                    // The user's own line already decides this name.
                    out.skipped += 1;
                } else {
                    entries.push(BlockEntry::new(
                        p.address.clone(),
                        p.domain.clone(),
                        owners.clone(),
                    ));
                    out.appended += 1;
                }
            }
            Some(i) => {
                let e = &mut entries[i];
                if e.address.eq_ignore_ascii_case(&p.address) {
                    let mut claimed = false;
                    for owner in owners {
                        if !e.is_owned_by(owner) {
                            e.claim(owner);
                            claimed = true;
                        }
                    }
                    if claimed {
                        out.claimed += 1;
                    } else {
                        out.kept += 1;
                    }
                } else if e.address == BLOCK_ADDRESS && p.address != BLOCK_ADDRESS {
                    e.address = p.address.clone();
                    e.raw = None;
                    for owner in owners {
                        e.claim(owner);
                    }
                    out.upgraded += 1;
                } else if p.replace_existing
                    && !p.address.is_empty()
                    && !p.address.eq_ignore_ascii_case(BLOCK_ADDRESS)
                {
                    e.address = p.address.clone();
                    e.raw = None;
                    for owner in owners {
                        e.claim(owner);
                    }
                    out.replaced += 1;
                } else {
                    // A working address already in the block is never replaced
                    // by a different one unless the caller probed it and found
                    // it dead. Both processes still rely on the name, so both
                    // are recorded as owners.
                    let mut claimed = false;
                    for owner in owners {
                        if !e.is_owned_by(owner) {
                            e.claim(owner);
                            claimed = true;
                        }
                    }
                    if claimed {
                        out.claimed += 1;
                    } else {
                        out.kept += 1;
                    }
                }
            }
        }
    }
    out.changed = out.appended + out.upgraded + out.replaced + out.claimed > 0;
    if out.changed {
        out.bytes = file.render_block(&entries);
    }
    out
}

/// Take one process's name off the entries it put there.
///
/// A line that only this process asked for goes away. A line it shares with
/// another process stays, with the other process's name still on it -- which is
/// the point of recording owners at all: removing one process's entries must
/// not take a name another process is still relying on. Nothing outside the
/// block is touched, and a process that has claimed nothing changes nothing.
pub fn unclaim(file: &HostsFile, process: &str) -> Removal {
    let entries = file.block_entries();
    let mut out = Removal {
        bytes: file.raw.clone(),
        ..Default::default()
    };
    if entries.is_empty() {
        return out;
    }
    let mut kept: Vec<BlockEntry> = Vec::new();
    for mut e in entries {
        if !e.is_owned_by(process) {
            kept.push(e);
            continue;
        }
        e.owners.retain(|o| !o.eq_ignore_ascii_case(process));
        if e.owners.is_empty() {
            out.removed += 1;
        } else {
            // Still someone else's line: re-emit it without our name.
            e.raw = None;
            out.shared += 1;
            kept.push(e);
        }
    }
    out.changed = out.removed + out.shared > 0;
    if out.changed {
        out.bytes = if kept.is_empty() {
            // Nothing of ours left at all: the empty markers go too.
            file.render_without()
        } else {
            file.render_block(&kept)
        };
    }
    out
}

/// Remove one specific line from the managed block.
///
/// This is the "delete this row" action in the current-entries window, and it
/// is deliberately the blunt one: the line goes, whoever else may have been
/// relying on it. Selecting a single line is an explicit instruction about that
/// line, and leaving a half-claimed line behind would not be what the user
/// pointed at. Per-process removal (`unclaim`) remains the way to take one
/// process's names off shared lines.
///
/// Matching is by domain and address, both case-insensitive, because that is
/// what the row displays. Removing the last line takes the empty markers with
/// it, exactly as `unclaim` does.
pub fn remove_entry(file: &HostsFile, domain: &str, address: &str) -> Removal {
    let entries = file.block_entries();
    let mut out = Removal {
        bytes: file.raw.clone(),
        ..Default::default()
    };
    if entries.is_empty() {
        return out;
    }
    let mut kept: Vec<BlockEntry> = Vec::with_capacity(entries.len());
    for e in entries {
        if e.domain.eq_ignore_ascii_case(domain) && e.address.eq_ignore_ascii_case(address) {
            out.removed += 1;
        } else {
            kept.push(e);
        }
    }
    out.changed = out.removed > 0;
    if out.changed {
        out.bytes = if kept.is_empty() {
            file.render_without()
        } else {
            file.render_block(&kept)
        };
    }
    out
}

/// Keep only the newest `keep` backups.
///
/// Returns how many were removed.
pub fn prune_backups(dir: &Path, keep: usize) -> usize {
    let mut removed = 0;
    for old in list_backups(dir).into_iter().skip(keep) {
        if std::fs::remove_file(&old).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// The processes recorded on an entry's tag, in the order they claimed it.
///
/// The tag is the last comment on the line: `# nm` by itself on a line an older
/// version wrote, `# nm msedge.exe,baidunetdisk.exe` once owners are recorded.
/// Anything after a second `#` is a hand-written note and is not read as part
/// of a process name.
fn parse_owners(line: &str) -> Vec<String> {
    let Some((_, comment)) = line.split_once('#') else {
        return Vec::new();
    };
    let comment = comment.split('#').next().unwrap_or("").trim();
    let Some(rest) = comment.strip_prefix("nm") else {
        return Vec::new();
    };
    // `# nm` or `# nm <names>`; `# nmfoo` is not our tag.
    if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
        return Vec::new();
    }
    rest.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Parse `address name [more names] [# comment]` into `(address, first name)`.
///
/// A hosts line may list several names for one address; the first is what we
/// report, since that is the one we would have written.
fn parse_host_line(line: &str) -> Option<(String, String)> {
    let code = line.split('#').next().unwrap_or("").trim();
    if code.is_empty() {
        return None;
    }
    let mut parts = code.split_whitespace();
    let addr = parts.next()?;
    let name = parts.next()?;
    if addr.parse::<IpAddr>().is_err() {
        return None;
    }
    Some((addr.to_string(), name.to_string()))
}

/// Write `bytes` to `path` via a temporary file in the same directory.
///
/// `ReplaceFileW` is used rather than a plain overwrite because it keeps the
/// destination's security descriptor and attributes: the hosts file has
/// restrictions that a freshly created file would not inherit, and quietly
/// loosening them would be a security problem, not a cosmetic one.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).ok();
    let tmp = dir.join(format!(
        ".netmon-hosts-{}-{}.tmp",
        std::process::id(),
        crate::util::now_unix_ms()
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }

    if !path.exists() {
        return std::fs::rename(&tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e
        });
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn ReplaceFileW(
                replaced: *const u16,
                replacement: *const u16,
                backup: *const u16,
                flags: u32,
                exclude: *mut core::ffi::c_void,
                reserved: *mut core::ffi::c_void,
            ) -> i32;
        }
        let wide = |p: &Path| -> Vec<u16> {
            p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
        };
        let target = wide(path);
        let source = wide(&tmp);
        let ok = unsafe {
            ReplaceFileW(
                target.as_ptr(),
                source.as_ptr(),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok != 0 {
            return Ok(());
        }
        // Fall through to a plain move if ReplaceFile declined (for example on
        // a filesystem that does not support it).
        let err = std::io::Error::last_os_error();
        if std::fs::rename(&tmp, path).is_ok() {
            return Ok(());
        }
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(&tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e
        })
    }
}

// ---------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------

/// Copy the hosts file to `dir` under a timestamped name.
pub fn backup(hosts: &Path, dir: &Path) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S%.3f");
    let name = format!("hosts-{stamp}.bak");
    let dest = dir.join(name.replace('.', "_").replacen("_bak", ".bak", 1));
    std::fs::copy(hosts, &dest)?;
    Ok(dest)
}

/// All backups in `dir`, newest first.
pub fn list_backups(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("hosts-") && n.ends_with(".bak"))
                .unwrap_or(false)
        })
        .collect();
    v.sort();
    v.reverse();
    v
}

/// Put a backup back.
///
/// The current file is backed up first, so a restore can itself be undone --
/// restoring the wrong snapshot should never be the last word.
pub fn restore(backup_path: &Path, hosts: &Path, dir: &Path) -> anyhow::Result<PathBuf> {
    if !backup_path.is_file() {
        anyhow::bail!("backup not found: {}", backup_path.display());
    }
    let safety = if hosts.exists() {
        Some(backup(hosts, dir)?)
    } else {
        None
    };
    let bytes = std::fs::read(backup_path)?;
    write_atomic(hosts, &bytes)?;
    Ok(safety.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn best_address_prefers_global_unicast() {
        // Order in the answer must not matter: the highest scope wins.
        let a = vec![
            ip("fe80::1"),
            ip("fc00::1"),
            ip("2606:4700::1"),
            ip("::1"),
        ];
        assert_eq!(best_ipv6(&a), Some(ip("2606:4700::1")));
    }

    #[test]
    fn best_address_falls_back_in_scope_order() {
        assert_eq!(
            best_ipv6(&[ip("fe80::1"), ip("fd12::5")]),
            Some(ip("fd12::5")),
            "unique local beats link-local"
        );
        assert_eq!(
            best_ipv6(&[ip("fe80::1"), ip("::1")]),
            Some(ip("::1"))
        );
    }

    #[test]
    fn unusable_addresses_are_rejected() {
        assert_eq!(best_ipv6(&[]), None);
        assert_eq!(best_ipv6(&[ip("fe80::abcd")]), None, "link-local needs a scope id");
        assert_eq!(best_ipv6(&[ip("::")]), None, "unspecified");
        assert_eq!(
            best_ipv6(&[ip("::ffff:192.168.0.1")]),
            None,
            "IPv4-mapped is not really IPv6"
        );
    }

    #[test]
    fn ties_keep_the_resolver_order() {
        let a = vec![ip("2606:4700::1"), ip("2606:4700::2")];
        assert_eq!(best_ipv6(&a), Some(ip("2606:4700::1")));
    }

    #[test]
    fn plan_applies_the_policy_to_names_without_ipv6() {
        let hosts = vec![ip("2606:4700::5")];
        let rows: Vec<(&str, &[Ipv6Addr])> = vec![
            ("has.example.com", &hosts),
            ("none.example.com", &[]),
        ];

        let blocked = plan(rows.iter().copied(), NoAaaaPolicy::Block);
        assert_eq!(blocked.len(), 2);
        assert_eq!(blocked[0].domain, "has.example.com");
        assert_eq!(blocked[0].address, "2606:4700::5");
        assert_eq!(blocked[1].domain, "none.example.com");
        assert_eq!(blocked[1].address, "127.0.0.1");
        assert_eq!(blocked[1].reason, PlanReason::BlockedNoIpv6);

        let skipped = plan(rows.iter().copied(), NoAaaaPolicy::Skip);
        assert_eq!(skipped[1].reason, PlanReason::SkippedNoIpv6);
    }

    #[test]
    fn default_policy_blocks() {
        // Stated as a test because it is a product decision, not an accident.
        assert_eq!(NoAaaaPolicy::default(), NoAaaaPolicy::Block);
    }

    #[test]
    fn plan_skips_unwritable_names() {
        let rows: Vec<(&str, &[Ipv6Addr])> = vec![("", &[]), ("has space.com", &[])];
        assert!(plan(rows.iter().copied(), NoAaaaPolicy::Block).is_empty());
    }

    fn write_temp(name: &str, content: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("netmon-hosts-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    const SAMPLE: &str = "# Copyright (c) 1993-2009 Microsoft Corp.\r\n\
                          #\r\n\
                          # This is a sample HOSTS file.\r\n\
                          \r\n\
                          127.0.0.1       localhost\r\n\
                          ::1             localhost\r\n";

    /// Re-read the file from rendered bytes, the way the next run of the
    /// program would.
    fn reload(path: &Path, bytes: Vec<u8>) -> HostsFile {
        let mut f = HostsFile::load(path).unwrap();
        f.raw = bytes;
        f
    }

    /// One planned row: a domain with the IPv6 address we would write for it.
    fn entry(address: &str, domain: &str) -> PlannedEntry {
        PlannedEntry {
            address: address.into(),
            domain: domain.into(),
            reason: PlanReason::Ipv6,
            previous_session: false,
            replace_existing: false,
        }
    }

    fn one(domain: &str, address: &str) -> Vec<PlannedEntry> {
        vec![entry(address, domain)]
    }

    /// Write one process's plan and hand back the file the next run would read.
    fn merged(path: &Path, f: &HostsFile, process: &str, plan: &[PlannedEntry]) -> HostsFile {
        reload(path, merge(f, process, plan).bytes)
    }

    /// A block entry, as if it were already in the file.
    fn be(address: &str, domain: &str, owners: &[&str]) -> BlockEntry {
        BlockEntry::new(
            address.to_string(),
            domain.to_string(),
            owners.iter().map(|o| o.to_string()).collect(),
        )
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn writing_leaves_every_other_byte_alone() {
        let p = write_temp("keep.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let out = String::from_utf8(merge(&f, "edge.exe", &one("example.com", "2606:4700::1")).bytes)
            .unwrap();
        for line in SAMPLE.lines() {
            assert!(out.contains(line), "original line lost: {line:?}");
        }
        assert!(out.contains("2606:4700::1"));
        assert!(out.contains(ENTRY_TAG));
        assert!(out.contains("edge.exe"), "the entry must say who asked for it");
        assert!(out.contains(MARK_BEGIN));
        assert!(out.contains(MARK_END));
    }

    #[test]
    fn write_then_remove_restores_the_file_exactly() {
        let p = write_temp("roundtrip.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let rows = plan(
            [("a.example.com", &[ip("2606:4700::1")][..])].iter().copied(),
            NoAaaaPolicy::Block,
        );
        let written = merged(&p, &f, "a.exe", &rows);
        assert!(written.has_managed_block());

        let taken = unclaim(&written, "a.exe");
        assert!(taken.changed && taken.removed == 1);
        assert_eq!(
            taken.bytes,
            SAMPLE.as_bytes(),
            "removing the last entry must give back the original bytes exactly"
        );
        // And the same through the wholesale removal.
        assert_eq!(written.render_without(), SAMPLE.as_bytes());
    }

    #[test]
    fn remove_is_a_no_op_when_there_is_no_block() {
        let p = write_temp("noblock.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        assert!(!f.has_managed_block());
        assert_eq!(f.render_without(), SAMPLE.as_bytes());
    }

    #[test]
    fn a_file_without_a_trailing_newline_still_round_trips() {
        // No trailing newline: one is added ahead of the block, and removing
        // the block takes the blank separator with it.
        let src = "# header\r\n127.0.0.1 localhost";
        let p = write_temp("notrail.hosts", src);
        let f = HostsFile::load(&p).unwrap();
        let rows = plan(
            [("a.test", &[ip("2606:4700::1")][..])].iter().copied(),
            NoAaaaPolicy::Block,
        );
        let written = reload(&p, merge(&f, "a.exe", &rows).bytes);
        let after = unclaim(&written, "a.exe").bytes;
        assert_eq!(
            after,
            b"# header\r\n127.0.0.1 localhost\r\n".to_vec(),
            "the original text survives; a trailing newline is the one addition"
        );
    }

    #[test]
    fn a_second_process_appends_without_disturbing_the_first() {
        let p = write_temp("idem.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let first = merged(&p, &f, "a.exe", &one("one.example.com", "2606:4700::1"));
        let first_line = first.block_entries()[0].clone();

        let second = merged(&p, &first, "b.exe", &one("two.example.com", "2606:4700::2"));
        let entries = second.block_entries();
        assert_eq!(
            entries.len(),
            2,
            "the second write must add to the first, not replace it"
        );
        assert_eq!(entries[0].text(), first_line.text(), "the first line is untouched");
        assert_eq!(entries[0].owners, names(&["a.exe"]));
        assert_eq!(entries[1].owners, names(&["b.exe"]));
        assert_eq!(
            second.contents().matches(MARK_BEGIN).count(),
            1,
            "block must not accumulate"
        );
    }

    #[test]
    fn a_second_write_of_the_same_plan_changes_nothing() {
        let p = write_temp("idem2.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let rows = one("a.example.com", "2606:4700::1");
        let once = merged(&p, &f, "edge.exe", &rows);
        let again = merge(&once, "edge.exe", &rows);
        assert!(!again.changed, "already written: nothing to do");
        assert_eq!(again.bytes, once.raw().to_vec(), "and nothing to rewrite");
        assert_eq!(once.block_entries().len(), 1, "no duplicate line");
    }

    #[test]
    fn an_empty_plan_never_removes_anything() {
        // The bug this guards: a write with nothing to add used to erase every
        // entry already in the block.
        let p = write_temp("empty-plan.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let written = merged(&p, &f, "edge.exe", &one("a.test", "2606:4700::1"));
        let after = merge(&written, "edge.exe", &[]);
        assert!(!after.changed);
        assert_eq!(after.bytes, written.raw().to_vec(), "the entry stays put");
        assert_eq!(written.managed_entries().len(), 1);
    }

    #[test]
    fn a_blocked_name_is_upgraded_once_ipv6_shows_up() {
        let p = write_temp("upgrade.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        // First write: no IPv6 answer, so the name is pointed at the block address.
        let blocked = plan(
            [("late.example.com", &[][..])].iter().copied(),
            NoAaaaPolicy::Block,
        );
        let first = merged(&p, &f, "edge.exe", &blocked);
        assert_eq!(first.managed_entries()[0].0, BLOCK_ADDRESS);

        // The IPv6 answer arrives. This is the one change a write makes to a
        // line that is already there.
        let m = merge(&first, "edge.exe", &one("late.example.com", "2606:4700::9"));
        assert!(m.changed);
        assert_eq!(m.upgraded, 1);
        assert_eq!(m.appended, 0, "the line is corrected, not duplicated");
        let after = reload(&p, m.bytes);
        assert_eq!(after.managed_entries()[0].0, "2606:4700::9");
        assert_eq!(after.block_entries()[0].owners, names(&["edge.exe"]));
    }

    #[test]
    fn a_working_address_is_never_replaced_by_the_block_address() {
        // The other direction is not corrected: a name that resolved to a real
        // address keeps it even when this run has no IPv6 answer for it.
        let p = write_temp("nodowngrade.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let first = merged(&p, &f, "edge.exe", &one("was.example.com", "2606:4700::5"));
        let blocked = plan(
            [("was.example.com", &[][..])].iter().copied(),
            NoAaaaPolicy::Block,
        );
        let m = merge(&first, "edge.exe", &blocked);
        assert!(!m.changed);
        assert_eq!(reload(&p, m.bytes).managed_entries()[0].0, "2606:4700::5");
    }

    #[test]
    fn a_name_another_process_wrote_is_not_written_twice() {
        let p = write_temp("shared.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let shared = one("cdn.example.com", "2606:4700::7");
        let a = merged(&p, &f, "a.exe", &shared);

        let m = merge(&a, "b.exe", &shared);
        assert!(m.changed, "b.exe gets recorded on the line");
        assert_eq!(m.appended, 0, "but the line itself is not written twice");
        assert_eq!(m.claimed, 1);
        let after = reload(&p, m.bytes);
        assert_eq!(after.block_entries().len(), 1);
        assert_eq!(after.block_entries()[0].owners, names(&["a.exe", "b.exe"]));
    }

    #[test]
    fn removing_one_line_deletes_it_even_when_shared() {
        let p = write_temp("remove-entry.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let a = merged(&p, &f, "a.exe", &one("one.example.com", "2606:4700::1"));
        let b = merged(&p, &a, "b.exe", &one("two.example.com", "2606:4700::2"));
        // a.exe asks for the same name and address: it only joins the line.
        let shared = merged(&p, &b, "a.exe", &one("two.example.com", "2606:4700::2"));
        assert_eq!(shared.block_entries().len(), 2);
        assert_eq!(shared.block_entries()[1].owners, names(&["b.exe", "a.exe"]));

        // Deleting the row removes it outright, including the other owner's
        // claim: this is the blunt "delete this line" action.
        let r = remove_entry(&shared, "two.example.com", "2606:4700::2");
        assert!(r.changed && r.removed == 1);
        let after = reload(&p, r.bytes);
        assert_eq!(
            after.managed_entries(),
            vec![("2606:4700::1".to_string(), "one.example.com".to_string())]
        );

        // A row that is not there changes nothing, byte for byte.
        let before = after.raw().to_vec();
        let r2 = remove_entry(&after, "two.example.com", "2606:4700::2");
        assert!(!r2.changed);
        assert_eq!(r2.bytes, before);

        // Removing the last row takes the empty markers with it, so the file
        // comes back exactly as it was before any write.
        let r3 = remove_entry(&after, "one.example.com", "2606:4700::1");
        assert!(r3.changed && r3.removed == 1);
        let empty = reload(&p, r3.bytes);
        assert!(!empty.has_managed_block());
        assert_eq!(empty.raw().to_vec(), SAMPLE.as_bytes());
    }

    #[test]
    fn removing_a_process_takes_only_its_own_entries() {
        let p = write_temp("perproc.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let a = merged(&p, &f, "a.exe", &one("a-only.example.com", "2606:4700::1"));
        let both = merged(&p, &a, "b.exe", &one("b-only.example.com", "2606:4700::2"));

        let r = unclaim(&both, "a.exe");
        assert!(r.changed && r.removed == 1 && r.shared == 0);
        let after = reload(&p, r.bytes);
        assert_eq!(
            after.managed_entries(),
            vec![("2606:4700::2".to_string(), "b-only.example.com".to_string())]
        );
        assert_eq!(after.block_entries()[0].owners, names(&["b.exe"]));
        assert_eq!(after.owners_summary(), vec![("b.exe".to_string(), 1)]);
    }

    #[test]
    fn removing_a_process_keeps_a_line_another_process_still_needs() {
        let p = write_temp("shared-remove.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let shared = one("cdn.example.com", "2606:4700::7");
        let a = merged(&p, &f, "a.exe", &shared);
        let both = merged(&p, &a, "b.exe", &shared);

        let r = unclaim(&both, "a.exe");
        assert_eq!(r.removed, 0, "b.exe is still relying on the line");
        assert_eq!(r.shared, 1);
        let after = reload(&p, r.bytes);
        assert_eq!(after.managed_entries().len(), 1);
        assert_eq!(after.block_entries()[0].owners, names(&["b.exe"]));

        // Once b.exe's entries go too, so does the line -- and the block.
        let r2 = unclaim(&after, "b.exe");
        assert_eq!(r2.removed, 1);
        let empty = reload(&p, r2.bytes);
        assert!(!empty.has_managed_block());
        assert_eq!(empty.raw().to_vec(), SAMPLE.as_bytes(), "the file comes back exactly");
    }

    #[test]
    fn removing_a_process_that_wrote_nothing_changes_nothing() {
        let p = write_temp("noop-remove.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let a = merged(&p, &f, "a.exe", &one("a.example.com", "2606:4700::1"));
        let r = unclaim(&a, "never.exe");
        assert!(!r.changed);
        assert_eq!(r.bytes, a.raw().to_vec());
    }

    #[test]
    fn a_hand_written_line_is_left_alone() {
        // The user's own line comes first in the file, so a copy in our block
        // would never be reached. It is reported, not written.
        let p = write_temp("userline.hosts", "# header\r\n10.0.0.1  mine.example.com\r\n");
        let f = HostsFile::load(&p).unwrap();
        let m = merge(&f, "edge.exe", &one("mine.example.com", "2606:4700::1"));
        assert!(!m.changed);
        assert_eq!(m.bytes, f.raw().to_vec());
    }

    #[test]
    fn untouched_lines_come_back_byte_for_byte() {
        let p = write_temp("spacing.hosts", "# header\r\n127.0.0.1 localhost\r\n");
        let f = HostsFile::load(&p).unwrap();
        let first = merged(&p, &f, "a.exe", &one("keep.example.com", "2606:4700::1"));
        // Tidy the line up by hand, the way a user might.
        let tidied = first
            .contents()
            .replace("2606:4700::1", "2606:4700::1        ");
        let hand = reload(&p, tidied.clone().into_bytes());

        let m = merge(&hand, "b.exe", &one("new.example.com", "2606:4700::2"));
        assert!(m.changed);
        let after = String::from_utf8(m.bytes).unwrap();
        assert!(
            after.contains("2606:4700::1        "),
            "a line nobody changed must keep its exact spacing"
        );
        assert!(after.contains("new.example.com"));
    }

    #[test]
    fn managed_entries_are_readable() {
        let p = write_temp("read.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let rows = plan(
            [
                ("a.example.com", &[ip("2606:4700::1")][..]),
                ("b.example.com", &[][..]),
            ]
            .iter()
            .copied(),
            NoAaaaPolicy::Block,
        );
        let with = merged(&p, &f, "a.exe", &rows);
        let got = with.managed_entries();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], ("2606:4700::1".to_string(), "a.example.com".to_string()));
        assert_eq!(got[1], ("127.0.0.1".to_string(), "b.example.com".to_string()));
        assert_eq!(with.owners_summary(), vec![("a.exe".to_string(), 2)]);
    }

    #[test]
    fn skipped_entries_are_not_written() {
        let p = write_temp("skip.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let rows = plan(
            [("none.example.com", &[][..])].iter().copied(),
            NoAaaaPolicy::Skip,
        );
        let m = merge(&f, "a.exe", &rows);
        assert!(!m.changed, "a policy-skipped name changes nothing");
        assert_eq!(m.bytes, SAMPLE.as_bytes());
    }

    #[test]
    fn line_endings_follow_the_file() {
        let lf = write_temp("lf.hosts", "# comment\n127.0.0.1 localhost\n");
        let f = HostsFile::load(&lf).unwrap();
        let out = merge(
            &f,
            "a.exe",
            &plan(
                [("a.test", &[ip("2606:4700::1")][..])].iter().copied(),
                NoAaaaPolicy::Block,
            ),
        )
        .bytes;
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains('\r'), "an LF file must stay LF");
    }

    #[test]
    fn backup_and_restore_round_trip() {
        let dir = std::env::temp_dir().join(format!("netmon-hb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hosts = write_temp("bk.hosts", SAMPLE);
        let b = backup(&hosts, &dir).unwrap();
        assert!(b.is_file());
        assert_eq!(std::fs::read(&b).unwrap(), SAMPLE.as_bytes());

        std::fs::write(&hosts, "changed\r\n").unwrap();
        let safety = restore(&b, &hosts, &dir).unwrap();
        assert_eq!(std::fs::read(&hosts).unwrap(), SAMPLE.as_bytes());
        assert!(safety.is_file(), "restoring must back up what it replaced");
        assert_eq!(list_backups(&dir).len(), 2);
    }

    #[test]
    fn classify_says_what_is_already_there() {
        let rows = vec![
            entry("2606:4700::1", "mine.example.com"),
            entry("2606:4700::2", "theirs.example.com"),
            entry("2606:4700::3", "blocked.example.com"),
            entry("2606:4700::4", "stale.example.com"),
            entry("2606:4700::5", "fresh.example.com"),
            entry("2606:4700::6", "user-added.example.com"),
        ];
        let managed = vec![
            be("2606:4700::1", "mine.example.com", &["edge.exe"]),
            be("2606:4700::2", "theirs.example.com", &["other.exe"]),
            be(BLOCK_ADDRESS, "blocked.example.com", &["edge.exe"]),
            be("9999::9", "stale.example.com", &["edge.exe"]),
            be("2606:4700::8", "legacy.example.com", &[]),
        ];
        let mut all: Vec<(String, String)> = managed
            .iter()
            .map(|e| (e.address.clone(), e.domain.clone()))
            .collect();
        all.push(("10.1.1.1".to_string(), "user-added.example.com".to_string()));

        let got = classify(&rows, &managed, &all, "edge.exe");
        assert_eq!(got[0].state, WrittenState::Same);
        assert_eq!(got[0].action, RowAction::Keep);
        assert_eq!(got[1].state, WrittenState::OtherOwner);
        assert_eq!(got[1].action, RowAction::Claim);
        assert_eq!(got[2].state, WrittenState::Upgrade);
        assert_eq!(got[2].action, RowAction::Update);
        assert_eq!(got[3].state, WrittenState::OtherAddress);
        assert_eq!(got[3].action, RowAction::Keep);
        assert_eq!(got[4].state, WrittenState::Absent);
        assert_eq!(got[4].action, RowAction::Append);
        assert_eq!(got[5].state, WrittenState::OutsideOurBlock);
        assert_eq!(got[5].action, RowAction::Skip);

        assert!(!got[0].action.changes_file(), "already exactly right");
        assert!(got[1].action.changes_file(), "the line gains our name");
        assert!(got[2].action.changes_file(), "the address is corrected");
        assert!(!got[3].action.changes_file(), "an address that works is kept");
        assert!(got[4].action.changes_file(), "a new line is added");
        assert!(!got[5].action.changes_file(), "the user's own line stands");
    }

    #[test]
    fn a_stale_address_is_replaced_when_the_probe_marks_it() {
        let p = write_temp("stale.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let first = merged(&p, &f, "edge.exe", &one("stale.example.com", "2606:4700::1"));
        assert_eq!(first.managed_entries()[0].0, "2606:4700::1");

        // The probe failed for the old address; the fresh answer may replace it.
        let mut fresh = entry("2606:4700::2", "stale.example.com");
        fresh.replace_existing = true;
        let m = merge(&first, "edge.exe", std::slice::from_ref(&fresh));
        assert!(m.changed);
        assert_eq!(m.replaced, 1);
        assert_eq!(m.kept, 0);
        let after = reload(&p, m.bytes);
        assert_eq!(after.managed_entries()[0].0, "2606:4700::2");
        assert_eq!(after.block_entries()[0].owners, names(&["edge.exe"]));
    }

    #[test]
    fn classify_marks_a_stale_address_as_replaceable() {
        let mut fresh = entry("2606:4700::2", "stale.example.com");
        fresh.replace_existing = true;
        let managed = vec![be("2606:4700::1", "stale.example.com", &["edge.exe"])];
        let got = classify(std::slice::from_ref(&fresh), &managed, &[], "edge.exe");
        assert_eq!(got[0].state, WrittenState::StaleAddress);
        assert_eq!(got[0].action, RowAction::Replace);
        assert!(got[0].action.changes_file());
    }

    #[test]
    fn a_line_an_older_version_wrote_is_claimed_instead_of_duplicated() {
        let rows = vec![entry("2606:4700::8", "legacy.example.com")];
        let managed = vec![be("2606:4700::8", "legacy.example.com", &[])];
        let got = classify(&rows, &managed, &[], "edge.exe");
        assert_eq!(got[0].state, WrittenState::Unrecorded);
        assert_eq!(got[0].action, RowAction::Claim);
    }

    #[test]
    fn a_different_process_is_not_told_it_owns_our_line() {
        let rows = vec![entry("2606:4700::1", "mine.example.com")];
        let managed = vec![be("2606:4700::1", "mine.example.com", &["other.exe"])];
        let got = classify(&rows, &managed, &[], "edge.exe");
        assert_eq!(got[0].state, WrittenState::OtherOwner, "so removal stays per-process");
        assert_eq!(got[0].action, RowAction::Claim);
    }

    #[test]
    fn skipped_entries_are_never_marked_as_written() {
        let rows = vec![PlannedEntry {
            address: String::new(),
            domain: "x.test".into(),
            reason: PlanReason::SkippedNoIpv6,
            previous_session: false,
            replace_existing: false,
        }];
        let got = classify(&rows, &[], &[], "edge.exe");
        assert_eq!(got[0].state, WrittenState::Absent);
        assert_eq!(got[0].action, RowAction::Skip);
    }

    #[test]
    fn owners_are_counted_for_every_process_sharing_a_line() {
        let p = write_temp("owner-count.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let shared = one("cdn.example.com", "2606:4700::7");
        let a = merged(&p, &f, "a.exe", &shared);
        let b = merged(&p, &a, "b.exe", &shared);
        assert_eq!(b.block_entries().len(), 1, "one line, two owners");
        assert_eq!(
            b.owners_summary(),
            vec![("a.exe".to_string(), 1), ("b.exe".to_string(), 1)],
            "a shared line is one entry for each process that asked for it"
        );
    }

    #[test]
    fn owners_are_read_from_the_tag() {
        assert_eq!(parse_owners("1.2.3.4 x.test # nm"), Vec::<String>::new());
        assert_eq!(parse_owners("1.2.3.4 x.test # nm edge.exe"), names(&["edge.exe"]));
        assert_eq!(
            parse_owners("1.2.3.4 x.test # nm a.exe,b.exe"),
            names(&["a.exe", "b.exe"])
        );
        assert_eq!(parse_owners("1.2.3.4 x.test"), Vec::<String>::new());
        assert_eq!(
            parse_owners("1.2.3.4 x.test # nmx.exe"),
            Vec::<String>::new(),
            "not our tag"
        );
        assert_eq!(
            parse_owners("1.2.3.4 x.test # nm a.exe # a note"),
            names(&["a.exe"]),
            "a note after the tag is not a process name"
        );
    }

    #[test]
    fn pruning_keeps_the_newest_backups() {
        let dir = std::env::temp_dir().join(format!("netmon-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let hosts = write_temp("prune.hosts", SAMPLE);
        for i in 0..8 {
            // Names sort by timestamp, so a later index reads as newer.
            std::fs::write(dir.join(format!("hosts-2026010{i}-000000_000.bak")), b"x").unwrap();
        }
        let _ = backup(&hosts, &dir);
        assert!(list_backups(&dir).len() >= 8);
        assert!(prune_backups(&dir, 3) >= 5);
        assert_eq!(list_backups(&dir).len(), 3);
    }

    #[test]
    fn merge_owned_writes_one_line_for_several_owners() {
        let p = write_temp("owned.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let rows = vec![(
            names(&["a.exe", "b.exe"]),
            entry("2606:4700::9", "shared.example.com"),
        )];
        let m = merge_owned(&f, &rows);
        assert_eq!(m.appended, 1);
        let after = reload(&p, m.bytes);
        assert_eq!(after.block_entries().len(), 1);
        assert_eq!(
            after.owners_summary(),
            vec![("a.exe".to_string(), 1), ("b.exe".to_string(), 1)],
            "both processes own the single line"
        );
        assert!(after.contents().contains("2606:4700::9"));
        // Running it again changes nothing: all owners are already recorded.
        assert!(!merge_owned(&after, &rows).changed);
    }

    #[test]
    fn merge_owned_keeps_a_working_address_and_records_the_other_owner() {
        let p = write_temp("owned-conflict.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let first = vec![(names(&["a.exe"]), entry("2606:4700::1", "cdn.example.com"))];
        let after = reload(&p, merge_owned(&f, &first).bytes);
        // b.exe resolved the same name to a different address: one line can
        // only hold one address, so the existing one stays and b is recorded.
        let second = vec![(names(&["b.exe"]), entry("2606:4700::2", "cdn.example.com"))];
        let m = merge_owned(&after, &second);
        let after = reload(&p, m.bytes);
        let entries = after.block_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].address, "2606:4700::1");
        assert_eq!(entries[0].owners, names(&["a.exe", "b.exe"]));
    }

    #[test]
    fn merge_owned_upgrades_a_blocked_line_and_claims_it() {
        let p = write_temp("owned-upgrade.hosts", SAMPLE);
        let f = HostsFile::load(&p).unwrap();
        let blocked = vec![(names(&["a.exe"]), entry(BLOCK_ADDRESS, "x.example.com"))];
        let after = reload(&p, merge_owned(&f, &blocked).bytes);
        let upgraded = vec![(names(&["b.exe"]), entry("2606:4700::3", "x.example.com"))];
        let m = merge_owned(&after, &upgraded);
        assert_eq!(m.upgraded, 1);
        let after = reload(&p, m.bytes);
        assert_eq!(after.block_entries()[0].address, "2606:4700::3");
        assert_eq!(after.block_entries()[0].owners, names(&["a.exe", "b.exe"]));
    }

    #[test]
    fn parsing_ignores_comments_and_blank_lines() {
        assert_eq!(parse_host_line("# comment"), None);
        assert_eq!(parse_host_line("   "), None);
        assert_eq!(
            parse_host_line("127.0.0.1 localhost # nm"),
            Some(("127.0.0.1".to_string(), "localhost".to_string()))
        );
        assert_eq!(parse_host_line("not-an-address foo"), None);
    }
}
