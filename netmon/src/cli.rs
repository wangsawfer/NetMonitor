//! Command-line interface.

use std::path::PathBuf;

use clap::Parser;

use crate::app::SourceOptions;

/// Event-driven Windows DNS monitor for a target application and its children.
///
/// Monitoring is started *before* the target application is launched, so the
/// very first query the target makes is captured.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "netmon",
    version,
    about,
    long_about = None,
    after_help = "EXAMPLES:\n  \
        netmon --app \"D:\\Apps\\browser.exe\"\n  \
        netmon --app \"C:\\App\\app.exe\" --app \"C:\\Tools\\updater.exe\"\n  \
        netmon --app \"C:\\Program Files\\App\\app.exe\" --arg --profile --arg default\n  \
        netmon --attach msedge.exe --attach chrome.exe --keep-alive\n  \
        netmon --app \"D:\\app.exe\" --duration 30 --export out.csv\n  \
        netmon --doctor"
)]
pub struct Cli {
    /// Path to an application to monitor. Monitoring starts first, then this
    /// executable is launched.
    ///
    /// Repeat the flag to monitor several programs in one session: each one
    /// becomes a root of the same process tree, so their children are covered
    /// too. `--arg` applies to every one of them.
    #[arg(short = 'a', long = "app", value_name = "PATH")]
    pub apps: Vec<PathBuf>,

    /// An argument to forward to the target application(s). Repeat for each
    /// one. The same list is passed to every `--app`.
    #[arg(long = "arg", value_name = "ARG", allow_hyphen_values = true)]
    pub args: Vec<String>,

    /// Attach to a process that is already running, by image name
    /// (e.g. `chrome.exe`) instead of launching one.
    ///
    /// Repeat the flag to attach to several image names. Every matching
    /// process is adopted, not just the first.
    #[arg(long = "attach", value_name = "IMAGE")]
    pub attaches: Vec<String>,

    /// Watch for processes by image name and adopt them as they appear.
    ///
    /// Repeat for several names. Unlike `--attach`, which adopts whatever is
    /// running at that instant, this keeps matching: a process that starts
    /// minutes later is picked up the moment it appears, along with its
    /// descendants.
    ///
    /// Matching is by image name only, so a program that downloads through a
    /// separate helper can be monitored without the main window's traffic --
    /// watch the helper's name and the main process is excluded automatically.
    /// Find the name in Task Manager: Details tab, or right-click the column
    /// header and add "Command line".
    #[arg(long = "watch", value_name = "IMAGE")]
    pub watch: Vec<String>,

    /// Disable the ETW source (primary).
    #[arg(long = "no-etw", default_value_t = false)]
    pub no_etw: bool,

    /// Disable the Npcap packet-capture source (supplement).
    #[arg(long = "no-npcap", default_value_t = false)]
    pub no_npcap: bool,

    /// Also capture on loopback interfaces.
    #[arg(long = "loopback", default_value_t = false)]
    pub loopback: bool,

    /// Override the built-in BPF filter (diagnosis only). Example:
    /// `--pcap-filter "udp port 53 or tcp port 443"`.
    #[arg(long = "pcap-filter", value_name = "EXPR")]
    pub pcap_filter: Option<String>,

    /// Name of the ETW trace session to create. Empty (the default) derives a
    /// per-process name, so several instances can run side by side.
    #[arg(long = "session-name", default_value = "")]
    pub session_name: String,

    /// Accepted for compatibility: this build has no terminal UI, so every run
    /// is headless. Kept so existing scripts and documentation do not break.
    #[arg(long = "headless", default_value_t = false)]
    pub headless: bool,

    /// Stop automatically after this many seconds.
    #[arg(long = "duration", value_name = "SECS")]
    pub duration: Option<u64>,

    /// Also print DNS answers / SNI records.
    #[arg(long = "show-responses", default_value_t = false)]
    pub show_responses: bool,

    /// Keep monitoring until stopped, even after the target process exits.
    ///
    /// Without this, a run with no `--duration` ends once the target and all of
    /// its live descendants are gone -- which is right for a one-shot CLI run
    /// and wrong for a GUI session that should stay open. It also matters for
    /// single-instance applications: a browser launched while it is already
    /// running exits immediately, and without `--keep-alive` the session would
    /// end seconds later having seen nothing.
    #[arg(long = "keep-alive", default_value_t = false)]
    pub keep_alive: bool,

    /// Number of background workers that look up AAAA records.
    ///
    /// The lookups run on their own threads so a slow or unreachable resolver
    /// can never hold up capture. 0 disables them.
    #[arg(long = "aaaa-workers", value_name = "N", default_value_t = 4)]
    pub aaaa_workers: usize,

    /// Ask the resolver to bypass its cache when looking up AAAA records.
    ///
    /// Off by default: the name was usually resolved moments ago by the
    /// monitored application, so the answer is already cached and a wire query
    /// would only add traffic.
    #[arg(long = "aaaa-bypass-cache", default_value_t = false)]
    pub aaaa_bypass_cache: bool,

    /// Emit newline-delimited JSON instead of tab-separated text. Every line is
    /// one self-contained object with a `type` field. The types are: `hello`,
    /// `log`, `record`, `status`, `domain`, `aaaa`, `summary`, `fatal`, and the
    /// hosts replies `hosts_preview`, `hosts_content`, `hosts_history`,
    /// `hosts_result`, `hosts_auto`, `hosts_auto_written`, `hosts_written`,
    /// `hosts_removed`, `hosts_edited`, `hosts_restored`. This is the interface
    /// the GUI drives; see MANUAL §8.5 for the full protocol.
    #[arg(long = "stream-json", default_value_t = false)]
    pub stream_json: bool,

    /// How often to emit a `status` object in `--stream-json` mode, in
    /// milliseconds. Ignored otherwise.
    #[arg(long = "status-interval-ms", default_value_t = 500)]
    pub status_interval_ms: u64,

    /// Include rows whose owning process could not be determined. Off by
    /// default: such a row is not evidence that the target caused it.
    #[arg(long = "show-unattributed", default_value_t = false)]
    pub show_unattributed: bool,

    /// Let the target application write to this console.
    ///
    /// Off by default in `--stream-json` mode, where one line of the target's
    /// output would corrupt the protocol. Plain text output tolerates it, and a
    /// target that refuses to run without a real console needs it.
    #[arg(long = "child-console", default_value_t = false)]
    pub child_console: bool,

    /// Write the collected records to this file when the session ends
    /// (`.json` selects JSON, anything else selects CSV).
    #[arg(long = "export", value_name = "PATH")]
    pub export: Option<PathBuf>,

    /// Write the per-process domain tables, with AAAA results, when the
    /// session ends. `.json` selects JSON, anything else selects CSV.
    ///
    /// One row per (process, domain): a domain seen by two processes appears
    /// twice, because the table is per process.
    #[arg(long = "export-domains", value_name = "PATH")]
    pub export_domains: Option<PathBuf>,

    /// Path to the hosts file to manage. Defaults to the system one
    /// (`%SystemRoot%\System32\drivers\etc\hosts`).
    #[arg(long = "hosts-file", value_name = "PATH")]
    pub hosts_file: Option<PathBuf>,

    /// Where hosts backups are kept.
    ///
    /// Defaults to `hosts-backups` beside the executable, so the only thing
    /// this tool puts on the system drive is the hosts file itself.
    #[arg(long = "hosts-backup-dir", value_name = "DIR")]
    pub hosts_backup_dir: Option<PathBuf>,

    /// Where the local cache lives: the domain-table snapshot and the hosts
    /// change log.
    ///
    /// Defaults to `netmon-data` beside the executable. Keeping it next to the
    /// program is what keeps it off the system drive, and it is what lets a
    /// later run see which entries an earlier one wrote.
    #[arg(long = "data-dir", value_name = "DIR")]
    pub data_dir: Option<PathBuf>,

    /// Do not read or write the local cache.
    ///
    /// The program still manages the hosts file; it just starts with empty
    /// domain tables and keeps no change log. Useful for a one-off run that
    /// should leave nothing behind.
    #[arg(long = "no-cache", default_value_t = false)]
    pub no_cache: bool,

    /// What to do with domains that have no usable IPv6 address.
    /// `block` points them at 127.0.0.1, `skip` leaves them alone.
    #[arg(long = "no-aaaa", value_name = "MODE", default_value = "block")]
    pub no_aaaa: String,

    /// Print environment diagnostics (ETW access, Npcap devices, elevation) and
    /// exit without monitoring.
    #[arg(long = "doctor", default_value_t = false)]
    pub doctor: bool,

    /// Stop every trace session NetMonitor ever left behind, then exit
    /// (with --doctor) or continue (otherwise).
    ///
    /// Use this when ETW fails with "not enough system resources" (1450):
    /// that means sessions leaked by runs that were killed before they could
    /// clean up. Unlike the automatic sweep, this one does not check whether
    /// the owning process is still alive, so it will also stop a second
    /// instance you are running on purpose.
    #[arg(long = "clean-sessions", default_value_t = false)]
    pub clean_sessions: bool,

    /// Do not use colour in the output.
    #[arg(long = "no-color", default_value_t = false)]
    pub no_color: bool,
}

impl Cli {
    pub fn source_options(&self) -> SourceOptions {
        SourceOptions {
            use_etw: !self.no_etw,
            use_npcap: !self.no_npcap,
            include_loopback: self.loopback,
            bpf_override: self.pcap_filter.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_one_or_more_apps_and_attaches() {
        let c = Cli::try_parse_from([
            "netmon",
            "--app",
            "D:\\a\\b.exe",
            "--arg",
            "-x",
            "--arg",
            "y",
        ])
        .unwrap();
        assert_eq!(c.apps.len(), 1);
        assert_eq!(c.apps[0].to_str().unwrap(), "D:\\a\\b.exe");
        assert_eq!(c.args, vec!["-x".to_string(), "y".to_string()]);

        // Several targets: each --app is kept, in order, and the argument list
        // is shared by all of them.
        let c = Cli::try_parse_from([
            "netmon",
            "--app",
            "a.exe",
            "--app",
            "b.exe",
            "--arg",
            "--profile",
            "--attach",
            "msedge.exe",
            "--attach",
            "chrome.exe",
        ])
        .unwrap();
        assert_eq!(c.apps.len(), 2);
        assert_eq!(c.apps[1].to_str().unwrap(), "b.exe");
        assert_eq!(c.args, vec!["--profile".to_string()]);
        assert_eq!(c.attaches, vec!["msedge.exe", "chrome.exe"]);

        // None at all is allowed: the engine reports the missing target.
        let c = Cli::try_parse_from(["netmon"]).unwrap();
        assert!(c.apps.is_empty() && c.attaches.is_empty() && c.watch.is_empty());
    }

    #[test]
    fn source_options_respect_flags() {
        let c = Cli::try_parse_from(["netmon", "--no-npcap", "--loopback"]).unwrap();
        let o = c.source_options();
        assert!(o.use_etw);
        assert!(!o.use_npcap);
        assert!(o.include_loopback);
    }
}
