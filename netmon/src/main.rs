//! NetMonitor -- event-driven Windows DNS monitor for a target application.
//!
//! Two run modes, selected from the command line:
//!
//! * **headless** (default) -- stream accepted records to stdout, either as
//!   tab-separated text or, with `--stream-json`, as NDJSON. The graphical
//!   front-end (`gui/netmon_gui.py`) drives this mode: one process, one pipe.
//! * **`--doctor`** -- print environment diagnostics and exit.
//!
//! The terminal UI was removed; this binary is now the capture engine and the
//! scriptable front-end. The ordering guarantee lives here all the same:
//! `Session::start_capture` runs before `Session::launch_target`, in every mode.

mod app;
mod capture;
mod cli;
mod domains;
mod hosts;
mod model;
mod persist;
mod pipeline;
mod store;
mod util;
mod win;

use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Parser;

use crate::app::{NoteLevel, Session, SourceOptions};
use crate::cli::Cli;

fn main() -> ExitCode {
    // A panic would otherwise leave the console in whatever state the panic
    // interrupted. Nothing here rewrites the console any more, but the exit
    // path and the message are worth keeping: a stack trace with no context is
    // worse than one line saying what happened.
    let result = std::panic::catch_unwind(run);
    match result {
        Ok(code) => code,
        Err(_) => {
            eprintln!("netmon: fatal error; the trace session has been closed");
            ExitCode::from(70)
        }
    }
}

fn run() -> ExitCode {
    let cli = Cli::parse();

    if cli.clean_sessions {
        let stopped = win::etw::stop_stale_sessions(
            win::etw::SESSION_NAME_PREFIX,
            "",
            true,
        );
        if stopped.is_empty() {
            println!("no NetMonitor trace sessions were left behind");
        } else {
            println!("stopped {} stale trace session(s):", stopped.len());
            for n in &stopped {
                println!("  {n}");
            }
        }
        // Whether to carry on after the cleanup depends on whether the user
        // asked to run something as well. `--clean-sessions` on its own is a
        // maintenance action, not a monitoring session -- and since headless is
        // now the default mode, "no flag" can no longer mean "nothing to do".
        let wants_session = cli.headless
            || cli.stream_json
            || !cli.apps.is_empty()
            || !cli.attaches.is_empty()
            || !cli.watch.is_empty()
            || cli.duration.is_some();
        if !cli.doctor && !wants_session {
            return ExitCode::SUCCESS;
        }
        println!();
    }

    if cli.doctor {
        return doctor(&cli);
    }
    // There is no interactive terminal UI any more: this binary is the engine
    // and the scriptable front-end, and the graphical front-end drives it
    // through `--stream-json`. `--headless` is still accepted so existing
    // scripts keep working; it no longer selects anything.
    headless(&cli)
}

/// ETW session names must be unique per running instance; a fixed default
/// would make a second instance stomp on the first one's session.
fn session_name(cli: &Cli) -> String {
    if cli.session_name.trim().is_empty() {
        format!("NetMonitor-{}", std::process::id())
    } else {
        cli.session_name.clone()
    }
}

fn build_session(cli: &Cli) -> Session {
    let opts: SourceOptions = cli.source_options();
    let mut s = Session::new(opts, session_name(cli))
        .with_aaaa(cli.aaaa_workers, cli.aaaa_bypass_cache);
    s.attach_names = cli
        .attaches
        .iter()
        .map(|n| n.trim().to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    s.watch_names = cli
        .watch
        .iter()
        .map(|n| n.trim().to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    s.target_paths = cli.apps.clone();
    s.target_args = cli.args.clone();
    s.hosts_file = cli.hosts_file.clone();
    s.hosts_backup_dir = cli.hosts_backup_dir.clone();
    s.data_dir = if cli.no_cache {
        None
    } else {
        Some(
            cli.data_dir
                .clone()
                .unwrap_or_else(crate::persist::default_dir),
        )
    };
    // Read the previous session's tables before anything else looks at them:
    // the domain view, the hosts window and automatic writing all consult them.
    s.load_domain_cache();
    s.no_aaaa_policy = if cli.no_aaaa.eq_ignore_ascii_case("skip") {
        crate::hosts::NoAaaaPolicy::Skip
    } else {
        crate::hosts::NoAaaaPolicy::Block
    };
    s
}

// ---------------------------------------------------------------------------
// Headless (the only interactive-free mode left)
// ---------------------------------------------------------------------------

/// How long to keep monitoring after the target process exits, so that
/// in-flight lookups and late children are still recorded.
const POST_EXIT_GRACE: Duration = Duration::from_secs(3);

fn headless(cli: &Cli) -> ExitCode {
    if cli.apps.is_empty() && cli.attaches.is_empty() && cli.watch.is_empty() {
        eprintln!(
            "netmon: this build has no terminal UI; pass --app <path> (repeatable), \
             --attach <image name> (repeatable) or --watch <image name>, or start the \
             graphical front-end (run-netmon-gui.cmd)"
        );
        return ExitCode::from(2);
    }

    let json = cli.stream_json;
    let mut session = build_session(cli);
    // Plain text output is a human-readable stream, so the target's own output
    // is welcome next to it. JSON output is a protocol: one stray line from the
    // target would be a parse error, so the child is muted there.
    session.silence_child = json && !cli.child_console;
    // Output follows the same contract the interface did: only the target tree
    // is reported unless the operator opts in to unattributed rows.
    session
        .include_unattributed
        .store(cli.show_unattributed, std::sync::atomic::Ordering::Relaxed);

    if json {
        emit_json(&serde_json::json!({
            "type": "hello",
            "version": env!("CARGO_PKG_VERSION"),
            "pid": std::process::id(),
            "elevated": is_elevated(),
            "session": session.etw_session_name,
            // `target`/`attach` keep the first element for older readers;
            // `targets`/`attaches` are the complete lists.
            "target": cli.apps.first().map(|p| p.display().to_string()),
            "targets": cli.apps.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "attach": cli.attaches.first(),
            "attaches": cli.attaches,
        }));
    }

    if let Err(e) = session.start_capture() {
        if json {
            emit_json(&serde_json::json!({
                "type": "fatal",
                "text": format!("cannot start capture: {e}"),
            }));
        } else {
            eprintln!("netmon: cannot start capture: {e}");
        }
        return ExitCode::FAILURE;
    }

    for n in session.notes.clone() {
        emit_log(json, &n);
    }

    if json {
        // The restored tables, so a window opened now already knows which
        // processes have entries in the hosts file -- including ones that are
        // not running any more.
        emit_domain_tables(json, &session);
    }

    if cli.attaches.is_empty() && cli.watch.is_empty() {
        // Every --app becomes a root of the same tree. One bad path must not
        // cancel the others, but if none of them started there is nothing to
        // monitor and the run is a failure.
        let mut started = 0usize;
        for app in cli.apps.clone() {
            match session.launch_target(&app, &cli.args) {
                Ok(pid) => {
                    started += 1;
                    if json {
                        emit_json(&serde_json::json!({
                            "type": "log", "level": "info",
                            "text": format!("launched {} as pid {pid}", app.display()),
                        }));
                    } else {
                        eprintln!("[info] launched {} as pid {pid}", app.display());
                    }
                }
                Err(e) => {
                    if json {
                        emit_json(&serde_json::json!({
                            "type": "log", "level": "error",
                            "text": format!("could not launch {}: {e}", app.display()),
                        }));
                    } else {
                        eprintln!("netmon: could not launch {}: {e}", app.display());
                    }
                }
            }
        }
        if started == 0 {
            if json {
                emit_json(&serde_json::json!({
                    "type": "fatal", "text": "no target could be launched",
                }));
            }
            session.stop_capture();
            return ExitCode::FAILURE;
        }
    }

    if !json && !cli.no_color {
        println!("# seq\ttime\tprocess\tpid\tqtype\tsource\tkind\tdomain\tdetail");
    }

    // Only in JSON mode: the terminal UI reads stdin itself.
    let commands = if json { crate::app::spawn_command_reader() } else { None };

    let started = Instant::now();
    let mut last_seq = 0u64;
    let mut printed = 0u64;
    let mut child_gone_at: Option<Instant> = None;
    let mut next_status = Instant::now();
    // Domain-table deltas: which (process, domain) pairs and which lookup
    // results the GUI has already been told about. Sending changes rather than
    // snapshots keeps the stream small even with thousands of domains.
    let mut next_domain_push = Instant::now();
    let mut seen_domains: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();
    let mut last_status: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let status_every = Duration::from_millis(cli.status_interval_ms.max(50));
    // Notes already reported, so the log channel never repeats itself.
    let mut notes_sent = session.notes.len();

    loop {
        std::thread::sleep(Duration::from_millis(60));

        let fresh: Vec<crate::model::Record> = {
            let s = session.store.lock().unwrap();
            s.since(last_seq, 4096).into_iter().cloned().collect()
        };
        for r in fresh {
            last_seq = r.seq;
            if r.kind == crate::model::EventKind::Response && !cli.show_responses {
                continue;
            }
            if r.pid == 0 && !cli.show_unattributed {
                continue;
            }
            printed += 1;
            let kind = match r.kind {
                crate::model::EventKind::Query => "query",
                crate::model::EventKind::Response => "response",
                crate::model::EventKind::TlsSni => "tls_sni",
            };
            if json {
                emit_json(&serde_json::json!({
                    "type": "record",
                    "seq": r.seq,
                    "unix_ms": r.unix_ms,
                    "time": r.time,
                    "process": r.process,
                    "pid": r.pid,
                    "qtype": r.qtype,
                    "source": r.source.as_str(),
                    "kind": kind,
                    "domain": r.domain,
                    // Structured as well as rendered, so the address filter in
                    // the main list has something to match against.
                    "resolved_ips": r
                        .resolved
                        .iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>(),
                    "detail": r.detail,
                }));
            } else {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    r.seq,
                    r.time,
                    r.process,
                    r.pid,
                    r.qtype,
                    r.source.as_str(),
                    kind,
                    r.domain,
                    r.detail
                );
            }
        }

        // Anything the session logged since the last tick (a source dropping
        // out mid-run, a target that failed to start, ...).
        if session.notes.len() > notes_sent {
            let fresh_notes: Vec<crate::app::Note> = session.notes[notes_sent..].to_vec();
            notes_sent = session.notes.len();
            for n in &fresh_notes {
                emit_log(json, n);
            }
        }

        if json && Instant::now() >= next_domain_push {
            // Twice a second: fast enough to watch lookups land, cheap enough
            // that a large table costs nothing.
            next_domain_push = Instant::now() + Duration::from_millis(500);
            // The address cache is read once per push rather than once per
            // domain.
            let cached: std::collections::HashMap<String, Vec<String>> = {
                let store = session.store.lock().unwrap();
                session
                    .domains
                    .all_rows()
                    .into_iter()
                    .map(|(_, d, _)| {
                        let ips = store
                            .ips
                            .ips_for_name(&d)
                            .map(|v| v.iter().map(|i| i.to_string()).collect())
                            .unwrap_or_default();
                        (d, ips)
                    })
                    .collect()
            };
            for (process, domain, entry) in session.domains.all_rows() {
                if seen_domains.insert((process.clone(), domain.clone())) {
                    emit_json(&serde_json::json!({
                        "type": "domain",
                        "process": process,
                        "domain": domain,
                    }));
                }
                let status = entry.status();
                // The row is re-sent when either the lookup status or the
                // resolved addresses change, so the table never shows a stale
                // address next to a fresh status.
                let observed = cached.get(&domain).cloned().unwrap_or_default();
                let (merged, from_own) = crate::domains::merged_addresses(
                    &observed
                        .iter()
                        .filter_map(|a| a.parse::<std::net::IpAddr>().ok())
                        .collect::<Vec<_>>(),
                    Some(&entry),
                );
                let resolved: Vec<String> =
                    merged.iter().map(|a| a.to_string()).collect();
                let key = format!("{status}|{}", resolved.join(","));
                if last_status.get(&domain).map(|s| s != &key).unwrap_or(true) {
                    last_status.insert(domain.clone(), key);
                    emit_json(&serde_json::json!({
                        "type": "aaaa",
                        "domain": domain,
                        "status": status,
                        "settled": entry.settled(),
                        "archived": entry.archived,
                        "addresses": entry.addresses()
                            .iter()
                            .map(|a| a.to_string())
                            .collect::<Vec<_>>(),
                        "resolved_ips": resolved,
                        "resolved_by_us": from_own,
                    }));
                }
            }
        }

        if json && Instant::now() >= next_status {
            next_status = Instant::now() + status_every;
            emit_status(&mut session, started.elapsed().as_secs_f64());
        }

        // Keep the local cache warm, so an unclean exit loses at most half a
        // minute of domain-table history.
        session.save_domain_cache_if_due();

        // Automatic hosts writing. Cheap when off; when on it writes only once
        // the plan has settled and only if the file actually differs.
        if let Some(outcome) = session.hosts_auto_tick() {
            emit_json(&serde_json::json!({
                "type": "hosts_auto_written",
                "note": outcome.note,
                "appended": outcome.appended,
                "upgraded": outcome.upgraded,
                "claimed": outcome.claimed,
                "kept": outcome.kept,
                "skipped": outcome.skipped,
                "process": session.hosts_auto.process,
                "writes": session.hosts_auto.writes,
            }));
        }

        // Commands from whoever is driving us (the GUI).
        if let Some(rx) = &commands {
            while let Ok(cmd) = rx.try_recv() {
                match cmd {
                    crate::app::EngineCommand::Requery { failed_only } => {
                        let n = session.domains.requery(failed_only);
                        emit_json(&serde_json::json!({
                            "type": "log", "level": "info",
                            "text": if failed_only {
                                format!("re-querying {n} failed lookup(s)")
                            } else {
                                format!("re-querying all {n} domain(s)")
                            },
                        }));
                    }
                    crate::app::EngineCommand::ExportDomains { path } => {
                        match export_domains(&session, &path) {
                            Ok(n) => emit_json(&serde_json::json!({
                                "type": "log", "level": "info",
                                "text": format!("wrote {n} domain row(s) to {}", path.display()),
                            })),
                            Err(e) => emit_json(&serde_json::json!({
                                "type": "log", "level": "error",
                                "text": format!("domain export failed: {e}"),
                            })),
                        }
                    }
                    crate::app::EngineCommand::HostsPreview { process, policy } => {
                        // The preview is annotated with what is already in the
                        // file, so the window can say "已写入" without a second
                        // round trip.
                        let annotated = session.hosts_preview_annotated(&process, policy);
                        emit_json(&hosts_preview_json(&process, policy, &annotated));
                    }
                    crate::app::EngineCommand::HostsWrite {
                        process,
                        policy,
                        domains,
                    } => {
                        // A subset is a different request, not a flag on the
                        // whole-table write: the selection decides which rows
                        // are planned, while every write rule stays the same.
                        let result = match &domains {
                            Some(list) => session.hosts_write_selected(&process, policy, list),
                            None => session.hosts_write(&process, policy),
                        };
                        match result {
                            Ok(o) => emit_json(&hosts_outcome_json("hosts_written", true, &o, &session)),
                            Err(e) => emit_json(&serde_json::json!({
                                "type": "hosts_result", "ok": false,
                                "note": format!("写入失败：{e}"),
                            })),
                        }
                    }
                    crate::app::EngineCommand::HostsRemove { process } => {
                        match session.hosts_remove(process.as_deref()) {
                            Ok(o) => {
                                emit_json(&hosts_outcome_json("hosts_removed", true, &o, &session))
                            }
                            Err(e) => emit_json(&serde_json::json!({
                                "type": "hosts_result", "ok": false,
                                "note": format!("移除失败：{e}"),
                            })),
                        }
                    }
                    crate::app::EngineCommand::HostsRemoveEntry {
                        domain,
                        address,
                        process,
                    } => match session.hosts_remove_entry(&domain, &address, &process) {
                        Ok(o) => emit_json(&hosts_outcome_json(
                            "hosts_removed",
                            true,
                            &o,
                            &session,
                        )),
                        Err(e) => emit_json(&serde_json::json!({
                            "type": "hosts_result", "ok": false,
                            "note": format!("删除失败：{e}"),
                        })),
                    },
                    crate::app::EngineCommand::HostsHistory { limit } => {
                        let entries: Vec<serde_json::Value> = session
                            .hosts_history(limit)
                            .iter()
                            .map(|h| {
                                serde_json::json!({
                                    "at_ms": h.at_ms,
                                    "time": crate::persist::format_time(h.at_ms),
                                    "action": h.action,
                                    "action_label": h.action_label(),
                                    "process": h.process,
                                    "detail": h.detail(),
                                    "appended": h.appended,
                                    "upgraded": h.upgraded,
                                    "claimed": h.claimed,
                                    "removed": h.removed,
                                    "shared": h.shared,
                                    "backup": h.backup,
                                    "note": h.note,
                                })
                            })
                            .collect();
                        emit_json(&serde_json::json!({
                            "type": "hosts_history",
                            "entries": entries,
                        }));
                    }
                    crate::app::EngineCommand::HostsRead => {
                        let v = session.hosts_view();
                        emit_json(&serde_json::json!({
                            "type": "hosts_content",
                            "path": v.path.display().to_string(),
                            "text": v.text,
                            "managed_entries": v.managed_entries,
                            "total_entries": v.total_entries,
                            "by_owner": v.by_owner.iter()
                                .map(|(name, n)| serde_json::json!({
                                    "process": name,
                                    "entries": n,
                                }))
                                .collect::<Vec<_>>(),
                            // The block itself, with owners: the window groups
                            // these by process, and a shared line appears under
                            // each process that asked for it.
                            "entries": v.entries.iter()
                                .map(|e| serde_json::json!({
                                    "address": e.address,
                                    "domain": e.domain,
                                    "owners": e.owners,
                                    "line": e.line,
                                }))
                                .collect::<Vec<_>>(),
                            "backup_dir": v.backup_dir.display().to_string(),
                            "backups": v.backups.iter()
                                .map(|b| b.display().to_string())
                                .collect::<Vec<_>>(),
                            // Where the change log lives, so the window can say
                            // where "previous sessions" come from.
                            "data_dir": session.data_dir.as_ref()
                                .map(|d| d.display().to_string())
                                .unwrap_or_default(),
                        }));
                    }
                    crate::app::EngineCommand::HostsEdit { text } => {
                        match session.hosts_replace_text(&text) {
                            Ok(o) => emit_json(&hosts_outcome_json("hosts_edited", true, &o, &session)),
                            Err(e) => emit_json(&serde_json::json!({
                                "type": "hosts_result", "ok": false,
                                "note": format!("保存失败：{e}"),
                            })),
                        }
                    }
                    crate::app::EngineCommand::HostsPruneBackups { keep } => {
                        let removed = session.hosts_prune_backups(keep);
                        emit_json(&serde_json::json!({
                            "type": "hosts_result", "ok": true,
                            "note": format!("已清理 {removed} 个旧备份，保留最新 {keep} 个"),
                        }));
                    }
                    crate::app::EngineCommand::HostsBackup => match session.hosts_backup_now() {
                        Ok(b) => emit_json(&serde_json::json!({
                            "type": "hosts_result", "ok": true,
                            "note": format!("已备份到 {}", b.display()),
                            "backup": b.display().to_string(),
                        })),
                        Err(e) => emit_json(&serde_json::json!({
                            "type": "hosts_result", "ok": false,
                            "note": format!("备份失败：{e}"),
                        })),
                    },
                    crate::app::EngineCommand::HostsAuto { on, process, policy } => {
                        session.hosts_auto.policy = policy;
                        session.set_hosts_auto(on, process);
                        emit_json(&serde_json::json!({
                            "type": "hosts_auto",
                            "enabled": session.hosts_auto.enabled,
                            "process": session.hosts_auto.process,
                            "note": session.hosts_auto.last_note,
                        }));
                    }
                    crate::app::EngineCommand::HostsRestore { path } => {
                        match session.hosts_restore_backup(&path) {
                            Ok(o) => emit_json(&hosts_outcome_json("hosts_restored", true, &o, &session)),
                            Err(e) => emit_json(&serde_json::json!({
                                "type": "hosts_result", "ok": false,
                                "note": format!("恢复失败：{e}"),
                            })),
                        }
                    }
                    crate::app::EngineCommand::Stop => {
                        emit_json(&serde_json::json!({
                            "type": "log", "level": "info", "text": "stop requested",
                        }));
                        session.stop_capture();
                    }
                }
            }
        }

        if let Some(d) = cli.duration {
            if started.elapsed() >= Duration::from_secs(d) {
                if !json {
                    eprintln!("[info] duration reached");
                }
                break;
            }
        }

        // A single-instance application (browser) hands off to the process
        // that is already running and exits. Say so, with the command that
        // actually works, instead of sitting there capturing nothing. With
        // several targets this is checked per image, and reported once each.
        while let Some((image, pids)) = session.detect_handoff() {
            let text = format!(
                "target exited immediately but {} other '{image}' process(es) are running \
                 that were not started by us ({}). This application hands off to an \
                 existing instance. Stop this run and use:  netmon --attach {image} --keep-alive",
                pids.len(),
                pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
            );
            let note = crate::app::Note {
                at: Instant::now(),
                level: NoteLevel::Warn,
                text,
            };
            session.notes.push(note.clone());
            emit_log(json, &note);
            notes_sent = session.notes.len();
        }

        if !cli.keep_alive && cli.attaches.is_empty() && cli.watch.is_empty() {
            if session.target_finished() {
                let when = *child_gone_at.get_or_insert_with(Instant::now);
                if cli.duration.is_none() && when.elapsed() >= POST_EXIT_GRACE {
                    if !json {
                        eprintln!("[info] target and all of its descendants have exited");
                    }
                    break;
                }
            } else {
                child_gone_at = None;
            }
        }
        if !session.is_capturing() {
            break;
        }
    }

    // Drain anything that arrived during the final tick.
    std::thread::sleep(Duration::from_millis(120));

    let mut result = ExitCode::SUCCESS;
    if let Some(path) = &cli.export {
        let exported = {
            let store = session.store.lock().unwrap();
            store.export(path, &store::ViewFilter::default())
        };
        match exported {
            Ok(n) => {
                if json {
                    emit_json(&serde_json::json!({
                        "type": "log", "level": "info",
                        "text": format!("exported {n} record(s) to {}", path.display()),
                    }));
                } else {
                    eprintln!("[info] exported {n} record(s) to {}", path.display());
                }
            }
            Err(e) => {
                if json {
                    emit_json(&serde_json::json!({
                        "type": "log", "level": "error",
                        "text": format!("export failed: {e}"),
                    }));
                } else {
                    eprintln!("netmon: export failed: {e}");
                }
                result = ExitCode::FAILURE;
            }
        }
    }

    let kernel_dropped = session.kernel_dropped();
    let queue_dropped = session.queue_dropped();
    let (pcap_packets, pcap_queries, pcap_responses, pcap_sni, pcap_suppressed) =
        session.pcap_counters().unwrap_or((0, 0, 0, 0, 0));
    let (queries, domains, filtered, stored) = {
        let s = session.store.lock().unwrap();
        (
            s.stats.queries,
            s.stats.unique_domain_count(),
            s.stats.filtered_out_of_tree,
            s.stats.total_records,
        )
    };

    if json {
        emit_domain_tables(json, &session);
    }

    if let Some(path) = &cli.export_domains {
        match export_domains(&session, path) {
            Ok(n) => {
                let text = format!("wrote {n} domain row(s) to {}", path.display());
                if json {
                    emit_json(&serde_json::json!({
                        "type": "log", "level": "info", "text": text,
                    }));
                } else {
                    eprintln!("[info] {text}");
                }
            }
            Err(e) => {
                let text = format!("domain export failed: {e}");
                if json {
                    emit_json(&serde_json::json!({
                        "type": "log", "level": "error", "text": text,
                    }));
                } else {
                    eprintln!("netmon: {text}");
                }
                result = ExitCode::FAILURE;
            }
        }
    }

    if json {
        emit_json(&serde_json::json!({
            "type": "summary",
            "lines": printed,
            "queries": queries,
            "domains": domains,
            "stored": stored,
            "filtered_out_of_tree": filtered,
            "drops_kernel": kernel_dropped,
            "drops_queue": queue_dropped,
            "pcap_packets": pcap_packets,
            "pcap_queries": pcap_queries,
            "pcap_responses": pcap_responses,
            "pcap_sni": pcap_sni,
            "pcap_suppressed": pcap_suppressed,
        }));
    } else {
        eprintln!(
            "[info] pcap: {pcap_packets} packet(s) matched the filter, {pcap_queries} DNS query(ies), \
             {pcap_responses} answer(s), {pcap_sni} SNI name(s), {pcap_suppressed} svchost row(s) suppressed"
        );
        eprintln!(
            "[info] {} line(s) printed, {} DNS quer(ies), {} unique domain(s), \
             {} event(s) filtered out as other processes, {} drop(s)",
            printed,
            queries,
            domains,
            filtered,
            kernel_dropped + queue_dropped
        );
    }

    session.stop_capture();
    result
}

/// The preview of a hosts write: one row per domain, plus the totals.
fn hosts_preview_json(
    process: &str,
    policy: crate::hosts::NoAaaaPolicy,
    entries: &[(crate::hosts::PlannedEntry, crate::hosts::RowPlan)],
) -> serde_json::Value {
    let rows: Vec<serde_json::Value> = entries
        .iter()
        .map(|(e, row)| {
            serde_json::json!({
                "domain": e.domain,
                "address": e.address,
                "reason": e.reason.short(),
                "skipped": e.reason == crate::hosts::PlanReason::SkippedNoIpv6,
                "written": row.state.label(),
                "action": row.action.label(),
                "needs_write": row.action.changes_file(),
                // The address is the previous session's, not a fresh lookup.
                "previous": e.previous_session,
            })
        })
        .collect();
    serde_json::json!({
        "type": "hosts_preview",
        "process": process,
        "policy": if policy == crate::hosts::NoAaaaPolicy::Block { "block" } else { "skip" },
        "entries": rows,
    })
}

/// A completed hosts operation.
fn hosts_outcome_json(
    kind: &str,
    ok: bool,
    o: &crate::app::HostsOutcome,
    session: &crate::app::Session,
) -> serde_json::Value {
    serde_json::json!({
        "type": kind,
        "ok": ok,
        "note": o.note,
        "path": o.path.display().to_string(),
        "backup": o.backup.as_ref().map(|b| b.display().to_string()),
        "appended": o.appended,
        "upgraded": o.upgraded,
        "claimed": o.claimed,
        "kept": o.kept,
        "skipped": o.skipped,
        "removed": o.removed,
        "shared": o.shared,
        "unchanged": o.unchanged,
        "managed_entries": session.hosts_view().managed_entries,
    })
}

/// Emit the per-process domain tables as one NDJSON object.
fn emit_domain_tables(json: bool, session: &crate::app::Session) {
    if !json {
        return;
    }
    let tables: Vec<serde_json::Value> = session
        .domains
        .process_tables()
        .into_iter()
        .map(|t| {
            let cached = session.store.lock().unwrap();
            let rows: Vec<serde_json::Value> = session
                .domains
                .rows_for(&t.name)
                .into_iter()
                .map(|(_key, entry)| {
                    let observed: Vec<std::net::IpAddr> = cached
                        .ips
                        .ips_for_name(&entry.domain)
                        .map(|v| v.to_vec())
                        .unwrap_or_default();
                    let (merged, from_own) =
                        crate::domains::merged_addresses(&observed, Some(&entry));
                    serde_json::json!({
                        "domain": entry.domain,
                        "resolved_ips": merged.iter().map(|i| i.to_string())
                            .collect::<Vec<_>>(),
                        "resolved_by_us": from_own,
                        "status": entry.status(),
                        "settled": entry.settled(),
                        // Restored from the previous session's cache, not
                        // observed in this one. The UI marks these rows.
                        "archived": entry.archived,
                        "addresses": entry.addresses()
                            .iter()
                            .map(|a| a.to_string())
                            .collect::<Vec<_>>(),
                        "elapsed_ms": entry.elapsed_ms,
                    })
                })
                .collect();
            serde_json::json!({
                "process": t.name,
                "pid": t.pid,
                "domain_count": t.domains.len(),
                "records": t.records,
                "domains": rows,
            })
        })
        .collect();
    let s = session.domains.stats();
    emit_json(&serde_json::json!({
        "type": "domain_tables",
        "stats": {
            "unique_domains": s.unique_domains,
            "lookups_done": s.lookups_done,
            "found_aaaa": s.found_aaaa,
            "no_aaaa": s.no_aaaa,
            "no_such_name": s.no_such_name,
            "failed": s.failed,
            "retried": s.retried,
            "queue_dropped": s.queue_dropped,
            "requeries": s.requeries,
        },
        "tables": tables,
    }));
}

/// Write one row per (process, domain) with the AAAA result.
fn export_domains(session: &crate::app::Session, path: &std::path::Path) -> anyhow::Result<usize> {
    let rows = session.domains.all_rows();
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).ok();
        }
    }
    let is_json = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    if is_json {
        let out: Vec<serde_json::Value> = rows
            .iter()
            .map(|(process, domain, e)| {
                serde_json::json!({
                    "process": process,
                    "domain": domain,
                    "status": e.status(),
                    "settled": e.settled(),
                    "ipv6": e.addresses().iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                    "attempts": e.attempts,
                    "elapsed_ms": e.elapsed_ms,
                })
            })
            .collect();
        let f = std::fs::File::create(path)?;
        serde_json::to_writer_pretty(std::io::BufWriter::new(f), &out)?;
    } else {
        let f = std::fs::File::create(path)?;
        let mut w = csv::Writer::from_writer(std::io::BufWriter::new(f));
        w.write_record(["process", "domain", "status", "ipv6", "attempts", "elapsed_ms"])?;
        for (process, domain, e) in &rows {
            w.write_record([
                process.clone(),
                domain.clone(),
                e.status(),
                e.addresses()
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(";"),
                e.attempts.to_string(),
                e.elapsed_ms.to_string(),
            ])?;
        }
        w.flush()?;
    }
    Ok(rows.len())
}

/// Write one NDJSON object and flush immediately.
///
/// Flushing matters: the GUI reads this pipe line by line and would otherwise
/// sit behind a full pipe buffer, making the display look frozen under load.
fn emit_json(value: &serde_json::Value) {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    let _ = serde_json::to_writer(&mut out, value);
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

fn emit_log(json: bool, n: &crate::app::Note) {
    let level = match n.level {
        NoteLevel::Info => "info",
        NoteLevel::Warn => "warn",
        NoteLevel::Error => "error",
    };
    if json {
        emit_json(&serde_json::json!({ "type": "log", "level": level, "text": n.text }));
    } else {
        eprintln!("[{level}] {}", n.text);
    }
}

/// Live counters for the GUI status bar.
///
/// The CPU figure used to be sampled by the terminal event loop. That loop is
/// gone, so the sampling happens here: this is the only place that renders the
/// number, and sampling anywhere else would leave it frozen.
fn emit_status(session: &mut crate::app::Session, uptime_s: f64) {
    session.tick_cpu();
    let (records, queries, sni, domains, processes, filtered, rate) = {
        let s = session.store.lock().unwrap();
        (
            s.stats.total_records,
            s.stats.queries,
            s.stats.sni_observations,
            s.stats.unique_domain_count(),
            s.stats.unique_process_count(),
            s.stats.filtered_out_of_tree,
            s.stats.rate_per_sec(),
        )
    };
    let tree = session.tree.lock().unwrap().member_count();
    emit_json(&serde_json::json!({
        "type": "status",
        "uptime_s": (uptime_s * 10.0).round() / 10.0,
        "records": records,
        "queries": queries,
        "sni": sni,
        "domains": domains,
        "processes": processes,
        "tree_members": tree,
        "filtered_out_of_tree": filtered,
        "rate": (rate * 10.0).round() / 10.0,
        "cpu_percent": (session.cpu.percent * 100.0).round() / 100.0,
        "drops_kernel": session.kernel_dropped(),
        "drops_queue": session.queue_dropped(),
        "running": session.is_capturing(),
        // Which sources actually came up. Without this the GUI can only infer
        // it from log text, and a dead primary source looks exactly like a
        // quiet target.
        "etw": session.has_etw(),
        "npcap": session.has_pcap(),
        "domains_unique": session.domains.stats().unique_domains,
        "aaaa_found": session.domains.stats().found_aaaa,
        "aaaa_none": session.domains.stats().no_aaaa,
        "aaaa_failed": session.domains.stats().failed,
        "aaaa_pending": session
            .domains
            .stats()
            .unique_domains
            .saturating_sub(session.domains.stats().lookups_done),
    }));
}

// ---------------------------------------------------------------------------
// Doctor
// ---------------------------------------------------------------------------

fn doctor(cli: &Cli) -> ExitCode {
    println!("NetMonitor environment check");
    println!("=============================");
    println!("version        : {}", env!("CARGO_PKG_VERSION"));
    println!("executable     : {}", std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default());
    println!("windows        : {}", os_version());
    println!("elevated       : {}", if is_elevated() { "yes" } else { "NO -- ETW and Npcap need Administrator" });

    // --- ETW -------------------------------------------------------------
    let name = format!("NetMonitorDoctor-{}", std::process::id());
    match win::etw::EtwSession::start(&name, 64, 8, 64) {
        Ok(mut s) => {
            match s.enable(&win::etw::providers::DNS_CLIENT, 5, u64::MAX) {
                Ok(()) => println!("etw session    : OK (session '{name}', DNS-Client provider enabled)"),
                Err(e) => println!("etw provider   : FAILED to enable DNS-Client: {e}"),
            }
            s.stop();
        }
        Err(e) => println!("etw session    : FAILED to start: {e}"),
    }

    // --- Npcap -----------------------------------------------------------
    match pcap::Device::list() {
        Ok(devs) => {
            println!("npcap devices  : {}", devs.len());
            for d in devs.iter().take(12) {
                let addrs: Vec<String> = d
                    .addresses
                    .iter()
                    .map(|a| a.addr.to_string())
                    .filter(|a| a != "0.0.0.0" && a != "::")
                    .collect();
                println!(
                    "  - {:<28} {:<10} {}",
                    d.name,
                    if d.flags.is_loopback() { "loopback" } else { "live" },
                    d.desc.clone().unwrap_or_default()
                );
                if !addrs.is_empty() {
                    println!("      addresses: {}", addrs.join(", "));
                }
            }
            // Try a full open with the real filter, which is the thing that
            // actually has to work.
            let opts = cli.source_options();
            match capture::pcap_capture::PcapSource::start_probe(opts.include_loopback) {
                Ok((n, filter)) => println!("npcap capture  : OK on {n} interface(s), filter: {filter}"),
                Err(e) => println!("npcap capture  : FAILED: {e}"),
            }
        }
        Err(e) => println!("npcap devices  : FAILED to enumerate: {e}"),
    }

    println!();
    println!("If 'elevated' is NO, re-run from an Administrator terminal.");
    println!("If ETW fails, check that no policy blocks trace sessions");
    println!("(a user must be a member of the local 'Performance Log Users' group).");
    ExitCode::SUCCESS
}

fn os_version() -> String {
    // `RtlGetVersion` reports the real build even when the manifest lies.
    #[repr(C)]
    struct OsVersionInfoW {
        os_version_info_size: u32,
        major: u32,
        minor: u32,
        build: u32,
        platform: u32,
        csd_version: [u16; 128],
    }

    impl Default for OsVersionInfoW {
        fn default() -> Self {
            Self {
                os_version_info_size: 0,
                major: 0,
                minor: 0,
                build: 0,
                platform: 0,
                csd_version: [0; 128],
            }
        }
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(v: *mut OsVersionInfoW) -> i32;
    }
    let mut v = OsVersionInfoW {
        os_version_info_size: std::mem::size_of::<OsVersionInfoW>() as u32,
        ..Default::default()
    };
    let ok = unsafe { RtlGetVersion(&mut v) } == 0;
    if ok {
        format!("{}.{}.{}", v.major, v.minor, v.build)
    } else {
        "unknown".to_string()
    }
}

pub(crate) fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}
