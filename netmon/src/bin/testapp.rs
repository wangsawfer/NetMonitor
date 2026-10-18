//! `testapp` -- a deterministic target used to verify NetMonitor end to end.
//!
//! It does three things that a real application does, in a way that is fully
//! reproducible:
//!
//! 1. resolves a list of names through the Windows resolver (`getaddrinfo`),
//!    which is what produces ETW `Microsoft-Windows-DNS-Client` events;
//! 2. optionally forks a copy of itself, so process-tree attribution of a child
//!    can be tested;
//! 3. optionally opens a TCP connection and emits a TLS ClientHello carrying a
//!    given SNI, so the packet-capture path can be tested without a real server.
//!
//! Usage:
//!   testapp [--child] [--fork [N]] [--sni HOST] [--sni-port N] [--hold SECS] DOMAIN...

use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut domains: Vec<String> = Vec::new();
    let mut is_child = false;
    let mut sni: Option<String> = None;
    let mut sni_port: u16 = 443;
    let mut hold: u64 = 0;
    let mut fork: usize = 0;
    let mut spawn: Option<String> = None;
    let mut spawn_extra: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--child" => {
                is_child = true;
                i += 1;
            }
            "--fork" => {
                // Bare `--fork` means one child; `--fork N` spawns N, which is
                // how the burst-load measurement in the test report was made.
                fork = args
                    .get(i + 1)
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(1);
                i += if args.get(i + 1).and_then(|v| v.parse::<usize>().ok()).is_some() {
                    2
                } else {
                    1
                };
            }
            // Give the spawned helper names of its own, so it is not served
            // from the DNS cache the parent just populated. Without this the
            // helper's queries are indistinguishable from "not captured" when
            // they were simply never issued.
            "--spawn-extra" if i + 1 < args.len() => {
                spawn_extra = Some(args[i + 1].clone());
                i += 2;
            }
            "--spawn" if i + 1 < args.len() => {
                // Launch a *differently named* child that resolves the same
                // names. This is how the real case looks: a main program that
                // hands downloads to a separate helper executable.
                spawn = Some(args[i + 1].clone());
                i += 2;
            }
            "--sni" if i + 1 < args.len() => {
                sni = Some(args[i + 1].clone());
                i += 2;
            }
            "--sni-port" if i + 1 < args.len() => {
                sni_port = args[i + 1].parse().unwrap_or(443);
                i += 2;
            }
            "--hold" if i + 1 < args.len() => {
                hold = args[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            other => {
                domains.push(other.to_string());
                i += 1;
            }
        }
    }

    println!(
        "testapp pid={} role={} domains={:?}",
        std::process::id(),
        if is_child { "child" } else { "parent" },
        domains
    );

    for d in &domains {
        // `getaddrinfo` -> the Windows DNS Client -> ETW event 3006 with *this*
        // process's PID. Failure is expected for intentionally bogus names and
        // is still a DNS query, which is exactly what we want to observe.
        match (d.as_str(), 0u16).to_socket_addrs() {
            Ok(it) => {
                let v4: Vec<String> = it
                    .filter(|a| a.is_ipv4())
                    .map(|a| a.ip().to_string())
                    .take(3)
                    .collect();
                println!("  resolved {d} -> {}", v4.join(", "));
            }
            Err(e) => println!("  {d} -> error: {e}"),
        }
        std::thread::sleep(Duration::from_millis(120));
    }

    if let Some(host) = &sni {
        emit_client_hello(host, sni_port);
    }

    if let Some(helper) = &spawn {
        if !is_child {
            let mut cmd = Command::new(helper);
            cmd.arg("--child");
            for d in &domains {
                cmd.arg(d);
            }
            let mut expect = domains.clone();
            if let Some(extra) = &spawn_extra {
                cmd.arg(extra);
                expect.push(extra.clone());
            }
            println!("  helper expects {expect:?}");
            cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
            match cmd.spawn() {
                Ok(mut c) => {
                    println!("  spawned helper {} as pid {}", helper, c.id());
                    let _ = c.wait();
                }
                Err(e) => eprintln!("  could not spawn helper {helper}: {e}"),
            }
        }
    }

    if fork > 0 && !is_child {
        // Spawn a copy of ourselves that resolves a different name. Its PID is
        // unknown to NetMonitor until the watcher sweeps, which is precisely
        // the case the "adopt unknown pid" path exists to handle.
        let exe = std::env::current_exe().expect("current_exe");
        let mut cmd = Command::new(exe);
        cmd.arg("--child")
            .args(&domains)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let mut children = Vec::with_capacity(fork);
        for _ in 0..fork {
            let c = cmd.spawn().expect("spawn child");
            println!("  child pid={}", c.id());
            children.push(c);
        }
        for c in children.iter_mut() {
            let _ = c.wait();
        }
    }

    if hold > 0 {
        std::thread::sleep(Duration::from_secs(hold));
    }
}

/// Open a TCP connection and write a minimal TLS ClientHello with `host` in the
/// `server_name` extension. Nothing is read back: the point is only to put a
/// parseable ClientHello on the wire.
fn emit_client_hello(host: &str, port: u16) {
    let addr = format!("{host}:{port}");
    let sock = match addr.to_socket_addrs().ok().and_then(|mut it| it.next()) {
        Some(a) => a,
        None => {
            println!("  sni: cannot resolve {addr}");
            return;
        }
    };
    let mut stream = match TcpStream::connect_timeout(&sock, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(e) => {
            println!("  sni: connect to {addr} failed: {e}");
            return;
        }
    };
    let hello = build_client_hello(host);
    match stream.write_all(&hello) {
        Ok(()) => println!("  sni: sent ClientHello for {host} ({} bytes)", hello.len()),
        Err(e) => println!("  sni: write failed: {e}"),
    }
    let _ = stream.flush();
}

fn build_client_hello(host: &str) -> Vec<u8> {
    let name = host.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0);
    sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(name);

    let mut exts = Vec::new();
    exts.extend_from_slice(&0u16.to_be_bytes()); // server_name
    exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_ext);
    // supported_versions so the hello looks modern
    exts.extend_from_slice(&43u16.to_be_bytes());
    exts.extend_from_slice(&3u16.to_be_bytes());
    exts.extend_from_slice(&[0x02, 0x03, 0x04]);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x5a; 32]); // random
    body.push(0); // session id
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut hs = vec![0x01];
    let l = body.len();
    hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    hs.extend_from_slice(&body);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}
