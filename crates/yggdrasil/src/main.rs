use std::fs::{File, OpenOptions};
use std::path::Path;
use ed25519_dalek::SigningKey;
use getopts::Options;
use time::macros::format_description;
use tracing_subscriber::{fmt, EnvFilter};

use yggdrasil::address::{addr_for_key, subnet_for_key};
use yggdrasil::admin::AdminSocket;
use yggdrasil::config::Config;
use yggdrasil::core::Core;
use yggdrasil::ipv6rwc::ReadWriteCloser;

#[cfg(feature = "tun")]
use yggdrasil::tun::TunAdapter;

#[cfg(windows)]
mod service;

/// Tokio worker threads for the daemon.
///
/// tokio defaults to one worker per core, which is counter-productive here: the
/// data path is a chain of small per-packet tasks, so spreading it over every
/// core buys nothing but a cross-thread wakeup per hop. Measured with two peered
/// daemons at MTU 1400 on a 32-core box (see `benchmarks/datapath-throughput`):
/// 32 workers cost 23.7 us of CPU per packet for 1218 Mbit/s, while 3 workers
/// cost 18.9 us for 1300 Mbit/s -- more throughput for less CPU. Dropping to 1
/// worker is cheaper still (10.4 us/pkt) but caps throughput at ~910 Mbit/s.
const WORKER_THREADS: usize = 3;

/// Build the daemon's tokio runtime. Used by both console and service mode.
fn build_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get().min(WORKER_THREADS))
        .unwrap_or(1);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    build_runtime()?.block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut opts = Options::new();
    opts.optflagopt("g", "genconf", "Generate a new configuration (optionally save to FILE)", "FILE");
    opts.optflagopt("", "normalize", "Normalize a config: read from FILE (or stdin if absent), add any missing fields with defaults while preserving user values and comments, and print to stdout", "FILE");
    opts.optopt("c", "config", "Config file path (default: yggdrasil.toml, then system path)", "FILE");
    opts.optflag("", "autoconf", "Run without a configuration file (use ephemeral keys)");
    opts.optflag("a", "address", "Print the IPv6 address for the given config and exit");
    opts.optflag("s", "subnet", "Print the IPv6 subnet for the given config and exit");
    opts.optopt("l", "loglevel", "Log level: error, warn, info, debug, trace (default: info)", "LEVEL");
    opts.optflag("n", "no-replace", "With --genconf FILE, skip if the file already exists");
    opts.optopt("", "logto", "Log to a file instead of stderr", "FILE");
    #[cfg(feature = "ctl")]
    opts.optopt("e", "endpoint", "Admin socket address (default: tcp://localhost:9001)", "URI");
    #[cfg(feature = "ctl")]
    opts.optflag("j", "json", "Output control command results as raw JSON");
    #[cfg(windows)]
    opts.optflag("", "service", "Run as a Windows service (launched by the Service Control Manager)");
    opts.optflag("h", "help", "Print this help");
    opts.optflag("v", "version", "Print version");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("{}", opts.usage(&usage_string()));
            std::process::exit(1);
        }
    };

    if matches.opt_present("help") {
        println!("{}", opts.usage(&usage_string()));
        #[cfg(feature = "ctl")]
        print_ctl_commands();
        return Ok(());
    }

    if matches.opt_present("version") {
        println!("yggdrasil {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Resolve prefix/port early from binary/symlink/hardlink name suffix
    // so --address / --subnet and control-mode endpoint see the correct values.
    // Config mutation and the info message happen later (after logging is ready).
    if let Some((prefix, port)) = resolve_prefix_port() {
        yggdrasil::address::set_address_prefix(prefix);
        yggdrasil::multicast::set_multicast_port(port);
    }

    // If there are free (positional) arguments, treat as a control command
    #[cfg(feature = "ctl")]
    if !matches.free.is_empty() {
        let endpoint = matches.opt_str("endpoint")
            .unwrap_or_else(|| format!("tcp://localhost:{}", yggdrasil::multicast::multicast_port()));
        let json_output = matches.opt_present("json");
        let command = matches.free[0].clone();

        // Parse key=value arguments
        let mut arguments = serde_json::Map::new();
        for arg in &matches.free[1..] {
            if let Some((k, v)) = arg.split_once('=') {
                arguments.insert(k.to_string(), serde_json::Value::String(v.to_string()));
            }
        }

        return yggdrasil::ctl::run_ctl(&endpoint, json_output, &command, arguments).await;
    }

    // --service: run as Windows service
    #[cfg(windows)]
    if matches.opt_present("service") {
        return service::run_as_service();
    }

    let config_path = resolve_config_path(&matches);
    let autoconf = matches.opt_present("autoconf");
    let address = matches.opt_present("address");
    let subnet = matches.opt_present("subnet");
    let loglevel = matches.opt_str("loglevel").unwrap_or_else(|| "info".to_string());
    let logto = matches.opt_str("logto");

    // --genconf [FILE]: generate config, save to file or print to stdout
    if matches.opt_present("genconf") {
        if let Some(path) = matches.opt_str("genconf") {
            if matches.opt_present("no-replace") && std::path::Path::new(&path).exists() {
                eprintln!("Configuration file {} already exists, skipping", path);
                return Ok(());
            }
            let text = Config::generate_config_text();
            std::fs::write(&path, &text)?;
            eprintln!("Configuration saved to {}", path);
        } else {
            print!("{}", Config::generate_config_text());
        }
        return Ok(());
    }

    // --normalize [FILE]: read existing config (file or stdin), splice in
    // any new fields with their template comments, print to stdout.
    if matches.opt_present("normalize") {
        use std::io::Read;
        let mut buf = String::new();
        match matches.opt_str("normalize") {
            Some(path) if path != "-" => {
                File::open(&path)?.read_to_string(&mut buf)?;
            }
            _ => {
                std::io::stdin().read_to_string(&mut buf)?;
            }
        }
        match Config::normalize_config_text(&buf) {
            Ok(out) => {
                print!("{}", out);
                if !out.ends_with('\n') {
                    println!();
                }
                return Ok(());
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Initialize logging
    init_logging(&loglevel, logto.as_deref());

    // Load config
    let config = if autoconf {
        Config::default()
    } else if !config_path.is_empty() {
        let file = File::open(&config_path)?;
        let config = std::io::read_to_string(file)?;
        toml::from_str::<Config>(&config)?
    } else {
        tracing::error!("Please specify --genconf, --config, or --autoconf");
        std::process::exit(1);
    };

    // Parse or generate signing key
    // Priority: config file > YGGDRASIL_PRIVATE_KEY env var > ephemeral
    let signing_key = if !config.private_key.is_empty() {
        config
            .signing_key()
            .map_err(|e| format!("invalid private key: {}", e))?
    } else if let Ok(env_key) = std::env::var("YGGDRASIL_PRIVATE_KEY") {
        tracing::info!("Using private key from YGGDRASIL_PRIVATE_KEY environment variable");
        let bytes = hex::decode(&env_key)
            .map_err(|e| format!("invalid YGGDRASIL_PRIVATE_KEY hex: {}", e))?;
        let key_bytes: [u8; 64] = bytes.try_into()
            .map_err(|v: Vec<u8>| format!("YGGDRASIL_PRIVATE_KEY should be 64 bytes, got {}", v.len()))?;
        SigningKey::from_keypair_bytes(&key_bytes)
            .map_err(|e| format!("invalid YGGDRASIL_PRIVATE_KEY: {}", e))?
    } else {
        tracing::warn!("No private key configured, generating ephemeral key");
        SigningKey::generate(&mut rand::rngs::OsRng)
    };

    let public_key = signing_key.verifying_key().to_bytes();

    // --address: print address and exit
    if address {
        let addr = addr_for_key(&public_key);
        println!("{}", addr);
        return Ok(());
    }

    // --subnet: print subnet and exit
    if subnet {
        let subnet = subnet_for_key(&public_key);
        println!("{}", subnet);
        return Ok(());
    }

    // Console mode: Ctrl+C triggers shutdown
    let (watch_tx, watch_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = watch_tx.send(true);
    });

    run_node(watch_rx).await
}

/// Run the Yggdrasil node, blocking until the shutdown signal fires.
/// Called from both console mode (Ctrl+C) and Windows service mode (SCM stop).
async fn run_node(
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error>> {
    // When called from service mode, logging + config aren't set up yet.
    // Re-read CLI args to get config path / autoconf / loglevel.
    let args: Vec<String> = std::env::args().collect();
    let mut opts = Options::new();
    opts.optopt("c", "config", "", "FILE");
    opts.optflag("", "autoconf", "");
    opts.optopt("l", "loglevel", "", "LEVEL");
    opts.optopt("", "logto", "", "FILE");
    // Accept (and ignore) the rest so parsing doesn't fail
    opts.optflagopt("g", "genconf", "", "FILE");
    opts.optflag("a", "address", "");
    opts.optflag("s", "subnet", "");
    opts.optflag("n", "no-replace", "");
    opts.optflag("h", "help", "");
    opts.optflag("v", "version", "");
    #[cfg(feature = "ctl")]
    opts.optopt("e", "endpoint", "", "URI");
    #[cfg(feature = "ctl")]
    opts.optflag("j", "json", "");
    #[cfg(windows)]
    opts.optflag("", "service", "");

    let matches = opts.parse(&args[1..]).unwrap_or_else(|_| {
        // Fallback: empty matches
        opts.parse(Vec::<String>::new()).unwrap()
    });

    let config_path = resolve_config_path(&matches);
    let autoconf = matches.opt_present("autoconf");
    let loglevel = matches.opt_str("loglevel").unwrap_or_else(|| "info".to_string());
    let logto = matches.opt_str("logto");

    // Initialize logging (idempotent — if already initialized in console mode, this is a no-op)
    init_logging(&loglevel, logto.as_deref());

    // Load config
    let mut config = if autoconf {
        Config::default()
    } else if !config_path.is_empty() {
        let file = File::open(&config_path)?;
        let text = std::io::read_to_string(file)?;
        toml::from_str::<Config>(&text)?
    } else {
        return Err("No configuration: specify --config or --autoconf".into());
    };

    if let Some((prefix, port)) = resolve_prefix_port() {
        apply_prefix_port(prefix, port, &mut config);
    }

    // Parse or generate signing key
    let signing_key = if !config.private_key.is_empty() {
        config
            .signing_key()
            .map_err(|e| format!("invalid private key: {}", e))?
    } else if let Ok(env_key) = std::env::var("YGGDRASIL_PRIVATE_KEY") {
        tracing::info!("Using private key from YGGDRASIL_PRIVATE_KEY environment variable");
        let bytes = hex::decode(&env_key)
            .map_err(|e| format!("invalid YGGDRASIL_PRIVATE_KEY hex: {}", e))?;
        let key_bytes: [u8; 64] = bytes.try_into()
            .map_err(|v: Vec<u8>| format!("YGGDRASIL_PRIVATE_KEY should be 64 bytes, got {}", v.len()))?;
        SigningKey::from_keypair_bytes(&key_bytes)
            .map_err(|e| format!("invalid YGGDRASIL_PRIVATE_KEY: {}", e))?
    } else {
        tracing::warn!("No private key configured, generating ephemeral key");
        SigningKey::generate(&mut rand::rngs::OsRng)
    };

    // Create core
    let core = Core::new(signing_key, config.clone());
    tracing::info!("Your IPv6 address is {}", core.address());
    tracing::info!("Your IPv6 subnet is {}", core.subnet());
    tracing::info!("Your public key is {}", hex::encode(core.public_key()));
    tracing::info!("Salsa20 backend: {}", salsa20::active_backend());

    // Initialize links with core reference
    core.init_links().await;

    // Start listeners and connect to peers
    core.start().await;

    // Construct firewall (if enabled). Default-off; existing setups are untouched.
    let firewall = if config.firewall.enable {
        match yggdrasil::firewall::Firewall::new(&config.firewall) {
            Ok(fw) => {
                let fw = std::sync::Arc::new(fw);
                fw.spawn_gc();
                tracing::info!(
                    "Firewall enabled: {} TCP open, {} UDP open, {} bypass subnets, icmp_echo={}",
                    config.firewall.open_tcp.len(),
                    config.firewall.open_udp.len(),
                    config.firewall.open_all_for.len(),
                    config.firewall.allow_icmp_echo
                );
                Some(fw)
            }
            Err(e) => {
                tracing::error!("Firewall configuration error: {}", e);
                return Err(e.into());
            }
        }
    } else {
        None
    };

    // Create IPv6 RWC bridge
    let mtu = core.mtu();
    let rwc = ReadWriteCloser::new(
        core.clone(),
        mtu,
        #[cfg(feature = "ckr")]
        Some(&config.tunnel_routing),
        firewall,
    );

    // Wire up path_notify: when ironwood discovers a new path, update the key store
    core.set_path_notify(rwc.clone());

    // Seed the key store with the keys of directly-connected peers. We authenticated
    // those keys during the link handshake, so their address/subnet mapping is already
    // derivable locally -- no reason to buffer the first packet and wait for a lookup
    // to tell us what we know. Combined with the router's direct-peer shortcut this
    // takes the first packet to a direct peer from three round trips down to two
    // (the remaining one being the session Init/Ack).
    //
    // Re-run on a timer rather than hooking link setup: it picks up peers that connect
    // later, survives reconnects, and refreshes `last_seen` so entries can't age out
    // while the peer is up. `update_key` returns early for entries that are still
    // fresh, so a tick over an unchanged peer set is a couple of hashmap lookups.
    let seed_core = core.clone();
    let seed_rwc = rwc.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            ticker.tick().await;
            for key in seed_core.get_peer_keys().await {
                seed_rwc.update_key(key).await;
            }
        }
    });

    // Create TUN adapter
    #[cfg(feature = "tun")]
    let mut tun = if config.if_name != "none" {
        let addr_str = core.address().to_string();
        let subnet_str = core.subnet().to_string();
        let tun_mtu = config.if_mtu.min(mtu).min(65535) as u16;

        match TunAdapter::new(
            &config.if_name,
            rwc.clone(),
            &addr_str,
            &subnet_str,
            tun_mtu,
            #[cfg(windows)]
            &config.if_dns_servers,
            #[cfg(feature = "ckr")]
            Some(&config.tunnel_routing),
            #[cfg(feature = "ckr")]
            core.public_key(),
        ).await {
            Ok(tun) => {
                tracing::info!("TUN adapter started");
                core.set_tun_info(tun.name(), tun.mtu() as u64);
                Some(tun)
            }
            Err(e) => {
                // A TUN was requested (if_name != "none") but could not be
                // created. Fail loudly rather than continuing in a degraded,
                // TUN-less state: under systemd Type=notify this surfaces as a
                // failed start (then Restart=always retries) instead of a
                // silently broken node that still reports "ready".
                tracing::error!("Failed to create TUN adapter: {}", e);
                return Err(e.into());
            }
        }
    } else {
        tracing::info!("TUN adapter disabled");
        None
    };

    // Start admin socket
    let admin = match AdminSocket::new(&config.admin_listen, core.clone()).await {
        Ok(admin) => Some(admin),
        Err(e) => {
            tracing::warn!("Failed to start admin socket: {}", e);
            None
        }
    };

    // Start multicast peer discovery
    if let Err(e) = core.start_multicast().await {
        tracing::warn!("Multicast peer discovery disabled: {}", e);
    }

    // Wait for shutdown signal
    tracing::info!("Yggdrasil NG started");

    // Tell systemd we're ready (Type=notify). By this point the TUN interface
    // (if any) has been created and the admin socket/multicast started, so
    // ExecStartPost hooks that touch the interface can rely on it existing.
    // This is a no-op when not running under systemd (NOTIFY_SOCKET unset).
    #[cfg(all(feature = "systemd", target_os = "linux"))]
    {
        if let Err(e) = sd_notify::notify(&[sd_notify::NotifyState::Ready]) {
            tracing::warn!("Failed to notify systemd of readiness: {}", e);
        }
    }

    shutdown_rx.changed().await.ok();
    tracing::info!("Shutting down...");

    // Cleanup
    // Remove CKR routes before TUN is destroyed (critical on Windows where
    // routes don't auto-dissolve when the interface goes away).
    // Use the name the adapter got, not a second derivation of if_name.
    #[cfg(all(feature = "ckr", feature = "tun"))]
    if config.tunnel_routing.enable {
        if let Some(adapter) = tun.as_ref() {
            yggdrasil::ckr::remove_routes(
                &config.tunnel_routing,
                adapter.name(),
                core.public_key(),
            );
        }
    }

    // Tear down TUN explicitly so the OS interface is removed before this
    // function returns. Dropping TunAdapter alone is not enough: its tokio
    // tasks each hold an Arc<AsyncDevice>, and dropping a JoinHandle does
    // not abort the task — it only detaches it. Without an explicit close
    // we'd rely on the runtime drop to abort the tasks, which is too late
    // in Windows service mode (the SCM may kill the process after we report
    // Stopped, leaving an orphaned Wintun adapter).
    //
    // This happens before core.close() on purpose: the TUN write loop parks
    // in rwc.read(), so closing the core first pulls the RWC out from under
    // it and every clean shutdown logs a spurious "RWC read error".
    #[cfg(feature = "tun")]
    if let Some(t) = tun.take() {
        t.close().await;
    }

    core.close_multicast().await;
    if let Some(admin) = &admin {
        admin.close();
    }
    core.close().await.ok();

    tracing::info!("Goodbye!");
    Ok(())
}

fn init_logging(loglevel: &str, logto: Option<&str>) {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let filter = EnvFilter::try_new(loglevel)
            .unwrap_or_else(|_| EnvFilter::new("info"));
        let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]");
        let timer = fmt::time::LocalTime::new(format);

        // When running under systemd, the journal already provides timestamps.
        let under_systemd = std::env::var_os("JOURNAL_STREAM").is_some();

        if let Some(path) = logto {
            // Log files always get timestamps
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap_or_else(|e| {
                    eprintln!("Failed to open log file {}: {}", path, e);
                    std::process::exit(1);
                });
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_target(true)
                .with_level(true)
                .with_timer(timer)
                .with_writer(file)
                .init();
        } else if under_systemd {
            // Under systemd: skip timestamps, journal adds them
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_target(true)
                .with_level(true)
                .without_time()
                .init();
        } else {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_target(true)
                .with_level(true)
                .with_timer(timer)
                .init();
        }
    });
}

fn usage_string() -> String {
    #[cfg(feature = "ctl")]
    return "Usage: yggdrasil [options] [command [key=value ...]]".to_string();
    #[cfg(not(feature = "ctl"))]
    return "Usage: yggdrasil [options]".to_string();
}

#[cfg(feature = "ctl")]
fn print_ctl_commands() {
    println!("Commands (control mode):");
    println!("  Local queries:");
    println!("    list, getSelf, getPeers, getTree, getPaths, getSessions, getTUN, getMulticastInterfaces");
    println!("  Debug:");
    println!("    getDebug  (routing stats: tree size, broken paths, queue depth, etc.)");
    println!("  Peer management:");
    println!("    addPeer uri=<URI>, removePeer uri=<URI>");
    println!("  Remote queries:");
    println!("    getNodeInfo key=<hex>, debug_remoteGetSelf key=<hex>");
    println!("    debug_remoteGetPeers key=<hex>, debug_remoteGetTree key=<hex>");
    println!("  Path diagnostics:");
    println!("    getLookup key=<hex>, forceLookup key=<hex>");
}

/// Parse a prefix-port value according to the required format.
/// Used for the suffix after the last '_' in the binary/symlink/hardlink name.
/// Returns (prefix_u8, port_u16) on success, None on failure.
fn parse_prefix_port(s: &str) -> Option<(u8, u16)> {
    // Manual implementation of the given regex (no extra dependency).
    if s.len() < 6 {
        return None;
    }
    let bytes = s.as_bytes();
    // First two characters must be a valid prefix from the allowed set
    let p0 = bytes[0] as char;
    let p1 = bytes[1] as char;
    let valid_prefix = matches!(
        (p0, p1),
        ('0', '2' | '4' | '6' | '8' | 'a' | 'c' | 'e' | 'A' | 'C' | 'E')
            | ('1'..='9' | 'a'..='e' | 'A'..='E', '0' | '2' | '4' | '6' | '8' | 'a' | 'c' | 'e' | 'A' | 'C' | 'E')
            | ('f' | 'F', '0' | '2' | '4' | '6' | '8' | 'a' | 'c' | 'A' | 'C')
    );
    if !valid_prefix {
        return None;
    }
    let prefix = u8::from_str_radix(&s[..2], 16).ok()?;

    // Optional separator: any char that is not space and not hex digit
    let rest = &s[2..];
    let numeric_start = if rest.is_empty() {
        return None;
    } else if rest.as_bytes()[0].is_ascii_hexdigit() {
        0
    } else if rest.as_bytes()[0] != b' ' {
        1
    } else {
        return None;
    };
    let num_str: String = rest[numeric_start..]
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    if num_str.is_empty() {
        return None;
    }
    let port: u16 = num_str.parse().ok()?;
    if !(1024..=65535).contains(&port) {
        return None;
    }
    Some((prefix, port))
}

fn apply_prefix_port(prefix: u8, port: u16, config: &mut Config) {
    yggdrasil::address::set_address_prefix(prefix);
    yggdrasil::multicast::set_multicast_port(port);

    tracing::info!(
        "Using address prefix 0x{:02x} and port {}",
        prefix, port
    );

    // Override admin_listen only when it still has the default value
    // (i.e. was absent/commented in the config file).
    if config.admin_listen == "tcp://localhost:9001" {
        config.admin_listen = format!("tcp://localhost:{}", port);
    }

    // Override if_name only when it is the default "auto"
    // (absent/commented in config). macOS is left as "auto".
    if config.if_name == "auto" {
        let suffix = format!("{:02x}{}", prefix, port);
        if cfg!(windows) {
            config.if_name = format!("Yggdrasil{}", suffix);
        } else if !cfg!(target_os = "macos") {
            // Linux / BSD: strip the trailing "0" from "ygg0"
            config.if_name = format!("ygg{}", suffix);
        }
        // macOS: keep "auto" — kernel assigns utunN
    }
}

/// Return the basename of the program as invoked (argv[0]).
/// Works for renamed binaries, symlinks and hardlinks.
fn program_basename() -> String {
    std::env::args()
        .next()
        .map(|a| {
            Path::new(&a)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&a)
                .to_string()
        })
        .unwrap_or_default()
}

/// Extract prefix and port from the binary/symlink/hardlink name.
/// The last '_' in the name is the marker; everything after it is parsed
/// with parse_prefix_port (e.g. "029001", "02-9001", "02.9001.exe").
fn prefix_port_from_name(name: &str) -> Option<(u8, u16)> {
    let idx = name.rfind('_')?;
    let suffix = &name[idx + 1..];
    parse_prefix_port(suffix)
}

/// Resolve the configuration file path.
///
/// When `--config` / `-c` is not given:
/// 1. Determine the config filename:
///    - If the binary/symlink/hardlink name contains a recognised prefix+port
///      suffix (via `prefix_port_from_name`), use `<stem>.toml`
///      (stem = filename without extension, e.g. `ygg_029001.exe` → `ygg_029001.toml`).
///    - Otherwise fall back to the historic default `yggdrasil.toml`.
/// 2. Try that filename in the current working directory.
/// 3. If absent, try the OS-specific system directory with the same filename:
///    - Unix-like (Linux except Android, BSD, macOS, …): `/etc/yggdrasil/<filename>`
///    - Windows: `<ProgramData>\Yggdrasil-ng\<filename>`, where ProgramData is
///      obtained via SHGetKnownFolderPath(FOLDERID_ProgramData)
/// 4. If still not found, return the filename so that the subsequent
///    `File::open` produces the same style of error message as before.
fn resolve_config_path(matches: &getopts::Matches) -> String {
    if let Some(path) = matches.opt_str("config") {
        return path;
    }

    // Compute the config filename based on the binary name (if prefix/port recognised)
    let name = program_basename();
    let local = if prefix_port_from_name(&name).is_some() {
        let stem = Path::new(&name)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(&name);
        format!("{}.toml", stem)
    } else {
        "yggdrasil.toml".to_string()
    };

    if Path::new(&local).exists() {
        return local;
    }

    #[cfg(all(unix, not(target_os = "android")))]
    {
        let system = format!("/etc/yggdrasil/{}", local);
        if Path::new(&system).exists() {
            return system;
        }
    }

    #[cfg(windows)]
    {
        if let Some(program_data) = windows_program_data_dir() {
            let system = program_data.join("Yggdrasil-ng").join(&local);
            if system.exists() {
                return system.to_string_lossy().into_owned();
            }
        }
    }

    // File not found anywhere — return the computed filename so open() fails
    // with the same style of error message as before.
    local
}

/// Return the real ProgramData directory via SHGetKnownFolderPath(FOLDERID_ProgramData).
/// Returns None if the API call fails (no fallback to a hardcoded path).
#[cfg(windows)]
fn windows_program_data_dir() -> Option<std::path::PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_ProgramData, KNOWN_FOLDER_FLAG, SHGetKnownFolderPath};

    unsafe {
        let pwstr = SHGetKnownFolderPath(
            &FOLDERID_ProgramData,
            KNOWN_FOLDER_FLAG(0),
            None,
        )
        .ok()?;
        // PWSTR is a null-terminated wide string allocated by CoTaskMemAlloc.
        let wide = pwstr.as_wide();
        let path = std::path::PathBuf::from(OsString::from_wide(wide));
        CoTaskMemFree(Some(pwstr.0 as _));
        Some(path)
    }
}

/// Resolve (prefix, port) from the binary/symlink/hardlink name.
/// Valid suffix after the last '_' is used; otherwise None (keep defaults).
fn resolve_prefix_port() -> Option<(u8, u16)> {
    prefix_port_from_name(&program_basename())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_prefix_port_existing_cases() {
        assert_eq!(parse_prefix_port("02:9001"), Some((0x02, 9001)));
        assert_eq!(parse_prefix_port("02-9001"), Some((0x02, 9001)));
        assert_eq!(parse_prefix_port("029001"), Some((0x02, 9001)));
        assert_eq!(parse_prefix_port("fc.65535"), Some((0xfc, 65535)));
        assert_eq!(parse_prefix_port("02"), None);
        assert_eq!(parse_prefix_port("02:1023"), None); // port too low
        assert_eq!(parse_prefix_port("gg:9001"), None); // invalid prefix
    }

    #[test]
    fn test_prefix_port_from_name() {
        assert_eq!(prefix_port_from_name("yggdrasil_029001"), Some((0x02, 9001)));
        assert_eq!(prefix_port_from_name("yggdrasil_02-9001"), Some((0x02, 9001)));
        assert_eq!(prefix_port_from_name("yggdrasil_02.9001"), Some((0x02, 9001)));
        assert_eq!(prefix_port_from_name("yggdrasil_02-9001.exe"), Some((0x02, 9001)));
        assert_eq!(prefix_port_from_name("Yggdrasil_0a.12345"), Some((0x0a, 12345)));
        assert_eq!(prefix_port_from_name("yggdrasil"), None);
        assert_eq!(prefix_port_from_name("yggdrasil_"), None);
        assert_eq!(prefix_port_from_name("yggdrasil_foo"), None);
        assert_eq!(prefix_port_from_name("yggdrasil_02"), None);
        assert_eq!(prefix_port_from_name("yggdrasil_02-999"), None); // port < 1024
        // last '_' is the marker
        assert_eq!(prefix_port_from_name("my_ygg_02-9001"), Some((0x02, 9001)));
    }
}