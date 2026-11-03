use std::fs::{File, OpenOptions};
use ed25519_dalek::SigningKey;
use getopts::Options;
use time::macros::format_description;
use tracing_subscriber::{fmt, EnvFilter};

use yggdrasil::address::{addr_for_key, subnet_for_key};
use yggdrasil::config::Config;
use yggdrasil::node::NodeBuilder;

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
    opts.optopt("c", "config", "Config file path (default: yggdrasil.toml)", "FILE");
    opts.optflag("", "autoconf", "Run without a configuration file (use ephemeral keys)");
    opts.optflag("a", "address", "Print the IPv6 address for the given config and exit");
    opts.optflag("s", "subnet", "Print the IPv6 subnet for the given config and exit");
    opts.optopt("l", "loglevel", "Log level: error, warn, info, debug, trace (default: info)", "LEVEL");
    opts.optflag("n", "no-replace", "With --genconf FILE, skip if the file already exists");
    opts.optopt("", "logto", "Log to a file instead of stderr", "FILE");
    opts.optmulti("p", "peer", "Peer URI to connect to on startup (repeatable)", "URI");
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

    // If there are free (positional) arguments, treat as a control command
    #[cfg(feature = "ctl")]
    if !matches.free.is_empty() {
        let endpoint = matches.opt_str("endpoint")
            .unwrap_or_else(|| "tcp://localhost:9001".to_string());
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

    let config_path = matches.opt_str("config").unwrap_or_else(|| "yggdrasil.toml".to_string());
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

    let signing_key = load_signing_key(&config)?;

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
    // Accept (and collect) -p/--peer so startup peers can be merged into config.peers.
    opts.optmulti("p", "peer", "", "URI");
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

    let config_path = matches.opt_str("config").unwrap_or_else(|| "yggdrasil.toml".to_string());
    let autoconf = matches.opt_present("autoconf");
    let loglevel = matches.opt_str("loglevel").unwrap_or_else(|| "info".to_string());
    let logto = matches.opt_str("logto");

    // Initialize logging (idempotent — if already initialized in console mode, this is a no-op)
    init_logging(&loglevel, logto.as_deref());

    // Load config
    let config = if autoconf {
        Config::default()
    } else if !config_path.is_empty() {
        let file = File::open(&config_path)?;
        let text = std::io::read_to_string(file)?;
        toml::from_str::<Config>(&text)?
    } else {
        return Err("No configuration: specify --config or --autoconf".into());
    };

    let signing_key = load_signing_key(&config)?;

    // Merge CLI-provided peers (-p/--peer) into a clone of config so the node connects
    // to them on startup (deduped against configured entries).
    let mut config = config;
    for uri in matches.opt_strs("p") {
        if !config.peers.contains(&uri) {
            config.peers.push(uri);
        }
    }

    let node = NodeBuilder::new(config)
        .signing_key(signing_key)
        .start()
        .await
        .inspect_err(|e| tracing::error!("{}", e))?;

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

    // Wait for shutdown signal
    shutdown_rx.changed().await.ok();
    tracing::info!("Shutting down...");
    node.close().await;

    tracing::info!("Goodbye!");
    Ok(())
}

/// Resolve the node's signing key.
/// Priority: config file > YGGDRASIL_PRIVATE_KEY env var > ephemeral.
fn load_signing_key(config: &Config) -> Result<SigningKey, Box<dyn std::error::Error>> {
    if !config.private_key.is_empty() {
        return Ok(config
            .signing_key()
            .map_err(|e| format!("invalid private key: {}", e))?);
    }
    if let Ok(env_key) = std::env::var("YGGDRASIL_PRIVATE_KEY") {
        tracing::info!("Using private key from YGGDRASIL_PRIVATE_KEY environment variable");
        let bytes = hex::decode(&env_key)
            .map_err(|e| format!("invalid YGGDRASIL_PRIVATE_KEY hex: {}", e))?;
        let key_bytes: [u8; 64] = bytes.try_into()
            .map_err(|v: Vec<u8>| format!("YGGDRASIL_PRIVATE_KEY should be 64 bytes, got {}", v.len()))?;
        let key = SigningKey::from_keypair_bytes(&key_bytes)
            .map_err(|e| format!("invalid YGGDRASIL_PRIVATE_KEY: {}", e))?;
        if !ironwood::is_public_key_valid(&key.verifying_key().to_bytes()) {
            return Err("invalid YGGDRASIL_PRIVATE_KEY: public key is a low-order point".into());
        }
        return Ok(key);
    }
    tracing::warn!("No private key configured, generating ephemeral key");
    Ok(SigningKey::generate(&mut rand::rngs::OsRng))
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
