use std::fs::{File, OpenOptions};
use ed25519_dalek::SigningKey;
use getopts::Options;
use time::macros::format_description;
use tracing_subscriber::{fmt, EnvFilter};

use yggdrasil::address::{addr_for_key, subnet_for_key};
use yggdrasil::admin::AdminSocket;
use yggdrasil::config::Config;
use yggdrasil::core::Core;
use yggdrasil::ipv6rwc::ReadWriteCloser;
use yggdrasil::tun::TunAdapter;

#[cfg(windows)]
mod service;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut opts = Options::new();
    opts.optflagopt("g", "genconf", "Generate a new configuration (optionally save to FILE)", "FILE");
    opts.optopt("c", "config", "Config file path (default: yggdrasil.toml)", "FILE");
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

    // Initialize links with core reference
    core.init_links().await;

    // Start listeners and connect to peers
    core.start().await;

    // Create IPv6 RWC bridge
    let mtu = core.mtu();
    let rwc = ReadWriteCloser::new(core.clone(), mtu);

    // Wire up path_notify: when ironwood discovers a new path, update the key store
    core.set_path_notify(rwc.clone());

    // Create TUN adapter
    let _tun = if config.if_name != "none" {
        let addr_str = core.address().to_string();
        let subnet_str = core.subnet().to_string();
        let tun_mtu = config.if_mtu.min(mtu).min(65535) as u16;

        match TunAdapter::new(
            &config.if_name,
            rwc.clone(),
            &addr_str,
            &subnet_str,
            tun_mtu,
        )
        .await
        {
            Ok(tun) => {
                tracing::info!("TUN adapter started");
                Some(tun)
            }
            Err(e) => {
                tracing::warn!("Failed to create TUN adapter: {}", e);
                None
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

    // Wait for shutdown signal
    tracing::info!("Yggdrasil NG started");
    shutdown_rx.changed().await.ok();
    tracing::info!("Shutting down...");

    // Cleanup
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
    println!("    list, getSelf, getPeers, getTree, getPaths, getSessions, getTUN");
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
