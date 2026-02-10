use std::fs::File;
use clap::Parser;
use ed25519_dalek::SigningKey;
use time::macros::format_description;
use tracing_subscriber::{fmt, EnvFilter};

use yggdrasil::address::{addr_for_key, subnet_for_key};
use yggdrasil::admin::AdminSocket;
use yggdrasil::config::Config;
use yggdrasil::core::Core;
use yggdrasil::ipv6rwc::ReadWriteCloser;
use yggdrasil::tun::TunAdapter;

#[derive(Parser, Debug)]
#[command(name = "yggdrasil", version, about = "Yggdrasil mesh network daemon")]
struct Args {
    /// Generate a new configuration and print to stdout
    #[arg(long)]
    genconf: bool,

    /// Read configuration from stdin
    #[arg(long)]
    useconf: bool,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, default_value = "config.json")]
    useconffile: String,

    /// Run without a configuration file (generate ephemeral keys)
    #[arg(long)]
    autoconf: bool,

    /// Print the IPv6 address for the given config and exit
    #[arg(short, long)]
    address: bool,

    /// Print the IPv6 subnet for the given config and exit
    #[arg(short, long)]
    subnet: bool,

    /// Log level (error, warn, info, debug, trace)
    #[arg(short, long, default_value = "info")]
    loglevel: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // --genconf: generate and print config
    if args.genconf {
        let config = Config::generate();
        println!("{}", serde_json::to_string_pretty(&config)?);
        return Ok(());
    }

    // Initialize logging
    let filter = EnvFilter::try_new(&args.loglevel)
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]");
    let timer = fmt::time::LocalTime::new(format);
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false) // disables ANSI escape codes
        .with_target(true)
        .with_level(true)
        .with_timer(timer)
        .init();

    // Load config
    let config = if args.useconf {
        let stdin = std::io::read_to_string(std::io::stdin())?;
        serde_json::from_str::<Config>(&stdin)?
    } else if args.autoconf {
        Config::generate()
    } else if !args.useconffile.is_empty() {
        let file = File::open(&args.useconffile)?;
        let config = std::io::read_to_string(file)?;
        serde_json::from_str::<Config>(&config)?
    } else {
        tracing::error!("Please specify --genconf, --useconf, or --autoconf");
        std::process::exit(1);
    };

    // Parse or generate signing key
    let signing_key = if config.private_key.is_empty() {
        tracing::warn!("No private key configured, generating ephemeral key");
        SigningKey::generate(&mut rand::rngs::OsRng)
    } else {
        config
            .signing_key()
            .map_err(|e| format!("invalid private key: {}", e))?
    };

    let public_key = signing_key.verifying_key().to_bytes();

    // --address: print address and exit
    if args.address {
        let addr = addr_for_key(&public_key);
        println!("{}", addr);
        return Ok(());
    }

    // --subnet: print subnet and exit
    if args.subnet {
        let subnet = subnet_for_key(&public_key);
        println!("{}", subnet);
        return Ok(());
    }

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
    let _admin = match AdminSocket::new(&config.admin_listen, core.clone()).await {
        Ok(admin) => Some(admin),
        Err(e) => {
            tracing::warn!("Failed to start admin socket: {}", e);
            None
        }
    };

    // Wait for shutdown signal
    tracing::info!("Yggdrasil started. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down...");

    // Cleanup
    if let Some(admin) = &_admin {
        admin.close();
    }
    core.close().await.ok();

    tracing::info!("Goodbye!");
    Ok(())
}
