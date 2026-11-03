//! Runs an embedded Yggdrasil node without TUN and exposes it to other
//! applications through a SOCKS5 proxy and TCP/UDP port forwards.

use std::net::SocketAddr;
use std::process::ExitCode;

use getopts::Options;
use tokio::task::JoinSet;
use tracing_subscriber::EnvFilter;
use yggdrasil::config::Config;
use yggdrasil::node::NodeBuilder;
use yggdrasil_stack::proxy::{
    forward_local_tcp, forward_local_udp, forward_remote_tcp, forward_remote_udp, Socks5Server,
};
use yggdrasil_stack::{Target, YggStack};

type Error = Box<dyn std::error::Error>;

const USAGE: &str = "Usage: yggdrasil-proxy [options]

Forwards (repeatable):
  --local-tcp  127.0.0.1:8080=[200:1234::1]:80    host listener -> Yggdrasil target
  --local-udp  127.0.0.1:5353=<key>.pk.ygg:53     host socket   -> Yggdrasil target
  --remote-tcp 80=127.0.0.1:8080                  Yggdrasil port -> host target
  --remote-udp 53=127.0.0.1:53                    Yggdrasil port -> host target
Yggdrasil targets are [address]:port or <hex public key>.pk.ygg:port.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut opts = Options::new();
    opts.optopt("c", "config", "Yggdrasil config file (TOML). Without it an ephemeral key is used", "FILE");
    opts.optmulti("p", "peer", "Peer URI to connect to (repeatable)", "URI");
    opts.optopt("", "socks", "SOCKS5 listen address, e.g. 127.0.0.1:1080", "ADDR");
    opts.optopt("", "socks-auth", "Require SOCKS5 username/password", "USER:PASS");
    opts.optmulti("", "local-tcp", "Forward a host TCP listener to Yggdrasil", "LISTEN=TARGET");
    opts.optmulti("", "local-udp", "Forward a host UDP socket to Yggdrasil", "LISTEN=TARGET");
    opts.optmulti("", "remote-tcp", "Expose a host TCP service on a Yggdrasil port", "PORT=ADDR");
    opts.optmulti("", "remote-udp", "Expose a host UDP service on a Yggdrasil port", "PORT=ADDR");
    opts.optflag("", "admin", "Start the admin socket from the config (admin_listen)");
    opts.optopt("l", "loglevel", "error, warn, info, debug, trace (default: info)", "LEVEL");
    opts.optflag("h", "help", "Print this help");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: {e}\n{}", opts.usage(USAGE));
            return ExitCode::FAILURE;
        }
    };
    if matches.opt_present("help") {
        println!("{}", opts.usage(USAGE));
        return ExitCode::SUCCESS;
    }

    let level = matches.opt_str("loglevel").unwrap_or_else(|| "info".into());
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(matches)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn split_pair<'a>(spec: &'a str, what: &str) -> Result<(&'a str, &'a str), Error> {
    spec.split_once('=')
        .ok_or_else(|| format!("--{what} expects LEFT=RIGHT, got {spec:?}").into())
}

async fn run(matches: getopts::Matches) -> Result<(), Error> {
    let mut config = match matches.opt_str("config") {
        Some(path) => toml::from_str::<Config>(&std::fs::read_to_string(&path)?)?,
        None => Config::default(),
    };
    for peer in matches.opt_strs("peer") {
        if !config.peers.contains(&peer) {
            config.peers.push(peer);
        }
    }

    let node = NodeBuilder::new(config)
        .embedded()
        .admin(matches.opt_present("admin"))
        .start()
        .await?;
    let stack = YggStack::new(&node)?;

    let mut tasks = JoinSet::new();
    if let Some(listen) = matches.opt_str("socks") {
        let listener = tokio::net::TcpListener::bind(&listen).await?;
        let mut server = Socks5Server::new(stack.clone());
        if let Some(auth) = matches.opt_str("socks-auth") {
            let (user, pass) = auth.split_once(':').ok_or("--socks-auth expects USER:PASS")?;
            server = server.with_credentials(user, pass);
        }
        tracing::info!("SOCKS5 proxy on {}", listener.local_addr()?);
        tasks.spawn(server.serve(listener));
    }
    for spec in matches.opt_strs("local-tcp") {
        let (listen, target) = split_pair(&spec, "local-tcp")?;
        let target: Target = target.parse()?;
        let listener = tokio::net::TcpListener::bind(listen).await?;
        tracing::info!("Forwarding tcp {} -> {}", listener.local_addr()?, target);
        tasks.spawn(forward_local_tcp(stack.clone(), listener, target));
    }
    for spec in matches.opt_strs("local-udp") {
        let (listen, target) = split_pair(&spec, "local-udp")?;
        let target: Target = target.parse()?;
        let socket = tokio::net::UdpSocket::bind(listen).await?;
        tracing::info!("Forwarding udp {} -> {}", socket.local_addr()?, target);
        tasks.spawn(forward_local_udp(stack.clone(), socket, target));
    }
    for spec in matches.opt_strs("remote-tcp") {
        let (port, target) = split_pair(&spec, "remote-tcp")?;
        let port: u16 = port.parse()?;
        let target: SocketAddr = target.parse()?;
        tracing::info!("Exposing tcp [{}]:{} -> {}", stack.address(), port, target);
        tasks.spawn(forward_remote_tcp(stack.clone(), port, target));
    }
    for spec in matches.opt_strs("remote-udp") {
        let (port, target) = split_pair(&spec, "remote-udp")?;
        let port: u16 = port.parse()?;
        let target: SocketAddr = target.parse()?;
        tracing::info!("Exposing udp [{}]:{} -> {}", stack.address(), port, target);
        tasks.spawn(forward_remote_udp(stack.clone(), port, target));
    }
    if tasks.is_empty() {
        tracing::warn!("No --socks or forwards given; the node only answers pings");
    }

    let result: Result<(), Error> = tokio::select! {
        _ = tokio::signal::ctrl_c() => Ok(()),
        Some(done) = tasks.join_next() => match done {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e.into()),
            Err(e) => Err(e.into()),
        },
    };
    tracing::info!("Shutting down...");
    tasks.shutdown().await;
    stack.close();
    node.close().await;
    result
}
