use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[derive(Parser, Debug)]
#[command(
    name = "yggdrasilctl",
    version,
    about = "Yggdrasil mesh network control tool"
)]
struct Args {
    /// Admin socket address (default: tcp://localhost:9001)
    #[arg(short = 'e', long, default_value = "tcp://localhost:9001")]
    endpoint: String,

    /// Command to run (e.g. getSelf, getPeers, getTree, addPeer, removePeer)
    command: Option<String>,

    /// Arguments as key=value pairs
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,

    /// Output as raw JSON
    #[arg(short, long)]
    json: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let command = match &args.command {
        Some(c) => c.clone(),
        None => {
            eprintln!("Usage: yggdrasilctl [-e endpoint] <command> [key=value ...]");
            eprintln!("Commands: list, getSelf, getPeers, getTree, addPeer, removePeer");
            std::process::exit(1);
        }
    };

    // Parse key=value arguments into a JSON object
    let mut arguments = serde_json::Map::new();
    for arg in &args.args {
        if let Some((k, v)) = arg.split_once('=') {
            arguments.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
    }

    let request = serde_json::json!({
        "request": command,
        "arguments": arguments,
        "keepalive": false,
    });

    let addr = args
        .endpoint
        .strip_prefix("tcp://")
        .unwrap_or(&args.endpoint);

    let stream = TcpStream::connect(addr).await.map_err(|e| {
        format!(
            "Failed to connect to admin socket at {}: {}",
            args.endpoint, e
        )
    })?;

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // Send request
    let req_json = serde_json::to_string(&request)?;
    writer.write_all(req_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    // Read response
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    if line.trim().is_empty() {
        eprintln!("Empty response from admin socket");
        std::process::exit(1);
    }

    let resp: serde_json::Value = serde_json::from_str(line.trim())?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    // Check status
    let status = resp
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    if status != "success" {
        let error = resp
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        eprintln!("Error: {}", error);
        std::process::exit(1);
    }

    let response = &resp["response"];

    // Pretty-print based on command
    match command.to_lowercase().as_str() {
        "list" => {
            if let Some(list) = response.get("list").and_then(|v| v.as_array()) {
                println!("Available commands:");
                for cmd in list {
                    if let Some(s) = cmd.as_str() {
                        println!("  {}", s);
                    }
                }
            }
        }

        "getself" => {
            print_kv(response, &[
                ("Build name", "build_name"),
                ("Build version", "build_version"),
                ("Public key", "key"),
                ("IPv6 address", "address"),
                ("IPv6 subnet", "subnet"),
                ("Routing entries", "routing_entries"),
            ]);
        }

        "getpeers" => {
            if let Some(peers) = response.get("peers").and_then(|v| v.as_array()) {
                if peers.is_empty() {
                    println!("No peers connected.");
                } else {
                    for (i, peer) in peers.iter().enumerate() {
                        if i > 0 {
                            println!();
                        }
                        print_kv(peer, &[
                            ("URI", "uri"),
                            ("Up", "up"),
                            ("Inbound", "inbound"),
                            ("Public key", "key"),
                            ("IPv6 address", "address"),
                            ("IPv6 subnet", "subnet"),
                            ("Priority", "priority"),
                            ("Bytes received", "bytes_recvd"),
                            ("Bytes sent", "bytes_sent"),
                            ("RX rate", "rx_rate"),
                            ("TX rate", "tx_rate"),
                            ("Uptime", "uptime"),
                            ("Last error", "last_error"),
                        ]);
                    }
                }
            }
        }

        "gettree" => {
            if let Some(tree) = response.get("tree").and_then(|v| v.as_array()) {
                if tree.is_empty() {
                    println!("No tree entries.");
                } else {
                    for (i, entry) in tree.iter().enumerate() {
                        if i > 0 {
                            println!();
                        }
                        print_kv(entry, &[
                            ("Public key", "key"),
                            ("IPv6 address", "address"),
                            ("Parent", "parent"),
                            ("Sequence", "sequence"),
                        ]);
                    }
                }
            }
        }

        _ => {
            // Generic: print the response as pretty JSON
            println!("{}", serde_json::to_string_pretty(response)?);
        }
    }

    Ok(())
}

fn print_kv(obj: &serde_json::Value, fields: &[(&str, &str)]) {
    let max_label = fields.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    for (label, key) in fields {
        if let Some(val) = obj.get(key) {
            let val_str = match val {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => "n/a".to_string(),
                other => other.to_string(),
            };
            println!("  {:width$}  {}", format!("{}:", label), val_str, width = max_label + 1);
        }
    }
}
