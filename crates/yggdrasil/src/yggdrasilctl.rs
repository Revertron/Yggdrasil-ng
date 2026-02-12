use comfy_table::{presets, Table};
use getopts::Options;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut opts = Options::new();
    opts.optopt("e", "endpoint", "Admin socket address (default: tcp://localhost:9001)", "URI");
    opts.optflag("j", "json", "Output as raw JSON");
    opts.optflag("h", "help", "Print this help");
    opts.optflag("v", "version", "Print version");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("{}", opts.usage("Usage: yggdrasilctl [options] <command> [key=value ...]"));
            std::process::exit(1);
        }
    };

    if matches.opt_present("help") {
        println!("{}", opts.usage("Usage: yggdrasilctl [options] <command> [key=value ...]"));
        println!("Commands: list, getSelf, getPeers, getTree, addPeer, removePeer");
        return Ok(());
    }

    if matches.opt_present("version") {
        println!("yggdrasilctl {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let endpoint = matches.opt_str("endpoint").unwrap_or_else(|| "tcp://localhost:9001".to_string());
    let json_output = matches.opt_present("json");

    let free = matches.free.clone();
    let command = match free.first() {
        Some(c) => c.clone(),
        None => {
            eprintln!("Usage: yggdrasilctl [options] <command> [key=value ...]");
            eprintln!("Commands: list, getSelf, getPeers, getTree, addPeer, removePeer");
            std::process::exit(1);
        }
    };

    // Parse key=value arguments into a JSON object
    let mut arguments = serde_json::Map::new();
    for arg in &free[1..] {
        if let Some((k, v)) = arg.split_once('=') {
            arguments.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
    }

    let request = serde_json::json!({
        "request": command,
        "arguments": arguments,
        "keepalive": false,
    });

    let addr = endpoint
        .strip_prefix("tcp://")
        .unwrap_or(&endpoint);

    let stream = TcpStream::connect(addr).await.map_err(|e| {
        format!(
            "Failed to connect to admin socket at {}: {}",
            endpoint, e
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

    if json_output {
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
                    let mut table = Table::new();
                    table.load_preset(presets::NOTHING);
                    table.set_header(vec![
                        "URI", "State", "Dir", "IP Address", "Uptime", "RX", "TX",
                        "RX Rate", "TX Rate", "Pr", "Last Error"
                    ]);

                    for peer in peers {
                        let uri = peer.get("uri")
                            .and_then(|v| v.as_str())
                            .unwrap_or("-");
                        let up = peer.get("up")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let state = if up { "Up" } else { "Down" };
                        let inbound = peer.get("inbound")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let dir = if inbound { "In" } else { "Out" };
                        let address = peer.get("address")
                            .and_then(|v| v.as_str())
                            .unwrap_or("-");
                        let uptime = peer.get("uptime")
                            .and_then(|v| v.as_f64())
                            .map(format_uptime)
                            .unwrap_or_else(|| "-".to_string());
                        let rx_bytes = peer.get("bytes_recvd")
                            .and_then(|v| v.as_u64())
                            .map(format_bytes)
                            .unwrap_or_else(|| "-".to_string());
                        let tx_bytes = peer.get("bytes_sent")
                            .and_then(|v| v.as_u64())
                            .map(format_bytes)
                            .unwrap_or_else(|| "-".to_string());
                        let rx_rate = peer.get("rx_rate")
                            .and_then(|v| v.as_u64())
                            .map(|r| if r > 0 { format!("{}/s", format_bytes(r)) } else { "-".to_string() })
                            .unwrap_or_else(|| "-".to_string());
                        let tx_rate = peer.get("tx_rate")
                            .and_then(|v| v.as_u64())
                            .map(|r| if r > 0 { format!("{}/s", format_bytes(r)) } else { "-".to_string() })
                            .unwrap_or_else(|| "-".to_string());
                        let priority = peer.get("priority")
                            .and_then(|v| v.as_u64())
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "-".to_string());
                        let last_error = peer.get("last_error")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .unwrap_or("-");

                        table.add_row(vec![
                            uri, state, dir, address, &uptime, &rx_bytes, &tx_bytes,
                            &rx_rate, &tx_rate, &priority, last_error
                        ]);
                    }

                    println!("{}", table);
                }
            }
        }

        "gettree" => {
            if let Some(tree) = response.get("tree").and_then(|v| v.as_array()) {
                if tree.is_empty() {
                    println!("No tree entries.");
                } else {
                    let mut table = Table::new();
                    table.load_preset(presets::NOTHING);
                    table.set_header(vec!["Public Key", "IP Address", "Parent", "Sequence"]);

                    for entry in tree {
                        let key = entry.get("key")
                            .and_then(|v| v.as_str())
                            .unwrap_or("-");
                        let address = entry.get("address")
                            .and_then(|v| v.as_str())
                            .unwrap_or("-");
                        let parent = entry.get("parent")
                            .and_then(|v| v.as_str())
                            .unwrap_or("-");
                        let sequence = entry.get("sequence")
                            .and_then(|v| v.as_u64())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "-".to_string());

                        table.add_row(vec![key, address, parent, &sequence]);
                    }

                    println!("{}", table);
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

/// Format bytes as human-readable string (KB, MB, GB, etc.)
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0 B".to_string();
    }

    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

/// Format uptime in seconds as human-readable string (e.g., "1h23m45s")
fn format_uptime(seconds: f64) -> String {
    let total_secs = seconds as u64;
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    if hours > 0 {
        format!("{}h{}m{}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m{}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}
