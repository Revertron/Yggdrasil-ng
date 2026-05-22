# Yggdrasil-ng

A Rust rewrite of the [Yggdrasil Network](https://yggdrasil-network.github.io/) — an early-stage implementation of a fully end-to-end encrypted IPv6 networking protocol.
This project aims to provide a lightweight, self-arranging, and secure mesh network alternative to the original Go implementation.

## Features

- **End-to-end encryption** for all network traffic using XSalsa20-Poly1305 (RustCrypto implementation)
- **Self-arranging mesh topology** — nodes automatically discover optimal paths via spanning tree routing
- **IPv6 native** — provides every node with a unique, cryptographically bound IPv6 address derived from Ed25519 public key
- **Cross-platform** support (Linux, macOS, Windows)
- **Lightweight** — minimal resource footprint, suitable for embedded devices and routers
- **Rust implementation** — memory safety, performance, zero-cost abstractions, and modern tooling

### Implementation Status

**✅ Fully Implemented:**
- Core routing protocol (spanning tree, path discovery, bloom filters)
- End-to-end encryption with forward secrecy (session key ratcheting)
- TCP and TLS transports with automatic reconnection and exponential backoff
- TUN/TAP interface for IPv6 traffic
- Admin socket API (getSelf, getPeers, getTree, getPaths, getSessions, addPeer, removePeer, etc.)
- Session cleanup and timeout handling
- Optimized Ed25519→Curve25519 key conversion
- Single binary for daemon and control commands (no separate `yggdrasilctl`)
- Windows service support (runs as `yggdrasil-ng` service via SCM)
- UniFFI bindings for Android

**✅ Optional (feature-gated):**
- Crypto-Key Routing (CKR) — tunnel arbitrary IPv4/IPv6 subnets through the mesh (`--features ckr`)

**⏳ Planned Features:**
- Multicast peer discovery on local networks
- Performance optimizations and protocol improvements

## Building from Source

### Prerequisites

- [Rust](https://rustup.rs/) (latest stable version recommended)
- Cargo (included with Rust)

### Clone the Repository

```bash
git clone https://github.com/Revertron/Yggdrasil-ng.git
cd Yggdrasil-ng
```

### Building the Binaries

#### Build Both Binaries (Release Mode)

```bash
cargo build --release
```

This will produce a single binary in `./target/release/`:
- `yggdrasil` — The network daemon and control tool (combined)

#### Development/Debug Builds

For development purposes with faster compile times (but slower runtime performance):

```bash
cargo build
```

Binaries will be located in `./target/debug/`.

### Cross-Compilation

To build for a different target, use the `--target` flag. For example, for Linux ARM64:

```bash
cargo build --release --target aarch64-unknown-linux-gnu
```

## Installation

After building, you can install the binary system-wide:

```bash
# Copy binary to system PATH
sudo cp target/release/yggdrasil /usr/local/bin/

# Or use cargo install for local user installation
cargo install --path crates/yggdrasil
```

## Usage

### Command Line Options

```bash
yggdrasil [options]
```

**Available options:**

| Option | Description |
|--------|-------------|
| `-g, --genconf [FILE]` | Generate a new configuration (save to FILE or print to stdout) |
| `-c, --config FILE` | Config file path (default: `yggdrasil.toml`) |
| `--autoconf` | Run without a configuration file (use ephemeral keys) |
| `-a, --address` | Print the IPv6 address for the given config and exit |
| `-s, --subnet` | Print the IPv6 subnet for the given config and exit |
| `-l, --loglevel LEVEL` | Log level: error, warn, info, debug, trace (default: info) |
| `-n, --no-replace` | With `--genconf FILE`, skip if the file already exists |
| `--logto FILE` | Log to a file instead of stderr (appends) |
| `--service` | Run as a Windows service (Windows only) |
| `-h, --help` | Print help message |
| `-v, --version` | Print version |

**Environment variables:**

- `YGGDRASIL_PRIVATE_KEY`: Hex-encoded Ed25519 private key (128 hex chars). Overrides config file if set.

### Starting Yggdrasil

Generate a default configuration file:

```bash
yggdrasil --genconf > yggdrasil.toml
# Or save directly to a file:
yggdrasil --genconf=yggdrasil.toml
```

Edit the configuration to add peers, then start the daemon:

```bash
sudo yggdrasil -c yggdrasil.toml
```

Or run with auto-configuration (ephemeral key):

```bash
sudo yggdrasil --autoconf
```

Print your address without starting the daemon:

```bash
yggdrasil --config yggdrasil.toml --address
```

### Control Commands

The `yggdrasil` binary doubles as a control tool. Pass commands as positional arguments to query or manage a running daemon:

```bash
# Get your node's info
yggdrasil getSelf

# List connected peers
yggdrasil getPeers

# View routing table (spanning tree)
yggdrasil getTree
```

**Supported commands:**

*Local queries:*
- `getSelf` - Show node info (address, subnet, public key, coordinates)
- `getPeers` - List active peer connections with statistics
- `getTree` - Show routing table entries (spanning tree)
- `getPaths` - Show cached paths to remote destinations
- `getSessions` - Show active encrypted sessions
- `getTUN` - Show TUN adapter status
- `addPeer uri=<URI>` / `removePeer uri=<URI>` - Manage peer connections

*Remote queries:*
- `getNodeInfo key=<hex>` - Query node metadata from remote node
- `debug_remoteGetSelf key=<hex>` - Query self info from remote node
- `debug_remoteGetPeers key=<hex>` - Query peer list from remote node
- `debug_remoteGetTree key=<hex>` - Query tree entries from remote node

*Path diagnostics:*
- `getLookup key=<hex>` - Show cached lookup for a key
- `forceLookup key=<hex>` - Force a new path lookup

By default, control commands connect to `tcp://localhost:9001`. You can specify a different address:

```bash
yggdrasil -e tcp://127.0.0.1:9001 getPeers
```

Use `-j` / `--json` to get raw JSON output instead of formatted tables.

## Configuration

### Config File Format: TOML

Yggdrasil-ng uses **TOML** format for configuration (unlike the Go version which uses HJSON/JSON).

**Key configuration options:**

| Option | Type | Description |
|--------|------|-------------|
| `private_key` | string | Hex-encoded Ed25519 private key (128 hex chars, 64 bytes) |
| `peers` | array | Peer URIs to connect to, e.g. `["tcp://host:port"]` |
| `listen` | array | Listen addresses, e.g. `["tcp://[::]:1234"]` |
| `admin_listen` | string | Admin socket address, e.g. `"tcp://localhost:9001"` |
| `if_name` | string | TUN interface name: "auto" (default) or "none" to disable |
| `if_mtu` | integer | TUN MTU (default: 65535) |
| `node_info` | table | Custom node metadata (TOML table) |
| `node_info_privacy` | bool | Hide node info from other nodes (default: false) |
| `allowed_public_keys` | array | Whitelist of allowed peer keys (empty = allow all) |
| `[tunnel_routing]` | table | CKR tunnel routing config (requires `ckr` feature) |

**Example minimal configuration:**

```toml
# Your private Ed25519 key (DO NOT share!)
private_key = "0123456789abcdef..."

# Peers to connect to
peers = [
    "tcp://192.0.2.1:443",
    "tcp://[2001:db8::1]:12345"
]

# Listen for incoming connections
listen = ["tcp://[::]:1234"]

# Admin socket for yggdrasilctl
admin_listen = "tcp://localhost:9001"

# TUN interface settings
if_name = "auto"
if_mtu = 65535

# Custom node metadata (optional)
[node_info]
name = "my-node"
location = "datacenter-1"
```

### Peer URI Query Parameters

Both `peers` entries and `listen` addresses support optional query-string parameters:

**Outbound peers** (`peers`):

| Parameter | Description | Example |
|-----------|-------------|---------|
| `password=PASSWORD` | Shared secret required to connect (max 64 chars, must match remote side) | `?password=secret` |
| `key=PUBLICKEY` | Pin the expected public key (hex); connection fails if remote key differs | `?key=aabbcc...` |
| `priority=N` | Connection priority (0-255, lower = higher priority) when multiple connections exist to the same peer | `?priority=10` |
| `maxbackoff=DURATION` | Maximum reconnect backoff interval if the peer goes down (min 5s, default 68m) | `?maxbackoff=30s` |
| `sni=HOSTNAME` | Override TLS SNI hostname (TLS only; ignored for plain TCP) | `?sni=example.com` |

**Inbound listeners** (`listen`):

| Parameter | Description | Example |
|-----------|-------------|---------|
| `password=PASSWORD` | Require this password from connecting peers (max 64 chars) | `?password=secret` |

Duration values for `maxbackoff` accept plain seconds (`30`) or human-readable format (`30s`, `5m`, `1h`, `1h30m`).

**Example with multiple parameters:**

```toml
peers = [
    # VPS relay: faster reconnect, pinned key, TLS with custom SNI
    "tls://relay.example.com:2096?maxbackoff=30s&key=aabbccdd...&sni=example.net",

    # LAN node: higher priority than WAN peers
    "tcp://192.168.1.10:12345?priority=10",

    # Password-protected peer
    "tcp://peer.example.com:12345?password=mysecret",
]
```

### Differences from Go Version

**Command line:**
- `-c/--config` instead of `-useconffile`
- `--genconf [FILE]` instead of `-genconf` (can save directly to file)
- Config file defaults to `yggdrasil.toml` (not required to specify)
- New `YGGDRASIL_PRIVATE_KEY` environment variable support

**Config file:**
- **Format**: TOML instead of HJSON/JSON
- **Field names**: `snake_case` instead of `PascalCase`
  - `private_key` instead of `PrivateKey`
  - `admin_listen` instead of `AdminListen`
  - `if_name` instead of `IfName`
  - `if_mtu` instead of `IfMTU`
  - `node_info` instead of `NodeInfo`
  - `node_info_privacy` instead of `NodeInfoPrivacy`
  - `allowed_public_keys` instead of `AllowedPublicKeys`
- **Single binary**: Daemon and control tool are combined (no separate `yggdrasilctl`)
- **Transport support**: TCP and TLS only
- **Admin socket**: Defaults to TCP `localhost:9001` instead of Unix socket

**Migration from Go config:**
1. Convert HJSON/JSON to TOML format
2. Rename all fields from PascalCase to snake_case
3. Change transport URIs as needed (QUIC and WebSocket are not supported — use `tcp://` or `tls://`)
4. Update admin socket to TCP format if using Unix socket

## Crypto-Key Routing (CKR)

CKR enables tunneling arbitrary IPv4/IPv6 traffic through the Yggdrasil mesh by mapping IP subnets to node public keys. This turns Yggdrasil into a point-to-point VPN — useful for exit-node setups, site-to-site tunnels, or routing specific subnets between nodes.

CKR requires building with the `ckr` feature:

```bash
cargo build --release --features ckr
```

### Configuration

Add a `[tunnel_routing]` section to your `yggdrasil.toml`:

```toml
[tunnel_routing]
enable = true
yggdrasil_routing = true
ip_addresses = ["10.99.0.1/24"]

[tunnel_routing.remote_subnets]
"peer_public_key_hex" = ["10.0.0.0/24", "192.168.1.0/24"]
```

| Option | Type | Description |
|--------|------|-------------|
| `enable` | bool | Enable/disable CKR |
| `yggdrasil_routing` | bool | Also route standard Yggdrasil `0200::/7` traffic (default: true) |
| `install_system_routes` | bool | Automatically install system routing table entries for CKR. (default: true) |
| `ipv4_address` | string | IPv4 address to assign to TUN in CIDR notation (e.g., `"10.99.0.1/24"`). Deprecated |
| `ip_addresses` | array | IP addresses to assign to TUN in CIDR notation (e.g.,`[ "10.99.0.1/24", "2005:8a:9:11::3/64" ]`) |
| `remote_subnets` | table | Maps hex public key to list of CIDRs to route via that node |

System routes for all configured CIDRs are automatically installed when the TUN device starts and removed on shutdown. This works on Linux, Windows, and macOS.

The list of CIDRs for each public key supports additional syntax when the ckr feature is enabled (bare IPv4/IPv6 addresses without a subnet prefix are recognised as /32 and /128 respectively; this also applies to addresses beginning with "\~" and "!"):

Prefix an IPv4 or IPv6 address/subnet with "\~" (e.g. "\~0.0.0.0/1", "\~10.0.0.0/8", "\~2000::/3") to establish CKR tunnels without installing system routes for those prefixes.
Use "inetv4" to include the full list of IPv4 internet prefixes (excluding internal networks) for both CKR and system routes; use "\~inetv4" for CKR tunnels only without system routes.
Use "inetv6" or "\~inetv6" similarly for IPv6 (expands to "2000::/3").
The "!" prefix for exclusions applies to CKR ranges for both normal and "\~" prefixed includes. No "!inetv4" or "!inetv6" are supported.

### Exit-Node Setup

This example shows how to route all internet traffic from a client through a VPS running Yggdrasil-ng with CKR.

Both nodes must be peered (directly or through the mesh) and built with `--features ckr`.

#### Client configuration

```toml
[tunnel_routing]
enable = true
yggdrasil_routing = true
ip_addresses = ["10.99.0.2/24"]

[tunnel_routing.remote_subnets]
# Route all IPv4 and IPv6 internet traffic via VPS
"<VPS_PUBLIC_KEY>" = [
    "0.0.0.0/1", "128.0.0.0/1",
    "::/1", "8000::/1"
]
```

The `0.0.0.0/1` + `128.0.0.0/1` split covers all IPv4 without overriding the system default route (which would break the Yggdrasil peering connection itself). Same idea for `::/1` + `8000::/1` for IPv6. Yggdrasil's own `0200::/7` addresses still route natively — they are checked first before CKR lookup.

#### VPS (exit node) configuration

```toml
[tunnel_routing]
enable = true
yggdrasil_routing = true
ip_addresses = ["10.99.0.1/24"]

[tunnel_routing.remote_subnets]
# Accept traffic from client's CKR subnet
"<CLIENT_PUBLIC_KEY>" = ["10.99.0.2/32"]
```

#### VPS system setup (Linux)

Enable IP forwarding and NAT so tunneled traffic can reach the internet:

```bash
# Enable IPv4 and IPv6 forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# IPv4 NAT (replace eth0 with your internet-facing interface)
iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -i ygg0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o ygg0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# IPv6 NAT (for tunneled IPv6 traffic from Yggdrasil addresses)
ip6tables -t nat -A POSTROUTING -s 200::/7 -o eth0 -j MASQUERADE
ip6tables -A FORWARD -i ygg0 -o eth0 -j ACCEPT
ip6tables -A FORWARD -i eth0 -o ygg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

To make these persistent across reboots, add the sysctl settings to `/etc/sysctl.d/` and save the iptables rules with `iptables-save`/`ip6tables-save`.

#### Testing

From the client, verify your traffic exits through the VPS:

```bash
curl ifconfig.me          # Should show VPS IPv4 address
curl -6 ifconfig.me       # Should show VPS IPv6 address
```

### Dual-stack Site-to-Site Tunnel

CKR can also connect two private networks. For example, to link `192.168.1.0/24` / `fd0a:1:1:1::1/64` (Site A) with `192.168.2.0/24` / `fd0a:1:1:2::1/64` (Site B): 

**Site A:**
```toml
[tunnel_routing]
enable = true
ip_addresses = ["192.168.1.1/24", "fd0a:1:1:1::1/64"]

[tunnel_routing.remote_subnets]
"<SITE_B_KEY>" = ["192.168.2.0/32", "fd0a:1:1:2::1/128"]
```

**Site B:**
```toml
[tunnel_routing]
enable = true
ip_addresses = ["192.168.2.1/24", "fd0a:1:1:2::1/64"]

[tunnel_routing.remote_subnets]
"<SITE_A_KEY>" = ["192.168.1.0/32", "fd0a:1:1:1::1/128"]
```

Hosts on each side can then reach the other network through their Yggdrasil gateway node.

### Private IPv4 VPN (Multi-Node)

CKR can create a virtual private network where multiple nodes share a common IPv4 subnet and communicate directly over private IPs.
Each node gets an address from the shared range (e.g., `10.99.0.0/24`) and has CKR routes pointing to every other node.

**Node A** (`10.99.0.1`):
```toml
[tunnel_routing]
enable = true
ip_addresses = ["10.99.0.1/24"]

[tunnel_routing.remote_subnets]
"<NODE_B_KEY>" = ["10.99.0.2/32"]
"<NODE_C_KEY>" = ["10.99.0.3/32"]
```

**Node B** (`10.99.0.2`):
```toml
[tunnel_routing]
enable = true
ip_addresses = ["10.99.0.2/24"]

[tunnel_routing.remote_subnets]
"<NODE_A_KEY>" = ["10.99.0.1/32"]
"<NODE_C_KEY>" = ["10.99.0.3/32"]
```

**Node C** (`10.99.0.3`):
```toml
[tunnel_routing]
enable = true
ip_addresses = ["10.99.0.3/24"]

[tunnel_routing.remote_subnets]
"<NODE_A_KEY>" = ["10.99.0.1/32"]
"<NODE_B_KEY>" = ["10.99.0.2/32"]
```

Any IPv4 service works transparently between nodes — SSH, HTTP, SMB, databases, etc.
The nodes don't need to be directly peered; traffic routes through the Yggdrasil mesh automatically.

Note that each node needs routes to every other node, so the config grows with the number of participants.
For large deployments, consider a script to generate configs.

## Running as a Windows Service

On Windows, Yggdrasil-ng can run as a system service managed by the Service Control Manager (SCM).
The service is registered under the name `yggdrasil-ng` (display name "Yggdrasil NG") to avoid conflicts with the Go version.

### Register the service

Open an elevated (Administrator) command prompt:

```cmd
sc create yggdrasil-ng binPath= "C:\path\to\yggdrasil.exe --service -c C:\path\to\yggdrasil.toml" start= auto DisplayName= "Yggdrasil NG"
```

> **Note:** The spaces after `binPath=`, `start=`, and `DisplayName=` are required by `sc`.

### Start / Stop

```cmd
sc start yggdrasil-ng
sc stop yggdrasil-ng
```

Or use the Services GUI (`services.msc`).

### Remove the service

```cmd
sc delete yggdrasil-ng
```

### Running in console mode

Without the `--service` flag, the binary runs as a normal console application and shuts down on Ctrl+C.
This is the default and recommended mode for development and testing.

## Development

### Running Tests

```bash
cargo test
```

## Contributing

Contributions are not very welcome! Please don't feel free to submit issues or pull requests.
Ensure your code follows the project's own style guidelines and passes all tests.

## License

This project is licensed under the **Mozilla Public License 2.0 (MPL-2.0)** as the `ironwood`. See the [LICENSE](LICENSE) file for the full license text.

## Links

- [Yggdrasil Network Official Site](https://yggdrasil-network.github.io/)
- [Original Yggdrasil (Go implementation)](https://github.com/yggdrasil-network/yggdrasil-go)
- [Project Wiki](https://github.com/Revertron/Yggdrasil-ng/wiki)

## Compatibility with Go Version

Yggdrasil-ng is designed to be **wire-compatible** with the original Go implementation:

- ✅ Can peer with Go nodes over TCP
- ✅ Uses the same routing protocol and wire format
- ✅ Compatible address derivation (Ed25519 → IPv6)
- ✅ Compatible encryption (XSalsa20-Poly1305, session key ratcheting)
- ⚠️  Config files are **not** directly compatible (different format and field names)

**Interoperability tested with:**
- Yggdrasil-go v0.5.x

## Performance

- Thorough tests are to be made, but some tests with iperf3 show significant improvements over the Go's version.
- Also, the memory footprint is a lot smaller.
- And binaries are smaller too :)

---

**Note**: This is an experimental implementation under active development.
While core functionality is stable and tested, some features are still being implemented.
The network protocol is compatible with the Go version, but configuration format and CLI options differ.
Suitable for testing and development; use in production at your own discretion.