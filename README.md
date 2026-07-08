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
- Crypto-Key Routing (CKR) — tunnel arbitrary IPv4/IPv6 subnets through the mesh (enabled by default via the `ckr` feature)

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

## Container Image

Release container images are available from GitHub Container Registry.
See [docs/CONTAINER.md](docs/CONTAINER.md) for tags, supported platforms, and Docker/Podman usage.

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
| `[tunnel_routing]` | table | CKR tunnel routing config (`ckr` feature, enabled by default) — see [docs/CKR.md](docs/CKR.md) |

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

CKR enables tunneling arbitrary IPv4/IPv6 traffic through the Yggdrasil mesh by mapping IP subnets to node public keys.
This turns Yggdrasil into a point-to-point VPN — useful for exit-node setups, site-to-site tunnels, multi-node private VPNs,
or handing out routable public IPv6 to home devices.

CKR is part of the default feature set, so a standard build already includes it:

```bash
cargo build --release
```

To build without CKR, disable default features and re-enable the others:

```bash
cargo build --release --no-default-features --features ctl,tun,systemd
```

See the **[full CKR guide](docs/CKR.md)** for the `[tunnel_routing]` configuration reference and worked examples:

- [Exit-node setup](docs/CKR.md#exit-node-setup) — route all of a client's internet traffic through a VPS
- [Dual-stack site-to-site tunnel](docs/CKR.md#dual-stack-site-to-site-tunnel) — link two private networks
- [Private IPv4 VPN (multi-node)](docs/CKR.md#private-ipv4-vpn-multi-node) — a shared private subnet across many nodes
- [Routable IPv6 for home devices](docs/CKR.md#routable-ipv6-for-home-devices-hurricane-electric-alternative) — a self-hosted alternative to Hurricane Electric tunnel brokers

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