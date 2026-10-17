# Crypto-Key Routing (CKR)

> Part of the [Yggdrasil-ng](../README.md) documentation.

CKR enables tunneling arbitrary IPv4/IPv6 traffic through the Yggdrasil mesh by mapping IP subnets to node public keys. This turns Yggdrasil into a point-to-point VPN — useful for exit-node setups, site-to-site tunnels, or routing specific subnets between nodes.

CKR is part of the default feature set, so a standard build already includes it:

```bash
cargo build --release
```

To build without CKR, disable default features and re-enable the others:

```bash
cargo build --release --no-default-features --features ctl,tun,systemd
```

## Configuration

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

The list of CIDRs for each public key supports additional syntax (bare IPv4/IPv6 addresses without a subnet prefix are recognised as /32 and /128 respectively; this also applies to addresses beginning with "\~" and "!"):

Prefix an IPv4 or IPv6 address/subnet with "\~" (e.g. "\~0.0.0.0/1", "\~10.0.0.0/8", "\~2000::/3") to establish CKR tunnels without installing system routes for those prefixes.
Use "inetv4" to include the full list of IPv4 internet prefixes (excluding internal networks) for both CKR and system routes; use "\~inetv4" for CKR tunnels only without system routes.
Use "inetv6" or "\~inetv6" similarly for IPv6 (expands to "2000::/3").
The "!" prefix for exclusions applies to CKR ranges for both normal and "\~" prefixed includes. No "!inetv4" or "!inetv6" are supported.

## Exit-Node Setup

This example shows how to route all internet traffic from a client through a VPS running Yggdrasil-ng with CKR.

Both nodes must be peered (directly or through the mesh). CKR is included in a default build.

### Client configuration

```toml
[tunnel_routing]
enable = true
yggdrasil_routing = true
ip_addresses = ["10.99.0.2/24"]

[tunnel_routing.remote_subnets]
# Route all IPv4 and IPv6 internet traffic via VPS
"<VPS_PUBLIC_KEY>" = [
    "0.0.0.0/0", "2000::/3"
]
```

If you want, you can use the `0.0.0.0/1` + `128.0.0.0/1` routes instead of `0.0.0.0/0`, this split covers all IPv4 without overriding the system default route (which would break the Yggdrasil peering connection itself).
Same idea for `::/1` + `8000::/1` for IPv6. Yggdrasil's own `0200::/7` addresses still route natively — they are checked first before CKR lookup.

### VPS (exit node) configuration

```toml
[tunnel_routing]
enable = true
yggdrasil_routing = true
ip_addresses = ["10.99.0.1/24"]

[tunnel_routing.remote_subnets]
# Accept traffic from client's CKR subnet
"<CLIENT_PUBLIC_KEY>" = ["10.99.0.2/32"]
```

### VPS system setup (Linux)

Enable IP forwarding and NAT so tunneled traffic can reach the internet:

```bash
# Enable IPv4 and IPv6 forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# IPv4 NAT (replace eth0 with your internet-facing interface)
iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -i ygg0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o ygg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
# If you have problems with MTU, use this line:
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# IPv6 NAT (for tunneled IPv6 traffic from Yggdrasil addresses)
ip6tables -t nat -A POSTROUTING -s 200::/7 -o eth0 -j MASQUERADE
ip6tables -A FORWARD -i ygg0 -o eth0 -j ACCEPT
ip6tables -A FORWARD -i eth0 -o ygg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
# If you have problems with MTU, use this line:
ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

To make these persistent across reboots, add the sysctl settings to `/etc/sysctl.d/` and save the iptables rules with `iptables-save`/`ip6tables-save`.

### Testing

From the client, verify your traffic exits through the VPS:

```bash
curl ifconfig.me          # Should show VPS IPv4 address
curl -6 ifconfig.me       # Should show VPS IPv6 address
```

## Dual-stack Site-to-Site Tunnel

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

## Private IPv4 VPN (Multi-Node)

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

## Routable IPv6 for Home Devices (Hurricane Electric Alternative)

If your VPS comes with a routed IPv6 prefix (most providers hand out at least a /64; some give a /112 or smaller), you can use CKR to give your home machines, phones, or laptops **real, globally-routable IPv6 addresses** from that prefix — delivered through the Yggdrasil mesh. This replaces third-party tunnel brokers such as Hurricane Electric (tunnelbroker.net): your devices get full inbound and outbound IPv6 connectivity with addresses that belong to your own VPS, and they reach the VPS over whatever underlay they already have (home IPv4, CGNAT, mobile data — anything that can carry the Yggdrasil peering).

Unlike the [exit-node setup](#exit-node-setup) above, **no NAT is involved** — each device sends and receives traffic with its own public address.

### Scenario

The provider routes the prefix `2001:db8:0:1::/112` to the VPS:

| Address | Where |
|---------|-------|
| `2001:db8:0:1::1` | VPS itself (on `eth0`) |
| `2001:db8:0:1::4` | Phone (via Yggdrasil) |
| `2001:db8:0:1::5` | Home PC (via Yggdrasil) |

The VPS and each device must be peered with each other (peer the devices **to the VPS over IPv4** — see the note below), and you need each node's public key (`yggdrasil getSelf`). CKR is included in a default build.

### VPS configuration

```toml
[tunnel_routing]
enable = true
yggdrasil_routing = true

[tunnel_routing.remote_subnets]
"<HOME_PC_KEY>" = ["2001:db8:0:1::5/128"]
"<PHONE_KEY>"   = ["2001:db8:0:1::4/128"]
```

The VPS does not assign these addresses to its own interfaces. With `install_system_routes = true` (the default) the daemon adds the `…::5/128` and `…::4/128` routes via the TUN automatically.

Enable IPv6 forwarding on the VPS:

```bash
echo 'net.ipv6.conf.all.forwarding = 1' > /etc/sysctl.d/99-ygg.conf
sysctl --system
```

### Delivering the prefix to the VPS: routed vs. on-link

How the provider hands you the prefix decides whether an extra step is needed:

- **Routed** — the provider has a static route for your prefix pointing at the VPS. Nothing more to do; forwarding plus the config above is enough.
- **On-link** — the provider treats the prefix as on-link on the VPS's segment and uses Neighbor Discovery to reach each address. Because `…::4`/`…::5` live on the TUN (not on `eth0`), the VPS must answer NDP for them, or return traffic is dropped at the provider's gateway.

To tell them apart, run `ip -6 route` on the VPS: if the prefix shows as `dev eth0 proto kernel` (on-link) you likely need the NDP step; if it is reached via a gateway you are routed. The simplest test is to ping one of the device addresses from an outside host once everything is up — if outbound traffic from the device works but replies never arrive, it is the on-link case.

For the on-link case, answer NDP with **ndppd** (`apt install ndppd`), one rule per device in `/etc/ndppd.conf`:

```
proxy eth0 {
    rule 2001:db8:0:1::5/128 { static }
    rule 2001:db8:0:1::4/128 { static }
}
```

```bash
systemctl enable --now ndppd
```

> List each device explicitly rather than the whole prefix (`2001:db8:0:1::/112 { static }`). A blanket rule also answers for unused addresses, which — since the prefix is on-link on `eth0` too — can make packets to those addresses loop on the segment until their hop limit expires.
>
> If you would rather not install ndppd, the kernel can proxy a fixed set of addresses instead: set `net.ipv6.conf.eth0.proxy_ndp = 1` and add `ip -6 neigh add proxy 2001:db8:0:1::5 dev eth0` for each device (these `neigh` entries are not persistent across reboots).

### Device configuration

Each device assigns its own address to the TUN and routes all global IPv6 through the VPS:

```toml
# Peer to the VPS over IPv4 to avoid sending the peering through the tunnel
peers = ["tls://<VPS_IPV4>:<PORT>"]

[tunnel_routing]
enable = true
yggdrasil_routing = true
ip_addresses = ["2001:db8:0:1::5/128"]   # this device's public address

[tunnel_routing.remote_subnets]
"<VPS_KEY>" = ["inetv6"]                  # all global IPv6 (2000::/3) via the VPS
```

`inetv6` expands to `2000::/3` and is installed as the device's IPv6 default route via the TUN. The same route also tells CKR to accept inbound traffic from any internet address, as long as it arrives from the VPS.

> **Peer over IPv4 (or another non-tunneled path).** Because `inetv6` covers `2000::/3`, it includes the VPS's own underlay IPv6 address — peering over that address would route the peering connection back into the tunnel. Peering over IPv4 avoids this. If you must peer over IPv6, carve the VPS address out of the route with an exclusion (add `"!<VPS_UNDERLAY_IP>/128"` to the list) and make sure a native route to it exists.

For name resolution, point the device at an IPv6 DNS resolver (for example `2606:4700:4700::1111`), which is reachable through the tunnel.

### Testing

From the device:

```bash
curl -6 ifconfig.me        # shows this device's own address (…::5), not the VPS's
ping6 ipv6.google.com
```

From any outside host, confirm the address is reachable inbound:

```bash
ping6 2001:db8:0:1::5
```

If large transfers stall while small pings work, suspect MTU — the tunnel adds overhead, and PMTUD (ICMPv6 Packet Too Big) must be allowed to pass.

## Performance on forwarding nodes

A node that forwards CKR traffic handles other people's packets, which arrive at
whatever MSS the far end negotiated — usually small, and usually back to back.
That is the traffic shape [TUN segmentation offload](GSO.md) exists for, so
`if_gso = true` (Linux only) is worth enabling on exit nodes and site-to-site
gateways: it cut CPU per gigabit by roughly a third in testing. It is inert for
bulk transfer between two default-MTU nodes, so it is not worth enabling
everywhere by reflex.
