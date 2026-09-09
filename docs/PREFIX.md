# Custom `*00::/7` prefix and admin/multicast port

Yggdrasil-ng can run on a non-standard IPv6 prefix (`00::/7` through `fc00::/7`)
and a matching admin/multicast port. The values are taken from the **name** of
the binary, a symlink, or a hardlink. No extra command-line flag is required.

This page covers *why* you would do that, *how* the name is parsed, and a
quick start for prefix `fc00::/7` using `ygg_fc` / `ygg_fc.exe`.

The public mesh uses prefix `0200::/7` and admin/multicast port `9001`. Those
remain the defaults when the filename does not contain a recognised suffix.

The parser accepts **127** theoretically possible `/7` prefixes: the first
byte of the IPv6 address is an even value from `00` through `fc`
(`00`, `02`, …, `fa`, `fc`). That set exists so operators can pick an
overlay that does not collide with something already on the host. It does
**not** mean 127 overlays can actually run at once — much of that space is
already used by other networks (public Yggdrasil, Mycelium, ULA LANs,
global unicast, IANA special-purpose ranges). Read
[Possible prefix collisions](#possible-prefix-collisions) before choosing
anything other than the public-mesh default.

---

## Why run with a non-standard prefix

### Development and testing without leaving the public mesh

A second (or third) daemon on another `*00::/7` prefix is a separate overlay.
It does not share addresses, spanning-tree state, TUN name, or the admin
socket with a node that is still on `0200::/7`.

That is useful while developing Yggdrasil-ng itself:

- You can keep an everyday public-mesh node running (`yggdrasil` on
  `0200::/7`, port `9001`, interface `ygg0` / `Yggdrasil`) and never have to
  disconnect from the public network in order to test a change.
- You can start another copy of the same or a *different* binary under
  another name (`ygg_fc`, `ygg_06-9003`, …) and compare builds side by side.
  Each filename picks its own prefix, admin port, multicast port, default
  config filename, and TUN name, so two binaries do not fight over
  `tcp://localhost:9001` or over `ygg0`.
- Control commands follow the binary name: `ygg_fc getSelf` talks to the
  `fc00::/7` instance; `yggdrasil getSelf` still talks to the public one.

### Personal isolated networks for real work

The same mechanism builds a **private** overlay that is not joined to the
public `0200::/7` mesh. Traffic stays inside the group of nodes that share
that prefix. That avoids the public mesh as a source of routing noise
("network storms") and gives you a stable, smaller tree you control.

You can run several overlays on one machine at the same time, for example:

- one public node (`yggdrasil`, `0200::/7`);
- one or more personal nodes (`ygg_fc`, `ygg_aa`, …), each on its own
  prefix and port.

**Peer only personal nodes to other personal peers on the same
non-standard prefix.** Do not add public-mesh peers
(https://publicpeers.neilalexander.dev/ and similar lists) to a personal
node. A single peering into `0200::/7` collapses the isolation: you lose
the quiet tree and you mix two overlays that were never meant to meet.
Inbound `listen` URIs on a personal node should likewise not be advertised
as public peers.

A different prefix is **not** an access-control mechanism by itself. Anyone
who runs a binary with the same suffix can generate an address in that
`/7` and try to peer. Protect the overlay with a link password and a
closed-network `group_password` — see [Protecting an isolated
network](#protecting-an-isolated-network) at the end of this page.

Pick the `/7` with [Possible prefix collisions](#possible-prefix-collisions)
in mind. The public mesh already owns `200::/7`; other values can overlap
ULA LANs, Mycelium, IANA special-purpose space, or global unicast.

---

## Prefix and port from the binary name

The last `_` in the filename is the marker. Everything after that `_` is
parsed as a prefix and an optional port. A trailing Windows `.exe` is
stripped first, so `ygg_fc.exe` is treated as `ygg_fc`.

Accepted suffix forms:

| Suffix after the last `_` | Meaning |
|---------------------------|---------|
| `02`, `fc`, `06` | Prefix only. Port is derived (see below). |
| `029001`, `02-9001`, `02.9001` | Prefix `02` and port `9001`. |
| `fc9126`, `fc-9126`, `fc.9126` | Prefix `fc` and port `9126`. |

The two hex digits of the prefix must be a valid `*00::/7` value:
`00`–`fc` in steps of `2` (`00`, `02`, …, `fa`, `fc`). The optional port,
when present, must be in `1024`–`65535`. The separator between prefix and
port may be any single ASCII character that is not a space and not a hex
digit (`-`, `.`, `:`, and so on).

All 127 of those values parse. That is a flexibility limit, not a promise
that every value is safe on a given host. `00` overlaps IANA special-purpose
space; `02` is the public Yggdrasil Network; `fc` is RFC 4193 ULA space.
See [Possible prefix collisions](#possible-prefix-collisions).

Examples of names that parse:

- `yggdrasil_029001`, `yggdrasil_02-9001`, `ygg_029001`
- `yggdrasil_02.9001.exe`
- `ygg_02`, `yggdrasil_02`, `ygg_fc`, `ygg_fc.exe`
- `yggmesh_069003` → prefix `06`, port `9003`

Names with no `_`, or with a suffix that is not a valid prefix/port, keep
the built-in defaults: prefix `0x02` (`0200::/7`) and port `9001`.

### Port when the name has only a prefix

If the suffix is just the two hex digits, the admin **and** multicast port
is:

```text
port = prefix / 2 + 0x2328
```

`0x2328` is `9000`, so the derived port runs from `9000` (`00`) to `9126`
(`fc`):

| Prefix | Derived port | Example name |
|--------|--------------|--------------|
| `02` (`0200::/7`) | `9001` | `ygg_02` |
| `06` (`0600::/7`) | `9003` | `ygg_06` |
| `fc` (`fc00::/7`) | `9126` | `ygg_fc` |

You only need to put an explicit port in the filename when you want a
value other than this formula (`ygg_fc-16001`, `yggdrasil_06.15001`).

### What else the name changes

Once prefix and port are known, the same values are applied to:

- the overlay address prefix (`set_address_prefix`);
- the multicast discovery port (`set_multicast_port`);
- `admin_listen`, but only when it is still the default
  (`tcp://localhost:9001` or the same host with port `9001`) — a
  custom `admin_listen` in the config file is left alone, except that
  the default port is rewritten;
- the TUN name when `if_name` is still `"auto"`:
  - Linux: `ygg{prefix}{port}` (example: `yggfc9126`);
  - Windows: `Yggdrasil{prefix}{port}` (example: `Yggdrasilfc9126`);
  - macOS keeps `"auto"` so the kernel can allocate `utunN`.

Control-mode commands (`getSelf`, `getPeers`, `getTree`, …) use the
rewritten admin socket, so `ygg_fc getPeers` reaches the `fc00::/7`
daemon without `-e`.

### Default configuration filename

When `-c` / `--config` is omitted, the config filename follows the binary
name as well:

1. If the name contains a recognised prefix/port suffix, the file is
   `<stem>.toml` (`.exe` stripped). `ygg_fc` / `ygg_fc.exe` → `ygg_fc.toml`.
2. Otherwise the historic name `yggdrasil.toml` is used.

That filename is then looked up in this order:

1. the current working directory;
2. the OS system directory, same filename:
   - Unix-like (Linux except Android, BSD, macOS): `/etc/yggdrasil/<filename>`
   - Windows: `%ALLUSERSPROFILE%\Yggdrasil-ng\<filename>`

If a file exists at either default location, the daemon can be started
**without** `-c`. See [Default configuration file
paths](../README.md#default-configuration-file-paths) in the README.

Copy, symlink, and hardlink all work. A symlink or hardlink is the usual
choice on a router: one binary on disk, several names.

```bash
# Linux — extra name next to the installed binary
sudo ln -s /usr/local/bin/yggdrasil /usr/local/bin/ygg_fc
# or a second copy
sudo cp /usr/local/bin/yggdrasil /usr/local/bin/ygg_fc
```

```cmd
:: Windows — extra name next to the installed binary
:: Bare mklink creates a symbolic link and needs elevation or Developer Mode.
mklink "C:\Program Files\Yggdrasil-ng\ygg_fc.exe" "C:\Program Files\Yggdrasil-ng\yggdrasil.exe"
:: Hard link (same volume as the target):
mklink /H "C:\Program Files\Yggdrasil-ng\ygg_fc.exe" "C:\Program Files\Yggdrasil-ng\yggdrasil.exe"
:: or a second copy
copy "C:\Program Files\Yggdrasil-ng\yggdrasil.exe" "C:\Program Files\Yggdrasil-ng\ygg_fc.exe"
```

---

## Quick start: `fc00::/7` as `ygg_fc`

Goal: a second node on prefix `fc00::/7`, derived port `9126`, using the
**same private key** as an existing public-mesh config. The public node
can keep running.

Reuse of `private_key` is optional. It gives the personal node the same
identity bits under a different prefix (the IPv6 address changes because
the prefix changes). Generate a fresh key instead if you want a separate
identity: drop `--base` / `-b`.

`fc00::/7` is RFC 4193 unique-local address space. Use it only if the
host (and the LAN it sits on) does not already route ULA. If a ULA LAN
is already present, pick a free prefix from
[Possible prefix collisions](#possible-prefix-collisions) instead.

### Linux

Copy **or** symlink the binary, write `/etc/yggdrasil/ygg_fc.toml` from the
current template while copying `private_key` out of
`/etc/yggdrasil/yggdrasil.toml`, then start it. Because the file sits in
the system default directory under the name derived from `ygg_fc`, no
`-c` is required.

```bash
# One extra name for the same binary (pick one)
sudo ln -s /usr/local/bin/yggdrasil /usr/local/bin/ygg_fc
# sudo cp /usr/local/bin/yggdrasil /usr/local/bin/ygg_fc

sudo mkdir -p /etc/yggdrasil

# New template + private_key from the public-mesh config
sudo ygg_fc --genconf=/etc/yggdrasil/ygg_fc.toml --base=/etc/yggdrasil/yggdrasil.toml

# Edit peers / listen / group_password before the first start.
# Peer only other fc00::/7 nodes. Do not add public-mesh peers.
sudo $EDITOR /etc/yggdrasil/ygg_fc.toml

# System default path → no -c needed
sudo ygg_fc

# Equivalent explicit path
# sudo ygg_fc -c /etc/yggdrasil/ygg_fc.toml
```

Check the personal node with the same binary name:

```bash
ygg_fc getSelf
ygg_fc getPeers
```

`yggdrasil getSelf` continues to talk to the public node on port `9001`.

### Windows

Default public-mesh config: `%ALLUSERSPROFILE%\Yggdrasil-ng\yggdrasil.toml`
(usually `C:\ProgramData\Yggdrasil-ng\yggdrasil.toml`).

From an elevated command prompt:

```cmd
:: One extra name for the same binary (pick one)
:: Symbolic link (needs elevation or Developer Mode):
mklink "C:\Program Files\Yggdrasil-ng\ygg_fc.exe" "C:\Program Files\Yggdrasil-ng\yggdrasil.exe"
:: Hard link (same volume as the target):
mklink "C:\Program Files\Yggdrasil-ng\ygg_fc.exe" "C:\Program Files\Yggdrasil-ng\yggdrasil.exe"
:: copy "C:\Program Files\Yggdrasil-ng\yggdrasil.exe" "C:\Program Files\Yggdrasil-ng\ygg_fc.exe"

mkdir "%ALLUSERSPROFILE%\Yggdrasil-ng"

:: New template + private_key from the public-mesh config
ygg_fc.exe --genconf="%ALLUSERSPROFILE%\Yggdrasil-ng\ygg_fc.toml" --base="%ALLUSERSPROFILE%\Yggdrasil-ng\yggdrasil.toml"
```

Edit `%ALLUSERSPROFILE%\Yggdrasil-ng\ygg_fc.toml`: set personal peers only,
set `group_password`, set `?password=` on `listen` / `peers` as needed.

Run in the console (system default path → no `-c` needed):

```cmd
ygg_fc.exe --service
```

Without `--service` the process is an ordinary console app and exits on
Ctrl+C. That is the better mode while you are still editing the config:

```cmd
ygg_fc.exe
:: ygg_fc.exe -c "%ALLUSERSPROFILE%\Yggdrasil-ng\ygg_fc.toml"
```

#### Windows service `YggFC`

Same idea as [Running as a Windows Service](../README.md#running-as-a-windows-service)
in the README: change the service name, the binary name, and the config
filename. Creating the service **without** `-c` is valid when
`ygg_fc.toml` already exists in `%ALLUSERSPROFILE%\Yggdrasil-ng\`.

`sc create` with an explicit config path:

```cmd
sc create YggFC binPath= "%ProgramFiles%\Yggdrasil-ng\ygg_fc.exe --service -c %ALLUSERSPROFILE%\Yggdrasil-ng\ygg_fc.toml" start= auto DisplayName= "YggFC" 
sc description YggFC "Yggdrasil Network router process on prefix FC00::/7 and port 9126"
```

`sc create` without a config path (relies on the system default file):

```cmd
sc create YggFC binPath= "%ProgramFiles%\Yggdrasil-ng\ygg_fc.exe --service" start= auto DisplayName= "YggFC"
sc description YggFC "Yggdrasil Network router process on prefix FC00::/7 and port 9126"
```

The spaces after `binPath=`, `start=`, and `DisplayName=` are required by
`sc`.

PowerShell (elevated), with an explicit config path:

```powershell
New-Service -Name "YggFC" `
  -BinaryPathName "%ProgramFiles%\Yggdrasil-ng\ygg_fc.exe --service -c %ALLUSERSPROFILE%\Yggdrasil-ng\ygg_fc.toml" `
  -StartupType Automatic `
  -DisplayName "YggFC" `
  -Description "Yggdrasil Network router process on prefix FC00::/7 and port 9126"
```

PowerShell without a config path:

```powershell
New-Service -Name "YggFC" `
  -BinaryPathName "%ProgramFiles%\Yggdrasil-ng\ygg_fc.exe --service" `
  -StartupType Automatic `
  -DisplayName "YggFC" `
  -Description "Yggdrasil Network router process on prefix FC00::/7 and port 9126"
```

Start / stop / remove:

```cmd
sc start YggFC
sc stop YggFC
sc delete YggFC
```

```powershell
Start-Service YggFC
Stop-Service YggFC
```

---

## Protecting an isolated network

A custom prefix only puts you on a different overlay. It does not stop a
stranger who also runs `ygg_fc` from peering with you, and it does not
stop a mis-added public peer from bridging the two meshes.

Use both of the following on every personal node:

1. **Link password** — `?password=secret` on each `peers` URI and each
   `listen` URI (and the matching `password` on `[[multicast_interfaces]]`
   if you use LAN discovery). Only nodes that present the same secret
   form a direct link. See [Peer URI Query
   Parameters](../README.md#peer-uri-query-parameters) in the README.

2. **Closed-network group password** — set `group_password` to the same
   non-empty string on every member of the personal mesh. Encrypted
   sessions complete only with peers that use that exact value, even if
   a link was somehow established. Empty `group_password` is an open
   network. This is independent of the per-link `password`. See
   [Group password (closed networks)](../README.md#group-password-closed-networks)
   in the README.

Do not reuse the public-mesh `listen` port advertisement or the public
peer list on a personal node. Keep the two overlays on separate binaries
(or separate names) and separate config files.

---

## Possible prefix collisions

The filename parser accepts 127 theoretically possible `/7` prefixes
(first byte `00`, `02`, …, `fc`). That is the **flexibility** of the
mechanism: you can pick a `/7` that is still empty on *your* hosts.

It is **not** a claim that 127 Yggdrasil-ng overlays can run at the same
time on one machine, or that every value is unused on the Internet.
Part of that address space is almost certainly already occupied — by the
public Yggdrasil Network, by another overlay, by a LAN ULA, by IANA
special-purpose assignments, or by global unicast IPv6. Two networks
that share a `/7` will fight over routes and addresses on any host that
runs both.

`200::/7` (written `0200::/7` in some docs) is the public Yggdrasil
Network. Use a different prefix for a private overlay. The list below
is a practical map of the 127 values, not a routing-table dump.

- ⚠️ Prefix `0::/7` (`0000::/7`, suffix `00`). Collisions with IANA
  special-purpose space inside `::/7`: `64:ff9b::/96` (NAT64 well-known
  prefix, RFC 6052), `64:ff9b:1::/48` (RFC 8215), `100::/64` (discard-only,
  RFC 6666), `100:0:0:1::/64`, plus `::/128` (unspecified), `::1/128`
  (loopback), and `::ffff:0:0/96` (IPv4-mapped). A host with a NAT64
  gateway, or anything that depends on those ranges, can misbehave in
  ways that are hard to diagnose. For experienced or desperate operators
  only.

- ❌ Prefix `200::/7` (`0200::/7`, suffix `02`). Occupied by the public
  Yggdrasil Network. Do not use it for a private overlay if you want
  isolation from that mesh.

- ⚠️ Prefix `400::/7` (suffix `04`). May be occupied by the Mycelium
  Network (overlay addresses in `400::/7`).

- ✅ Range `600::/7`–`1e00::/7` (suffixes `06`–`1e`). Usually free. Safe
  to use on a typical host.

- ❌ Range `2000::/7`–`2e00::/7` (suffixes `20`–`2e`). Modern IPv6
  Internet (`2000::/3` global unicast). Do not use even if the ISP does
  not yet offer IPv6.

- ⚠️ Range `3000::/7`–`3e00::/7` (suffixes `30`–`3e`). Also inside
  `2000::/3`. Global unicast is expected to grow here, but not before
  about 2030. Theoretically usable until then.

- ✅ Range `4000::/7`–`5c00::/7` (suffixes `40`–`5c`). Usually free. Safe
  to use on a typical host.

- ❌ Prefix `5e00::/7` (suffix `5e`). Conflicts with `5f00::/16`. Usable
  only when the host has no IPv6 Internet connectivity and IPv4 is
  preferred over IPv6.

- ✅ Range `6000::/7`–`fa00::/7` (suffixes `60`–`fa`). Usually free. Safe
  to use on a typical host.

- ✅ Prefix `fc00::/7` (suffix `fc`). RFC 4193 unique-local address space,
  the usual choice for internal IPv6 networks. Recommended for a personal
  overlay **if** the host and its LAN do not already use ULA. If a ULA
  LAN is already present, this is the value in the set most likely to
  collide with something already on the network — pick another free
  prefix instead.
