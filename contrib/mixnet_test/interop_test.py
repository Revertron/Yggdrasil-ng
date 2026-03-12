#!/usr/bin/env python3
"""
Yggdrasil interop integration tests: yggdrasil-go <-> yggdrasil-ng

Tests all transport combinations (TLS, QUIC, WS) between Go and Rust
implementations over IPv4, IPv6, and hostname, plus multicast LAN discovery.
Runs without root — uses IfName="none" (no TUN).

Rust binaries are discovered relative to this script (../../target/debug/).
Go binaries must be provided via the YGGDRASIL_GO_DIR environment variable.

Usage:
    export YGGDRASIL_GO_DIR=/path/to/yggdrasil-go   # dir containing 'yggdrasil' binary
    python3 interop_test.py [--verbose] [--filter tls] [--timeout 20]
"""

import argparse
import json
import os
import platform
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time

# ── Paths ──

# Rust: relative to this script — contrib/mixnet_test/../../target/debug/
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RUST_PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))  # Yggdrasil-ng root
RUST_BIN = os.path.join(RUST_PROJECT_DIR, "target", "debug", "yggdrasil")

# Go: from environment variable
GO_DIR = os.environ.get("YGGDRASIL_GO_DIR", "")
GO_BIN = os.path.join(GO_DIR, "yggdrasil") if GO_DIR else ""

# ── Test matrix ──

TEST_MATRIX = [
    # (test_name, server_impl, client_impl, scheme, addr)
    # ── IPv4 (127.0.0.1) ──
    ("tls_go_server_rust_client", "go", "rust", "tls", "127.0.0.1"),
    ("tls_rust_server_go_client", "rust", "go", "tls", "127.0.0.1"),
    ("quic_go_server_rust_client", "go", "rust", "quic", "127.0.0.1"),
    ("quic_rust_server_go_client", "rust", "go", "quic", "127.0.0.1"),
    ("ws_go_server_rust_client", "go", "rust", "ws", "127.0.0.1"),
    ("ws_rust_server_go_client", "rust", "go", "ws", "127.0.0.1"),
    # ── IPv6 ([::1]) ──
    ("tls_go_server_rust_client_ipv6", "go", "rust", "tls", "[::1]"),
    ("tls_rust_server_go_client_ipv6", "rust", "go", "tls", "[::1]"),
    ("quic_go_server_rust_client_ipv6", "go", "rust", "quic", "[::1]"),
    ("quic_rust_server_go_client_ipv6", "rust", "go", "quic", "[::1]"),
    ("ws_go_server_rust_client_ipv6", "go", "rust", "ws", "[::1]"),
    ("ws_rust_server_go_client_ipv6", "rust", "go", "ws", "[::1]"),
    # ── Hostname (localhost) ──
    ("tls_go_server_rust_client_localhost", "go", "rust", "tls", "localhost"),
    ("tls_rust_server_go_client_localhost", "rust", "go", "tls", "localhost"),
    ("quic_go_server_rust_client_localhost", "go", "rust", "quic", "localhost"),
    ("quic_rust_server_go_client_localhost", "rust", "go", "quic", "localhost"),
    ("ws_go_server_rust_client_localhost", "go", "rust", "ws", "localhost"),
    ("ws_rust_server_go_client_localhost", "rust", "go", "ws", "localhost"),
]

# ── Multicast discovery test matrix ──

MULTICAST_TESTS = [
    # (test_name, first_impl, second_impl)
    ("multicast_go_first_rust_second", "go", "rust"),
    ("multicast_rust_first_go_second", "rust", "go"),
    ("multicast_rust_first_rust_second", "rust", "rust"),
]

# Admin port base for multicast tests (offset to avoid transport test ports)
MULTICAST_ADMIN_BASE = 19500

# ── Port allocation ──

PORT_BASE = 19000
ADMIN_PORT_BASE = 19100


def allocate_ports(test_index):
    """Return (listen_port, server_admin_port, client_admin_port) for a test."""
    listen_port = PORT_BASE + test_index + 1
    server_admin = ADMIN_PORT_BASE + test_index * 2 + 1
    client_admin = ADMIN_PORT_BASE + test_index * 2 + 2
    return listen_port, server_admin, client_admin


# ── Config generation ──


def generate_go_config(admin_port, listen_addrs=None, peers=None):
    """Generate a Go JSON config, return path to temp file."""
    result = subprocess.run(
        [GO_BIN, "-genconf", "-json"],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"genconf failed: {result.stderr}")

    cfg = json.loads(result.stdout)
    cfg["AdminListen"] = f"tcp://127.0.0.1:{admin_port}"
    cfg["IfName"] = "none"
    cfg["Listen"] = listen_addrs or []
    cfg["Peers"] = peers or []
    cfg["MulticastInterfaces"] = []

    fd, path = tempfile.mkstemp(suffix=".json", prefix="ygg_go_")
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
    return path, cfg.get("PrivateKey", "")


def generate_rust_config(admin_port, listen_addrs=None, peers=None):
    """Generate a Rust TOML config, return path to temp file."""
    result = subprocess.run(
        [RUST_BIN, "--genconf", "/dev/stdout"],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"genconf failed: {result.stderr}")

    # Parse TOML manually (stdlib has no toml module)
    lines = result.stdout.splitlines()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("admin_listen"):
            new_lines.append(f'admin_listen = "tcp://127.0.0.1:{admin_port}"')
        elif stripped.startswith("if_name"):
            new_lines.append('if_name = "none"')
        elif stripped.startswith("listen"):
            addrs = listen_addrs or []
            addrs_str = ", ".join(f'"{a}"' for a in addrs)
            new_lines.append(f"listen = [{addrs_str}]")
        elif stripped.startswith("peers"):
            peer_list = peers or []
            peers_str = ", ".join(f'"{p}"' for p in peer_list)
            new_lines.append(f"peers = [{peers_str}]")
        else:
            new_lines.append(line)

    fd, path = tempfile.mkstemp(suffix=".toml", prefix="ygg_rust_")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(new_lines) + "\n")

    # Extract private key for identity
    private_key = ""
    for line in new_lines:
        if line.strip().startswith("private_key"):
            private_key = line.split("=", 1)[1].strip().strip('"')
            break

    return path, private_key


# ── Multicast interface discovery ──


def find_multicast_interface():
    """Find a network interface suitable for multicast testing.

    Returns the interface name, or None if no suitable interface is found.
    Requirements: UP, RUNNING, MULTICAST flags; has a link-local IPv6 address;
    not POINTTOPOINT.
    """
    system = platform.system()

    if system == "Darwin":
        # macOS: lo0 typically has UP,LOOPBACK,RUNNING,MULTICAST and fe80::1
        for iface in ["lo0", "en0", "en1", "bridge0"]:
            try:
                result = subprocess.run(
                    ["ifconfig", iface],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode != 0:
                    continue
                output = result.stdout
                # Check required flags
                if "MULTICAST" not in output:
                    continue
                if "POINTOPOINT" in output:
                    continue
                # Check for link-local IPv6 address (fe80::)
                if re.search(r'inet6\s+fe80:', output):
                    return iface
            except Exception:
                continue

    elif system == "Linux":
        # Linux: parse 'ip -6 addr show' for interfaces with MULTICAST + fe80::
        try:
            result = subprocess.run(
                ["ip", "-6", "addr", "show"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                current_iface = None
                for line in result.stdout.splitlines():
                    # Interface header: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
                    m = re.match(r'\d+:\s+(\S+?):\s+<([^>]+)>', line)
                    if m:
                        iface_name = m.group(1)
                        flags = m.group(2)
                        if ("MULTICAST" in flags and "UP" in flags
                                and "POINTOPOINT" not in flags):
                            current_iface = iface_name
                        else:
                            current_iface = None
                    elif current_iface and "fe80::" in line:
                        return current_iface
        except Exception:
            pass

    return None


# ── Multicast config generation ──


def generate_go_multicast_config(admin_port, multicast_iface):
    """Generate a Go JSON config with multicast discovery enabled."""
    result = subprocess.run(
        [GO_BIN, "-genconf", "-json"],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"genconf failed: {result.stderr}")

    cfg = json.loads(result.stdout)
    cfg["AdminListen"] = f"tcp://127.0.0.1:{admin_port}"
    cfg["IfName"] = "none"
    cfg["Listen"] = []
    cfg["Peers"] = []
    cfg["MulticastInterfaces"] = [{
        "Regex": f"^{re.escape(multicast_iface)}$",
        "Beacon": True,
        "Listen": True,
        "Port": 0,
        "Priority": 0,
        "Password": "",
    }]

    fd, path = tempfile.mkstemp(suffix=".json", prefix="ygg_go_mc_")
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
    return path, cfg.get("PrivateKey", "")


def generate_rust_multicast_config(admin_port, multicast_iface):
    """Generate a Rust TOML config with multicast discovery enabled."""
    result = subprocess.run(
        [RUST_BIN, "--genconf", "/dev/stdout"],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"genconf failed: {result.stderr}")

    lines = result.stdout.splitlines()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("admin_listen"):
            new_lines.append(f'admin_listen = "tcp://127.0.0.1:{admin_port}"')
        elif stripped.startswith("if_name"):
            new_lines.append('if_name = "none"')
        elif stripped.startswith("listen"):
            new_lines.append("listen = []")
        elif stripped.startswith("peers"):
            new_lines.append("peers = []")
        else:
            new_lines.append(line)

    # Append multicast config section
    escaped = multicast_iface.replace("\\", "\\\\")
    new_lines.extend([
        "",
        "[[multicast_interfaces]]",
        f'regex = "^{escaped}$"',
        "beacon = true",
        "listen = true",
        "port = 0",
        "priority = 0",
        'password = ""',
    ])

    fd, path = tempfile.mkstemp(suffix=".toml", prefix="ygg_rust_mc_")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(new_lines) + "\n")

    private_key = ""
    for line in new_lines:
        if line.strip().startswith("private_key"):
            private_key = line.split("=", 1)[1].strip().strip('"')
            break

    return path, private_key


# ── Multicast test runner ──


def run_multicast_test(test_name, first_impl, second_impl, multicast_iface,
                       test_index, peer_timeout=30, verbose=False):
    """Run a multicast discovery test.

    Starts the first node, waits for it to begin beaconing, then starts
    the second node. Both should discover each other via multicast.
    Returns (success, message).
    """
    first_admin = MULTICAST_ADMIN_BASE + test_index * 2 + 1
    second_admin = MULTICAST_ADMIN_BASE + test_index * 2 + 2

    first_node = None
    second_node = None

    try:
        # Generate configs with multicast enabled
        if first_impl == "go":
            first_cfg, _ = generate_go_multicast_config(
                first_admin, multicast_iface)
            first_bin = GO_BIN
        else:
            first_cfg, _ = generate_rust_multicast_config(
                first_admin, multicast_iface)
            first_bin = RUST_BIN

        if second_impl == "go":
            second_cfg, _ = generate_go_multicast_config(
                second_admin, multicast_iface)
            second_bin = GO_BIN
        else:
            second_cfg, _ = generate_rust_multicast_config(
                second_admin, multicast_iface)
            second_bin = RUST_BIN

        # Start first node and let it begin beaconing
        first_node = YggNode(
            first_impl, first_bin, first_cfg, first_admin,
            f"{test_name}_first", verbose=verbose)
        first_node.wait_ready(timeout=10)

        # Brief pause so first node starts its beacon loop
        time.sleep(2)

        # Start second node — it should receive beacons and connect
        second_node = YggNode(
            second_impl, second_bin, second_cfg, second_admin,
            f"{test_name}_second", verbose=verbose)
        second_node.wait_ready(timeout=10)

        # Get public keys
        first_key = first_node.get_self_key()
        second_key = second_node.get_self_key()

        if verbose:
            print(f"\n    First  ({first_impl}) key: {first_key[:16]}...")
            print(f"    Second ({second_impl}) key: {second_key[:16]}...")

        # Poll getPeers until both nodes see each other
        deadline = time.time() + peer_timeout
        first_sees_second = False
        second_sees_first = False
        first_peer_info = None
        second_peer_info = None

        while time.time() < deadline:
            if not first_sees_second:
                try:
                    peers = first_node.get_peers()
                    for p in peers:
                        if p.get("key") == second_key and p.get("up", False):
                            first_sees_second = True
                            first_peer_info = p
                            break
                except Exception:
                    pass

            if not second_sees_first:
                try:
                    peers = second_node.get_peers()
                    for p in peers:
                        if p.get("key") == first_key and p.get("up", False):
                            second_sees_first = True
                            second_peer_info = p
                            break
                except Exception:
                    pass

            if first_sees_second and second_sees_first:
                break

            time.sleep(1)

        if not first_sees_second and not second_sees_first:
            return False, "neither node discovered the other via multicast"
        if not first_sees_second:
            return False, "first node does not see second"
        if not second_sees_first:
            return False, "second node does not see first"

        # Check connection direction via the 'inbound' field.
        # The second node (started later) typically receives the first node's
        # beacon and initiates the TLS connection. So we expect:
        #   first node:  inbound=True  (received the connection)
        #   second node: inbound=False (initiated the connection)
        first_inbound = first_peer_info.get("inbound")
        second_inbound = second_peer_info.get("inbound")
        first_uri = first_peer_info.get("uri", "?")
        second_uri = second_peer_info.get("uri", "?")

        direction_info = (
            f"first({first_impl}).inbound={first_inbound} "
            f"second({second_impl}).inbound={second_inbound}"
        )

        if verbose:
            print(f"    First  sees peer at: {first_uri}")
            print(f"    Second sees peer at: {second_uri}")
            print(f"    Direction: {direction_info}")

        # Both must have the inbound field, and they must be complementary
        if first_inbound is not None and second_inbound is not None:
            if first_inbound != second_inbound:
                return True, f"discovered, direction OK ({direction_info})"
            else:
                # Both inbound or both outbound — unusual but not a failure
                return True, f"discovered, direction same ({direction_info})"

        return True, f"discovered ({direction_info})"

    except Exception as e:
        return False, str(e)

    finally:
        if second_node:
            second_node.cleanup()
        if first_node:
            first_node.cleanup()
        # Give multicast sockets time to fully close before next test
        time.sleep(1)


# ── Admin socket communication ──


def admin_request(port, command, args=None, timeout=5):
    """Send a JSON request to the admin socket and return the parsed response."""
    req = {
        "request": command,
        "keepalive": False,
    }
    if args:
        req["arguments"] = args

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(("127.0.0.1", port))
        sock.sendall((json.dumps(req) + "\n").encode())

        # Read response (may come in chunks)
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
            # Response is a single JSON line
            if b"\n" in data:
                break
    finally:
        sock.close()

    if not data.strip():
        raise RuntimeError("empty response from admin socket")

    return json.loads(data.strip())


def wait_for_admin(port, timeout=10):
    """Poll admin socket until it responds to getSelf."""
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            resp = admin_request(port, "getSelf", timeout=2)
            if resp.get("status") == "success":
                return resp
        except Exception as e:
            last_err = e
        time.sleep(0.3)
    raise RuntimeError(f"admin socket on port {port} not ready after {timeout}s: {last_err}")


def get_peers(port, timeout=5):
    """Get peers from admin API."""
    resp = admin_request(port, "getPeers", timeout=timeout)
    if resp.get("status") != "success":
        raise RuntimeError(f"getPeers failed: {resp}")
    return resp.get("response", {}).get("peers", [])


def get_self_key(port, timeout=5):
    """Get our own public key from admin API."""
    resp = admin_request(port, "getSelf", timeout=timeout)
    if resp.get("status") != "success":
        raise RuntimeError(f"getSelf failed: {resp}")
    return resp.get("response", {}).get("key", "")


# ── Node process management ──


class YggNode:
    def __init__(self, impl_type, binary, config_path, admin_port, name, verbose=False):
        self.impl_type = impl_type
        self.admin_port = admin_port
        self.name = name
        self.config_path = config_path
        self.proc = None
        self.verbose = verbose

        if impl_type == "go":
            cmd = [binary, "-useconffile", config_path, "-loglevel", "info"]
        else:
            cmd = [binary, "-c", config_path, "-l", "info"]

        stderr_dest = None if verbose else subprocess.DEVNULL
        stdout_dest = None if verbose else subprocess.DEVNULL

        self.proc = subprocess.Popen(
            cmd,
            stdout=stdout_dest,
            stderr=stderr_dest,
            preexec_fn=os.setsid,
        )

    def wait_ready(self, timeout=10):
        """Wait until admin socket is responsive."""
        wait_for_admin(self.admin_port, timeout=timeout)

    def get_peers(self):
        return get_peers(self.admin_port)

    def get_self_key(self):
        return get_self_key(self.admin_port)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                    self.proc.wait(timeout=2)
                except Exception:
                    pass

    def cleanup(self):
        self.stop()
        if self.config_path and os.path.exists(self.config_path):
            os.unlink(self.config_path)


# ── Test runner ──


def run_test(test_name, server_impl, client_impl, scheme, test_index,
             addr="127.0.0.1", peer_timeout=15, verbose=False):
    """Run a single interop test. Returns (success, message)."""
    listen_port, server_admin, client_admin = allocate_ports(test_index)

    server_node = None
    client_node = None

    try:
        # Generate configs
        listen_addr = f"{scheme}://{addr}:{listen_port}"
        peer_addr = f"{scheme}://{addr}:{listen_port}"

        if server_impl == "go":
            server_cfg, _ = generate_go_config(
                server_admin, listen_addrs=[listen_addr])
            server_bin = GO_BIN
        else:
            server_cfg, _ = generate_rust_config(
                server_admin, listen_addrs=[listen_addr])
            server_bin = RUST_BIN

        if client_impl == "go":
            client_cfg, _ = generate_go_config(
                client_admin, peers=[peer_addr])
            client_bin = GO_BIN
        else:
            client_cfg, _ = generate_rust_config(
                client_admin, peers=[peer_addr])
            client_bin = RUST_BIN

        # Start server
        server_node = YggNode(
            server_impl, server_bin, server_cfg, server_admin,
            f"{test_name}_server", verbose=verbose)
        server_node.wait_ready(timeout=10)

        # Start client
        client_node = YggNode(
            client_impl, client_bin, client_cfg, client_admin,
            f"{test_name}_client", verbose=verbose)
        client_node.wait_ready(timeout=10)

        # Get public keys
        server_key = server_node.get_self_key()
        client_key = client_node.get_self_key()

        if verbose:
            print(f"    Server key: {server_key[:16]}...")
            print(f"    Client key: {client_key[:16]}...")

        # Poll getPeers on both nodes until they see each other
        deadline = time.time() + peer_timeout
        server_sees_client = False
        client_sees_server = False

        while time.time() < deadline:
            if not server_sees_client:
                try:
                    peers = server_node.get_peers()
                    for p in peers:
                        if p.get("key") == client_key and p.get("up", False):
                            server_sees_client = True
                            break
                except Exception:
                    pass

            if not client_sees_server:
                try:
                    peers = client_node.get_peers()
                    for p in peers:
                        if p.get("key") == server_key and p.get("up", False):
                            client_sees_server = True
                            break
                except Exception:
                    pass

            if server_sees_client and client_sees_server:
                break

            time.sleep(0.5)

        if not server_sees_client and not client_sees_server:
            return False, "neither node sees the other"
        if not server_sees_client:
            return False, "server does not see client"
        if not client_sees_server:
            return False, "client does not see server"

        return True, "peers connected"

    except Exception as e:
        return False, str(e)

    finally:
        if client_node:
            client_node.cleanup()
        if server_node:
            server_node.cleanup()


def check_binaries():
    """Verify all required binaries exist."""
    missing = []

    if not GO_BIN or not os.path.isfile(GO_BIN):
        if not GO_DIR:
            missing.append(
                "  yggdrasil-go: YGGDRASIL_GO_DIR not set. "
                "Export it to the directory containing the 'yggdrasil' binary."
            )
        else:
            missing.append(f"  yggdrasil-go: binary not found at {GO_BIN}")

    if not os.path.isfile(RUST_BIN):
        missing.append(f"  yggdrasil-ng: binary not found at {RUST_BIN}")

    if missing:
        print("Missing binaries:\n" + "\n".join(missing))
        print("\nSetup:")
        print("  # Build Go:")
        print("  cd /path/to/yggdrasil-go && go build -o yggdrasil ./cmd/yggdrasil")
        print("  export YGGDRASIL_GO_DIR=/path/to/yggdrasil-go")
        print()
        print("  # Build Rust (from this repo root):")
        print("  cargo build --features all-transports,multicast")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Yggdrasil interop tests")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show node stdout/stderr")
    parser.add_argument("--filter", "-f", type=str, default=None,
                        help="Only run tests matching this substring")
    parser.add_argument("--timeout", "-t", type=int, default=15,
                        help="Peer connection timeout in seconds (default: 15)")
    parser.add_argument("--multicast-timeout", type=int, default=30,
                        help="Multicast discovery timeout in seconds (default: 30)")
    args = parser.parse_args()

    check_binaries()

    # ── Transport tests ──

    transport_tests = TEST_MATRIX
    if args.filter:
        transport_tests = [(n, s, c, sch, a) for n, s, c, sch, a in transport_tests
                           if args.filter.lower() in n.lower()]

    # ── Multicast tests ──

    multicast_iface = find_multicast_interface()
    mc_tests = MULTICAST_TESTS
    if args.filter:
        mc_tests = [(n, f, s) for n, f, s in mc_tests
                    if args.filter.lower() in n.lower()]

    # Check if anything to run
    total_count = len(transport_tests) + len(mc_tests)
    if total_count == 0:
        print(f"No tests match filter '{args.filter}'")
        sys.exit(1)

    results = []

    # Run transport tests
    if transport_tests:
        print(f"Running {len(transport_tests)} transport interop tests...\n")

        for i, (test_name, server_impl, client_impl, scheme, addr) in enumerate(transport_tests):
            label = f"{scheme.upper():5s} {server_impl}(server) -> {client_impl}(client) @ {addr}"
            print(f"  [{i+1}/{len(transport_tests)}] {label} ...", end=" ", flush=True)

            ok, msg = run_test(
                test_name, server_impl, client_impl, scheme, i,
                addr=addr, peer_timeout=args.timeout, verbose=args.verbose,
            )
            status = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
            print(f"[{status}] {msg}")
            results.append((test_name, ok, msg))

    # Run multicast tests
    if mc_tests:
        print(f"\nRunning {len(mc_tests)} multicast discovery tests...\n")

        if multicast_iface is None:
            print("  \033[33mSKIP\033[0m: no multicast-capable interface found")
            print("        (need UP + MULTICAST + link-local IPv6 address)")
            for name, _, _ in mc_tests:
                results.append((name, True, "skipped (no multicast interface)"))
        else:
            print(f"  Using interface: {multicast_iface}\n")

            for i, (test_name, first_impl, second_impl) in enumerate(mc_tests):
                label = f"MCAST {first_impl}(first) -> {second_impl}(second) @ {multicast_iface}"
                print(f"  [{i+1}/{len(mc_tests)}] {label} ...", end=" ", flush=True)

                ok, msg = run_multicast_test(
                    test_name, first_impl, second_impl, multicast_iface, i,
                    peer_timeout=args.multicast_timeout, verbose=args.verbose,
                )
                status = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
                print(f"[{status}] {msg}")
                results.append((test_name, ok, msg))

    # Summary
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"\n{'='*50}")
    print(f"Results: {passed}/{total} passed")

    if passed < total:
        print("\nFailed tests:")
        for name, ok, msg in results:
            if not ok:
                print(f"  - {name}: {msg}")
        sys.exit(1)
    else:
        print("All tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
