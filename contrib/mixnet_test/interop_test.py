#!/usr/bin/env python3
"""
Yggdrasil interop integration tests: yggdrasil-go <-> yggdrasil-ng

Tests all transport combinations (TLS, QUIC, WS) between Go and Rust
implementations over IPv4, IPv6, and hostname. Runs without root —
uses IfName="none" (no TUN).

Rust binaries are discovered relative to this script (../../target/debug/).
Go binaries must be provided via the YGGDRASIL_GO_DIR environment variable.

Usage:
    export YGGDRASIL_GO_DIR=/path/to/yggdrasil-go   # dir containing 'yggdrasil' binary
    python3 interop_test.py [--verbose] [--filter tls] [--timeout 20]
"""

import argparse
import json
import os
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
        print("  cargo build --features all-transports")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Yggdrasil interop tests")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show node stdout/stderr")
    parser.add_argument("--filter", "-f", type=str, default=None,
                        help="Only run tests matching this substring")
    parser.add_argument("--timeout", "-t", type=int, default=15,
                        help="Peer connection timeout in seconds (default: 15)")
    args = parser.parse_args()

    check_binaries()

    # Filter test matrix
    tests = TEST_MATRIX
    if args.filter:
        tests = [(n, s, c, sch, a) for n, s, c, sch, a in tests
                 if args.filter.lower() in n.lower()]
        if not tests:
            print(f"No tests match filter '{args.filter}'")
            sys.exit(1)

    print(f"Running {len(tests)} interop tests...\n")

    results = []
    for i, (test_name, server_impl, client_impl, scheme, addr) in enumerate(tests):
        label = f"{scheme.upper():5s} {server_impl}(server) -> {client_impl}(client) @ {addr}"
        print(f"  [{i+1}/{len(tests)}] {label} ...", end=" ", flush=True)

        ok, msg = run_test(
            test_name, server_impl, client_impl, scheme, i,
            addr=addr, peer_timeout=args.timeout, verbose=args.verbose,
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
