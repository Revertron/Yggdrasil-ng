"""Embedded Yggdrasil node: TCP/UDP over the Yggdrasil network as ordinary
Python sockets, without a TUN adapter or elevated privileges.

    import ygg

    with ygg.Node(peers=["tls://peer.example.org:443"]) as node:
        print(node.address)
        s = node.connect("<hex key>.pk.ygg", 80)       # a socket.socket
        s.sendall(b"GET / HTTP/1.0\\r\\n\\r\\n")

asyncio:

    reader, writer = await node.open_connection("200:1234::1", 80)
    server = await node.start_server(handle_client, 8080)

Hosts are IPv6 addresses in 200::/7, hex public keys or "<hex key>.pk.ygg".
Blocking calls release the GIL.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
import struct
from typing import Any, Awaitable, Callable, Iterable, Optional, Tuple

from . import _native
from ._native import UDP_HEADER_LEN, generate_config

__version__ = _native.__version__
__all__ = [
    "Node",
    "Listener",
    "UdpSocket",
    "Service",
    "Server",
    "generate_config",
    "log_to_python",
    "UDP_HEADER_LEN",
]

_LEVELS = {
    1: logging.ERROR,
    2: logging.WARNING,
    3: logging.INFO,
    4: logging.DEBUG,
    5: logging.DEBUG,
}


def log_to_python(logger: Optional[logging.Logger] = None, filter: str = "info") -> None:
    """Forward the library's log output to a `logging` logger ("ygg" by
    default). `filter` uses tracing EnvFilter syntax, e.g. "info" or
    "warn,yggdrasil::links=debug". Can be called once per process."""
    log = logger or logging.getLogger("ygg")
    _native.set_logger(lambda level, message: log.log(_LEVELS.get(level, logging.INFO), message), filter)


def _toml_list(values: Iterable[str]) -> str:
    # JSON string arrays are valid TOML arrays.
    return json.dumps(list(values))


class Node:
    """A running Yggdrasil node.

    `config` is a Yggdrasil TOML configuration (see `generate_config()`);
    without it the node uses defaults and an ephemeral key. `peers` and
    `listen` are appended to it. TUN settings are ignored; `admin=True` also
    starts the admin socket on the config's `admin_listen`.
    """

    def __init__(
        self,
        config: Optional[str] = None,
        *,
        peers: Iterable[str] = (),
        listen: Iterable[str] = (),
        multicast: Optional[bool] = None,
        admin: bool = False,
    ) -> None:
        extra = []
        peers, listen = list(peers), list(listen)
        if peers:
            extra.append(f"peers = {_toml_list(peers)}")
        if listen:
            extra.append(f"listen = {_toml_list(listen)}")
        if multicast is False:
            extra.append("multicast_interfaces = []")
        if extra:
            # Top-level keys must precede any [table] in TOML; a key given both
            # here and in `config` is reported as a duplicate (ValueError).
            config = "\n".join(extra) + "\n" + (config or "")
        self._native = _native.NativeNode(config, admin)

    # ---- identity and control

    @property
    def address(self) -> str:
        return self._native.address()

    @property
    def subnet(self) -> str:
        return self._native.subnet()

    @property
    def public_key(self) -> str:
        """Hex-encoded public key; `f"{node.public_key}.pk.ygg"` names this node."""
        return self._native.public_key()

    def add_peer(self, uri: str) -> None:
        self._native.add_peer(uri)

    def remove_peer(self, uri: str) -> None:
        self._native.remove_peer(uri)

    def admin(self, request: str, **arguments: Any) -> Any:
        """Run an admin API request, e.g. `node.admin("getPeers")`. Returns
        the "response" part; raises RuntimeError on an error status."""
        reply = json.loads(self._native.admin(json.dumps({"request": request, "arguments": arguments})))
        if reply.get("status") != "success":
            raise RuntimeError(reply.get("error", "admin request failed"))
        return reply.get("response")

    def resolve(self, host: str) -> str:
        """IPv6 address of `host` (an address, hex key or `<key>.pk.ygg`)."""
        return self._native.resolve(host)

    def ping(self, host: str, timeout: Optional[float] = 5.0) -> float:
        """ICMPv6 echo; returns the round-trip time in seconds."""
        return self._native.ping(host, timeout)

    # ---- TCP

    def connect(self, host: str, port: int, timeout: Optional[float] = None) -> socket.socket:
        """Open a TCP connection; returns a connected `socket.socket`."""
        return socket.socket(fileno=self._native.tcp_connect(host, port, timeout))

    def listen(self, port: int) -> "Listener":
        return Listener(self, port)

    async def connect_async(self, host: str, port: int, timeout: Optional[float] = None) -> socket.socket:
        loop = asyncio.get_running_loop()
        fd = await loop.run_in_executor(None, self._native.tcp_connect, host, port, timeout)
        return socket.socket(fileno=fd)

    async def open_connection(
        self, host: str, port: int, timeout: Optional[float] = None, **kwargs: Any
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Like `asyncio.open_connection`, over Yggdrasil."""
        sock = await self.connect_async(host, port, timeout)
        return await asyncio.open_connection(sock=sock, **kwargs)

    async def start_server(
        self,
        client_connected_cb: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Optional[Awaitable[None]]],
        port: int,
    ) -> "Server":
        """Like `asyncio.start_server`, on Yggdrasil `port`."""
        return Server(self.listen(port), client_connected_cb)

    # ---- UDP

    def udp_bind(self, port: int = 0) -> "UdpSocket":
        return UdpSocket(self, port)

    # ---- proxy services

    def socks5(self, listen: str, username: Optional[str] = None, password: Optional[str] = None) -> "Service":
        """SOCKS5 server on host address `listen` ("127.0.0.1:1080")."""
        return Service(self, self._native.socks5_start(listen, username, password))

    def forward_local_tcp(self, listen: str, target: str) -> "Service":
        """Host TCP `listen` ("127.0.0.1:8080") -> Yggdrasil `target` ("[addr]:port")."""
        return Service(self, self._native.forward_local_tcp(listen, target))

    def forward_local_udp(self, listen: str, target: str) -> "Service":
        return Service(self, self._native.forward_local_udp(listen, target))

    def forward_remote_tcp(self, port: int, target: str) -> "Service":
        """Yggdrasil TCP `port` -> host service `target` ("127.0.0.1:8000")."""
        return Service(self, self._native.forward_remote_tcp(port, target))

    def forward_remote_udp(self, port: int, target: str) -> "Service":
        return Service(self, self._native.forward_remote_udp(port, target))

    # ---- lifecycle

    @property
    def closed(self) -> bool:
        return self._native.closed()

    def close(self) -> None:
        """Stop the node. Open connections see EOF. Idempotent."""
        self._native.close()

    def __enter__(self) -> "Node":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        if self.closed:
            return "<ygg.Node closed>"
        return f"<ygg.Node {self.address}>"


class Listener:
    """Accepts TCP connections on a Yggdrasil port. `fileno()` becomes
    readable when `accept()` has a connection (usable with select/selectors).
    """

    def __init__(self, node: Node, port: int) -> None:
        self._node = node
        self.port = port
        self._fd = node._native.tcp_listen(port)
        self._closed = False

    def fileno(self) -> int:
        return self._fd

    def accept(self, timeout: Optional[float] = None) -> Tuple[socket.socket, str]:
        """Returns (socket, "[addr]:port"). `timeout=None` waits forever;
        `timeout=0` raises BlockingIOError when nothing is pending."""
        fd, peer = self._node._native.tcp_accept(self._fd, timeout)
        return socket.socket(fileno=fd), peer

    async def accept_async(self) -> Tuple[socket.socket, str]:
        loop = asyncio.get_running_loop()
        while True:
            try:
                return self.accept(timeout=0)
            except BlockingIOError:
                pass
            ready = loop.create_future()
            try:
                loop.add_reader(self._fd, lambda: ready.done() or ready.set_result(None))
            except NotImplementedError:
                # Event loops without add_reader (Windows proactor).
                return await loop.run_in_executor(None, self.accept, None)
            try:
                await ready
            finally:
                loop.remove_reader(self._fd)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            if not self._node.closed:
                self._node._native.tcp_listener_close(self._fd)
            else:
                socket.socket(fileno=self._fd).close()

    def __enter__(self) -> "Listener":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class Server:
    """asyncio server on a Yggdrasil port (see `Node.start_server`)."""

    def __init__(self, listener: Listener, client_connected_cb: Callable[..., Any]) -> None:
        self._listener = listener
        self._cb = client_connected_cb
        self._clients: set = set()
        self._task = asyncio.get_running_loop().create_task(self._serve())

    @property
    def port(self) -> int:
        return self._listener.port

    async def _serve(self) -> None:
        while True:
            try:
                sock, _ = await self._listener.accept_async()
            except (ConnectionError, OSError):
                return
            task = asyncio.get_running_loop().create_task(self._client(sock))
            self._clients.add(task)
            task.add_done_callback(self._clients.discard)

    async def _client(self, sock: socket.socket) -> None:
        reader, writer = await asyncio.open_connection(sock=sock)
        result = self._cb(reader, writer)
        if asyncio.iscoroutine(result):
            await result

    def close(self) -> None:
        self._task.cancel()
        self._listener.close()

    async def wait_closed(self) -> None:
        try:
            await self._task
        except asyncio.CancelledError:
            pass

    async def __aenter__(self) -> "Server":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        self.close()
        await self.wait_closed()


class UdpSocket:
    """A UDP port on the node's address."""

    def __init__(self, node: Node, port: int) -> None:
        self._node = node
        self._fd, self.port = node._native.udp_bind(port)
        self.sock = socket.socket(fileno=self._fd)
        self._resolved: dict = {}

    def fileno(self) -> int:
        return self._fd

    def _frame(self, data: bytes, addr: Tuple[str, int]) -> bytes:
        host, port = addr
        ip = self._resolved.get(host)
        if ip is None:
            ip = ipaddress.IPv6Address(self._node.resolve(host)).packed
            self._resolved[host] = ip
        return ip + struct.pack(">H", port) + bytes(data)

    @staticmethod
    def _unframe(msg: bytes) -> Tuple[bytes, Tuple[str, int]]:
        if len(msg) < UDP_HEADER_LEN:
            raise OSError("short datagram")
        host = str(ipaddress.IPv6Address(msg[:16]))
        (port,) = struct.unpack(">H", msg[16:UDP_HEADER_LEN])
        return msg[UDP_HEADER_LEN:], (host, port)

    def sendto(self, data: bytes, addr: Tuple[str, int]) -> int:
        """Send `data` to (host, port); host may also be a public key."""
        self.sock.send(self._frame(data, addr))
        return len(data)

    def recvfrom(self, bufsize: int = 65535) -> Tuple[bytes, Tuple[str, int]]:
        return self._unframe(self.sock.recv(bufsize + UDP_HEADER_LEN))

    def settimeout(self, timeout: Optional[float]) -> None:
        self.sock.settimeout(timeout)

    async def sendto_async(self, data: bytes, addr: Tuple[str, int]) -> int:
        self.sock.setblocking(False)
        await asyncio.get_running_loop().sock_sendall(self.sock, self._frame(data, addr))
        return len(data)

    async def recvfrom_async(self, bufsize: int = 65535) -> Tuple[bytes, Tuple[str, int]]:
        self.sock.setblocking(False)
        msg = await asyncio.get_running_loop().sock_recv(self.sock, bufsize + UDP_HEADER_LEN)
        return self._unframe(msg)

    def close(self) -> None:
        if self.sock.fileno() == -1:
            return
        self.sock.detach()
        if not self._node.closed:
            self._node._native.udp_close(self._fd)
        else:
            socket.socket(fileno=self._fd).close()

    def __enter__(self) -> "UdpSocket":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class Service:
    """A running SOCKS5 server or port forward."""

    def __init__(self, node: Node, service_id: int) -> None:
        self._node = node
        self.id = service_id

    def stop(self) -> None:
        self._node._native.service_stop(self.id)

    def __enter__(self) -> "Service":
        return self

    def __exit__(self, *exc: Any) -> None:
        if not self._node.closed:
            self.stop()
