"""Minimal ctypes binding for libygg.

Connections come back as regular Python sockets, so they work with blocking
code, selectors and asyncio alike:

    node = Node(config_toml)              # or Node() for an ephemeral node
    s = node.connect("<hex key>.pk.ygg", 80)
    reader, writer = await asyncio.open_connection(sock=s)

Set YGG_LIB to the library path if it is not on the loader path.
"""

import ctypes
import ctypes.util
import ipaddress
import os
import socket
import struct
import sys

YGG_UDP_HEADER_LEN = 18
_WIN = sys.platform == "win32"
_sock_t = ctypes.c_size_t if _WIN else ctypes.c_int
_INVALID = (1 << (8 * ctypes.sizeof(ctypes.c_size_t))) - 1 if _WIN else -1


def _load():
    path = os.environ.get("YGG_LIB") or ctypes.util.find_library("ygg")
    if not path:
        raise OSError("libygg not found; set YGG_LIB")
    lib = ctypes.CDLL(path)
    c_char_p, c_void_p, c_int, c_size_t = ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t
    sigs = {
        "ygg_last_error": (c_int, []),
        "ygg_last_error_message": (c_char_p, []),
        "ygg_free_string": (None, [c_void_p]),
        "ygg_node_start": (c_void_p, [c_char_p, ctypes.c_uint32]),
        "ygg_node_stop": (None, [c_void_p]),
        "ygg_node_address": (c_int, [c_void_p, c_char_p, c_size_t]),
        "ygg_node_public_key": (c_int, [c_void_p, c_char_p, c_size_t]),
        "ygg_node_add_peer": (c_int, [c_void_p, c_char_p]),
        "ygg_node_admin": (c_void_p, [c_void_p, c_char_p]),
        "ygg_tcp_connect": (_sock_t, [c_void_p, c_char_p, ctypes.c_uint16, c_int]),
        "ygg_tcp_listen": (_sock_t, [c_void_p, ctypes.c_uint16]),
        "ygg_tcp_accept": (_sock_t, [c_void_p, _sock_t, c_char_p, c_size_t, c_int]),
        "ygg_tcp_listener_close": (c_int, [c_void_p, _sock_t]),
        "ygg_udp_bind": (_sock_t, [c_void_p, ctypes.c_uint16, ctypes.POINTER(ctypes.c_uint16)]),
        "ygg_udp_close": (c_int, [c_void_p, _sock_t]),
        "ygg_ping": (ctypes.c_int64, [c_void_p, c_char_p, c_int]),
    }
    for name, (res, args) in sigs.items():
        fn = getattr(lib, name)
        fn.restype, fn.argtypes = res, args
    return lib


_lib = _load()


class YggError(OSError):
    pass


def _check(ok):
    if not ok:
        raise YggError(_lib.ygg_last_error(), _lib.ygg_last_error_message().decode())


def _string(fn, node):
    buf = ctypes.create_string_buffer(128)
    _check(fn(node, buf, len(buf)) > 0)
    return buf.value.decode()


class Node:
    def __init__(self, config_toml=None):
        self._node = _lib.ygg_node_start(config_toml.encode() if config_toml else None, 0)
        _check(self._node)

    @property
    def address(self):
        return _string(_lib.ygg_node_address, self._node)

    @property
    def public_key(self):
        return _string(_lib.ygg_node_public_key, self._node)

    def add_peer(self, uri):
        _check(_lib.ygg_node_add_peer(self._node, uri.encode()) == 0)

    def admin(self, request, **arguments):
        import json
        ptr = _lib.ygg_node_admin(self._node, json.dumps({"request": request, "arguments": arguments}).encode())
        _check(ptr)
        try:
            return json.loads(ctypes.string_at(ptr).decode())
        finally:
            _lib.ygg_free_string(ptr)

    def connect(self, host, port, timeout_ms=0):
        fd = _lib.ygg_tcp_connect(self._node, host.encode(), port, timeout_ms)
        _check(fd != _INVALID)
        return socket.socket(fileno=fd)

    def listen(self, port):
        return Listener(self, port)

    def udp_bind(self, port=0):
        return UdpSocket(self, port)

    def ping(self, host, timeout_ms=5000):
        """Round-trip time in seconds."""
        r = _lib.ygg_ping(self._node, host.encode(), timeout_ms)
        _check(r >= 0)
        return r / 1e6

    def close(self):
        if self._node:
            _lib.ygg_node_stop(self._node)
            self._node = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class Listener:
    """`fileno()` becomes readable when accept() has a connection."""

    def __init__(self, node, port):
        self._node = node
        self._fd = _lib.ygg_tcp_listen(node._node, port)
        _check(self._fd != _INVALID)

    def fileno(self):
        return self._fd

    def accept(self, timeout_ms=-1):
        peer = ctypes.create_string_buffer(80)
        fd = _lib.ygg_tcp_accept(self._node._node, self._fd, peer, len(peer), timeout_ms)
        _check(fd != _INVALID)
        return socket.socket(fileno=fd), peer.value.decode()

    def close(self):
        _lib.ygg_tcp_listener_close(self._node._node, self._fd)


class UdpSocket:
    def __init__(self, node, port):
        self._node = node
        bound = ctypes.c_uint16()
        fd = _lib.ygg_udp_bind(node._node, port, ctypes.byref(bound))
        _check(fd != _INVALID)
        self.port = bound.value
        self._fd = fd
        self.sock = socket.socket(fileno=fd)

    def sendto(self, data, addr):
        host, port = addr
        self.sock.send(ipaddress.IPv6Address(host).packed + struct.pack(">H", port) + data)

    def recvfrom(self, size=65535):
        msg = self.sock.recv(size + YGG_UDP_HEADER_LEN)
        host = str(ipaddress.IPv6Address(msg[:16]))
        (port,) = struct.unpack(">H", msg[16:18])
        return msg[YGG_UDP_HEADER_LEN:], (host, port)

    def close(self):
        self.sock.detach()
        _lib.ygg_udp_close(self._node._node, self._fd)


if __name__ == "__main__":
    # python3 ygg.py PEER_URI HOST PORT MESSAGE  -> prints the echoed reply
    import asyncio

    peer, host, port, message = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    with Node(f'peers = ["{peer}"]\nmulticast_interfaces = []\nadmin_listen = "none"\n') as node:
        print("our address:", node.address)
        print("ping: %.1f ms" % (node.ping(host, 10000) * 1000))

        async def main():
            reader, writer = await asyncio.open_connection(sock=node.connect(host, port))
            writer.write(message.encode())
            await writer.drain()
            reply = await reader.readexactly(len(message))
            writer.close()
            await writer.wait_closed()
            return reply.decode()

        print("reply:", asyncio.run(main()))
