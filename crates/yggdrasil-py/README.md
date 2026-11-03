# ygg

Python bindings for an embedded [Yggdrasil-ng](../../README.md) node.
Connections over the Yggdrasil network are ordinary `socket.socket` objects,
so blocking code, `selectors` and `asyncio` all work unchanged. No TUN
adapter, root or administrator rights are needed.

```bash
pip install maturin
maturin build --release        # wheel in target/wheels/ (abi3, Python >= 3.9)
# or, into the active virtualenv:
maturin develop --release
```

```python
import ygg

with ygg.Node(peers=["tls://peer.example.org:443"]) as node:
    print(node.address, node.public_key)

    # TCP client: hosts are addresses, hex keys or "<key>.pk.ygg"
    s = node.connect("200:1234::1", 80)
    s.sendall(b"GET / HTTP/1.0\r\n\r\n")

    # TCP server
    with node.listen(8080) as listener:
        conn, peer = listener.accept()

    # UDP
    with node.udp_bind() as u:
        u.sendto(b"hi", ("200:1234::1", 5353))
        data, (host, port) = u.recvfrom()

    print("rtt", node.ping("200:1234::1"))
    print(node.admin("getPeers"))
```

asyncio:

```python
reader, writer = await node.open_connection("<key>.pk.ygg", 80)

async def handle(reader, writer):
    writer.write(await reader.read(100))
    await writer.drain()
    writer.close()

server = await node.start_server(handle, 8080)
```

Also: `node.socks5("127.0.0.1:1080")`, `node.forward_local_tcp(...)`,
`node.forward_remote_tcp(...)` (and UDP variants), and
`ygg.log_to_python()` to route library logs into `logging`.

Errors map to built-in exceptions: `ConnectionRefusedError`, `TimeoutError`,
`BlockingIOError`, `ConnectionError` (node closed), `ValueError` (bad
argument or config) and `OSError`.
