"""Two in-process nodes peered over loopback."""

import asyncio
import socket
import threading
import time

import pytest

import ygg


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def pair():
    port = free_port()
    a = ygg.Node(listen=[f"tcp://127.0.0.1:{port}"], multicast=False)
    b = ygg.Node(peers=[f"tcp://127.0.0.1:{port}"], multicast=False)
    deadline = time.time() + 20
    while True:
        try:
            a.ping(b.address, timeout=1)
            break
        except TimeoutError:
            assert time.time() < deadline, "nodes did not connect"
    yield a, b
    a.close()
    b.close()


def test_identity(pair):
    a, b = pair
    assert a.address.startswith("20") and a.address != b.address
    assert b.subnet.endswith("/64")
    assert len(b.public_key) == 64
    assert b.resolve(f"{b.public_key}.pk.ygg") == b.address
    assert b.admin("getSelf")["address"] == b.address
    assert "Node" in repr(a)


def test_tcp_blocking_and_threads(pair):
    a, b = pair
    with b.listen(7000) as listener:
        with pytest.raises(BlockingIOError):
            listener.accept(timeout=0)

        def serve():
            conn, peer = listener.accept(timeout=10)
            with conn:
                data = b""
                while chunk := conn.recv(65536):
                    data += chunk
                conn.sendall(data[::-1])
            served.append(peer)

        served = []
        t = threading.Thread(target=serve)
        t.start()
        payload = bytes(range(256)) * 2000
        with a.connect(f"{b.public_key}.pk.ygg", 7000, timeout=20) as s:
            s.sendall(payload)
            s.shutdown(socket.SHUT_WR)
            back = b""
            while chunk := s.recv(65536):
                back += chunk
        t.join(10)
        assert back == payload[::-1]
        assert served and served[0].startswith(f"[{a.address}]:")

    with pytest.raises(ConnectionRefusedError):
        a.connect(b.address, 7999, timeout=10)
    with pytest.raises(ValueError):
        a.connect("example.com", 80)


def test_asyncio(pair):
    a, b = pair

    async def main():
        async def handle(reader, writer):
            line = await reader.readline()
            writer.write(line.upper())
            await writer.drain()
            writer.close()

        async with await b.start_server(handle, 7001):
            results = []
            for i in range(5):
                reader, writer = await a.open_connection(b.address, 7001, timeout=20)
                writer.write(f"hello {i}\n".encode())
                await writer.drain()
                results.append(await asyncio.wait_for(reader.readline(), 10))
                writer.close()
            return results

    assert asyncio.run(main()) == [f"HELLO {i}\n".encode() for i in range(5)]


def test_udp(pair):
    a, b = pair
    with b.udp_bind(9000) as server, a.udp_bind() as client:
        assert server.port == 9000 and client.port != 0
        server.settimeout(10)
        client.settimeout(10)
        client.sendto(b"ping", (f"{b.public_key}.pk.ygg", 9000))
        data, (host, port) = server.recvfrom()
        assert data == b"ping" and host == a.address and port == client.port
        server.sendto(b"pong", (host, port))
        assert client.recvfrom() == (b"pong", (b.address, 9000))

        async def roundtrip():
            await client.sendto_async(b"async", (b.address, 9000))
            data, addr = await asyncio.wait_for(server.recvfrom_async(), 10)
            return data, addr

        assert asyncio.run(roundtrip()) == (b"async", (a.address, client.port))


def test_services(pair):
    a, b = pair
    echo = socket.create_server(("127.0.0.1", 0))
    echo_port = echo.getsockname()[1]

    def run_echo():
        conn, _ = echo.accept()
        with conn:
            conn.sendall(conn.recv(100))

    threading.Thread(target=run_echo, daemon=True).start()
    front_port = free_port()
    with b.forward_remote_tcp(80, f"127.0.0.1:{echo_port}"), \
         a.forward_local_tcp(f"127.0.0.1:{front_port}", f"{b.public_key}.pk.ygg:80"):
        with pytest.raises(OSError) as e:
            b.forward_remote_tcp(80, f"127.0.0.1:{echo_port}")
        assert e.value.errno == __import__("errno").EADDRINUSE
        with socket.create_connection(("127.0.0.1", front_port), timeout=20) as s:
            s.sendall(b"forwarded")
            assert s.recv(100) == b"forwarded"
    echo.close()


def test_logging_and_config():
    records = []
    ygg._native.set_logger(lambda level, msg: records.append((level, msg)), "info")
    conf = ygg.generate_config()
    assert "private_key" in conf
    # A key given both in the config and as an argument is rejected.
    with pytest.raises(ValueError, match="duplicate key"):
        ygg.Node(conf, multicast=False)
    with ygg.Node(conf) as n:
        key = n.public_key
    assert any(key in msg for _, msg in records)
    with pytest.raises(ValueError):
        ygg.Node("this is = not [toml")
    with pytest.raises(RuntimeError):
        ygg._native.set_logger(print)


def test_close_wakes_blocked_accept():
    node = ygg.Node(multicast=False)
    listener = node.listen(7002)
    errors = []

    def waiter():
        try:
            listener.accept()
        except Exception as e:
            errors.append(e)

    t = threading.Thread(target=waiter)
    t.start()
    time.sleep(0.2)
    node.close()
    t.join(10)
    assert not t.is_alive()
    assert isinstance(errors[0], ConnectionError)
    listener.close()
    node.close()
    assert node.closed
    with pytest.raises(ConnectionError):
        node.connect("200::1", 80)


def test_connect_async_does_not_block(pair):
    a, b = pair

    async def main():
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                ticks += 1
                await asyncio.sleep(0.01)

        async def handle(reader, writer):
            writer.write(await reader.readline())
            await writer.drain()
            writer.close()

        async with await b.start_server(handle, 7010):
            t = asyncio.create_task(ticker())
            sock = await a.connect_async(f"{b.public_key}.pk.ygg", 7010, timeout=20)
            # No thread-pool thread was needed for the connect.
            assert not any(th.name.startswith("asyncio_") for th in threading.enumerate())
            reader, writer = await asyncio.open_connection(sock=sock)
            writer.write(b"line\n")
            await writer.drain()
            assert await asyncio.wait_for(reader.readline(), 10) == b"line\n"
            writer.close()

            with pytest.raises(ConnectionRefusedError):
                await a.connect_async(b.address, 7999, timeout=20)

            # Cancelling the task abandons a connect that cannot complete.
            pending = asyncio.create_task(a.connect_async("200:dead:beef::1", 80))
            await asyncio.sleep(0.2)
            assert not pending.done()
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            t.cancel()
        return ticks

    assert asyncio.run(main()) > 0


def test_network_hooks(pair):
    a, b = pair
    a.network_changed()
    a.set_network_interfaces([("wlan0", 3, ["fe80::1"])])
    with pytest.raises(ValueError):
        a.set_network_interfaces([("wlan0", 3, ["not an address"])])
    with ygg.Node(multicast=False, network_interfaces=[("lo", 1, ["::1"])]) as n:
        n.network_changed()
        n.close()
        with pytest.raises(ConnectionError):
            n.network_changed()
