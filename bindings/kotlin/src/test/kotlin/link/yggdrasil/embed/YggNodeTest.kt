package link.yggdrasil.embed

import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** InputStream.readNBytes needs Android API 33; tests also run on older devices. */
internal fun java.io.InputStream.readExactly(n: Int): ByteArray {
    val buf = ByteArray(n)
    var off = 0
    while (off < n) {
        val r = read(buf, off, n - off)
        if (r < 0) throw java.io.EOFException("got $off of $n bytes")
        off += r
    }
    return buf
}

/** Two nodes in this JVM (or Android process), peered over loopback. */
class YggNodeTest {
    private lateinit var a: YggNode
    private lateinit var b: YggNode

    private fun freePort() = ServerSocket(0).use { it.localPort }

    @BeforeTest
    fun start() {
        val port = freePort()
        a = YggNode("listen = [\"tcp://127.0.0.1:$port\"]\nmulticast_interfaces = []\nadmin_listen = \"none\"\n")
        b = YggNode("peers = [\"tcp://127.0.0.1:$port\"]\nmulticast_interfaces = []\nadmin_listen = \"none\"\n")
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        while (true) {
            try {
                a.ping(b.address(), 1000u)
                break
            } catch (e: YggException.TimedOut) {
                assertTrue(System.nanoTime() < deadline, "nodes did not connect")
            }
        }
    }

    @AfterTest
    fun stop() {
        a.close()
        b.close()
    }

    @Test
    fun identity() {
        assertTrue(a.address().startsWith("20"))
        assertEquals(64, b.publicKey().length)
        assertTrue(b.subnet().endsWith("/64"))
        assertEquals(b.address(), a.resolve("${b.publicKey()}.pk.ygg"))
        assertTrue(b.admin("{\"request\":\"getSelf\"}").contains(b.address()))
        assertTrue(generateConfig().contains("private_key"))
    }

    @Test
    fun tcpEchoWithHalfClose() {
        b.listen(7000).use { listener ->
            assertFailsWith<YggException.WouldBlock> { listener.accept(timeoutMs = 0) }
            val peers = CopyOnWriteArrayList<String>()
            val server = thread {
                listener.accept(timeoutMs = 10_000).use { conn ->
                    peers += conn.peer!!
                    val data = conn.input.readBytes()          // until the client's EOF
                    conn.output.write(data.reversedArray())
                }
            }
            val payload = ByteArray(200_000) { (it % 251).toByte() }
            a.connect("${b.publicKey()}.pk.ygg", 7000, timeoutMs = 20_000).use { s ->
                s.output.write(payload)
                s.shutdownOutput()
                assertContentEquals(payload.reversedArray(), s.input.readBytes())
            }
            server.join(10_000)
            assertTrue(peers.single().startsWith("[${a.address()}]:"))
        }
        assertFailsWith<YggException.ConnectionRefused> { a.connect(b.address(), 7999, timeoutMs = 10_000) }
        assertFailsWith<YggException.InvalidArgument> { a.connect("example.com", 80) }
    }

    @Test
    fun udp() {
        b.udp(9000).use { server ->
            a.udp().use { client ->
                assertEquals(9000, server.port)
                client.send("${b.publicKey()}.pk.ygg", 9000, "ping".toByteArray())
                val got = server.receive()
                assertEquals(YggDatagram(a.address(), client.port, "ping".toByteArray()), got)
                server.send(got.host, got.port, "pong".toByteArray())
                assertEquals(YggDatagram(b.address(), 9000, "pong".toByteArray()), client.receive())
            }
        }
    }

    @Test
    fun forwards() {
        val echo = ServerSocket(0)
        thread(isDaemon = true) {
            echo.accept().use { c -> c.getOutputStream().write(c.getInputStream().readExactly(5)) }
        }
        val front = freePort()
        val remote = b.forwardRemoteTcp(80u, "127.0.0.1:${echo.localPort}")
        val local = a.forwardLocalTcp("127.0.0.1:$front", "${b.publicKey()}.pk.ygg:80")
        assertFailsWith<YggException.AddrInUse> { b.forwardRemoteTcp(80u, "127.0.0.1:1") }
        Socket("127.0.0.1", front).use { s ->
            s.soTimeout = 20_000
            s.getOutputStream().write("hello".toByteArray())
            assertEquals("hello", String(s.getInputStream().readExactly(5)))
        }
        a.serviceStop(local)
        b.serviceStop(remote)
        assertFailsWith<YggException.NotFound> { b.serviceStop(remote) }
        echo.close()
    }

    @Test
    fun closeWakesBlockedAccept() {
        val listener = b.listen(7001)
        val errors = CopyOnWriteArrayList<Throwable>()
        val waiter = thread {
            try {
                listener.accept()
            } catch (e: Throwable) {
                errors += e
            }
        }
        Thread.sleep(200)
        b.shutdown()
        waiter.join(10_000)
        assertTrue(errors.single() is YggException.Closed)
        // After shutdown the listener handle is closed by the wrapper itself.
        val handle = java.io.File("/proc/self/fd/${listener.fd}")
        val procFs = java.io.File("/proc/self/fd").isDirectory
        if (procFs) assertTrue(handle.exists(), "listener handle should be open")
        listener.close()
        if (procFs) assertTrue(!handle.exists(), "listener handle leaked after close")
        assertTrue(b.isClosed())
        assertFailsWith<YggException.Closed> { b.address() }
    }

    @Test
    fun suspendConnect(): Unit = kotlinx.coroutines.runBlocking {
        b.listen(7002).use { listener ->
            val server = thread {
                listener.accept(timeoutMs = 20_000).use { it.output.write(it.input.readExactly(5)) }
            }
            a.connectAsync("${b.publicKey()}.pk.ygg", 7002, timeoutMs = 20_000).use { s ->
                s.output.write("async".toByteArray())
                assertEquals("async", String(s.input.readExactly(5)))
            }
            server.join(10_000)
        }
        assertFailsWith<YggException.ConnectionRefused> { a.connectAsync(b.address(), 7999, timeoutMs = 20_000) }
        // Cancellation abandons a connect that cannot complete.
        assertFailsWith<kotlinx.coroutines.TimeoutCancellationException> {
            kotlinx.coroutines.withTimeout(300) { a.connectAsync("200:dead:beef::1", 80) }
        }
    }

    @Test
    fun networkHooks() {
        a.networkChanged()
        a.setNetworkInterfaces(systemNetworkInterfaces())
        a.setNetworkInterfaces(listOf(NetworkInterface("wlan0", 3u, listOf("fe80::1%wlan0"))))
        assertFailsWith<YggException.InvalidArgument> {
            a.setNetworkInterfaces(listOf(NetworkInterface("wlan0", 3u, listOf("not an address"))))
        }
        YggNode(
            "multicast_interfaces = []\nadmin_listen = \"none\"\n",
            networkInterfaces = listOf(NetworkInterface("lo", 1u, listOf("::1"))),
        ).use { node ->
            node.networkChanged()
            node.shutdown()
            assertFailsWith<YggException.Closed> { node.networkChanged() }
        }
    }

    @Test
    fun badConfig() {
        assertFailsWith<YggException.Config> { YggNode("this is = not [toml") }
    }
}

/** Logger installation is process-wide, so it gets its own class/order-independent check. */
class LoggingTest {
    @Test
    fun logsReachTheSink() {
        val lines = CopyOnWriteArrayList<String>()
        setLogger(object : LogSink {
            override fun log(level: Int, message: String) {
                lines += "$level $message"
            }
        }, "info")
        val node = YggNode("multicast_interfaces = []\nadmin_listen = \"none\"\n")
        val key = node.use { it.publicKey() }
        assertTrue(lines.any { it.startsWith("3 ") && it.contains(key) }, lines.joinToString("\n"))
    }
}

class FormatTest {
    private fun bytes(vararg groups: Int) =
        ByteArray(16) { i -> (groups[i / 2] shr (if (i % 2 == 0) 8 else 0)).toByte() }

    @Test
    fun matchesRustAddressFormatting() {
        assertEquals("200:1234:5678:9abc:def0:1:2:3", formatIpv6(bytes(0x200, 0x1234, 0x5678, 0x9abc, 0xdef0, 1, 2, 3)))
        assertEquals("200:0:1:2:3:4:5:6", formatIpv6(bytes(0x200, 0, 1, 2, 3, 4, 5, 6)))       // single zero group stays
        assertEquals("200:0:0:1::1", formatIpv6(bytes(0x200, 0, 0, 1, 0, 0, 0, 1)))            // longest run wins
        assertEquals("200::1:0:0:1:1", formatIpv6(bytes(0x200, 0, 0, 1, 0, 0, 1, 1)))        // tie: first run
        assertEquals("300::", formatIpv6(bytes(0x300, 0, 0, 0, 0, 0, 0, 0)))
        assertEquals("::1", formatIpv6(bytes(0, 0, 0, 0, 0, 0, 0, 1)))
        assertEquals("200:0:0:1:2::", formatIpv6(bytes(0x200, 0, 0, 1, 2, 0, 0, 0)))
    }
}
