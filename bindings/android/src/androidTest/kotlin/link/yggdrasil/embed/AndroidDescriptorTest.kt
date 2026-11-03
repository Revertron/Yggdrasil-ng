package link.yggdrasil.embed

import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.File
import java.net.ServerSocket
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Android-only checks: descriptors from the library are adopted by
 * ParcelFileDescriptor (owned under fdsan, which aborts the process on a
 * foreign close), handed back without double closes, and not leaked.
 */
class AndroidDescriptorTest {
    private lateinit var a: YggNode
    private lateinit var b: YggNode

    private fun freePort() = ServerSocket(0).use { it.localPort }

    private fun openFds(): Int = File("/proc/self/fd").list()!!.size

    @BeforeTest
    fun start() {
        val port = freePort()
        a = YggNode("listen = [\"tcp://127.0.0.1:$port\"]\nmulticast_interfaces = []\nadmin_listen = \"none\"\n")
        b = YggNode("peers = [\"tcp://127.0.0.1:$port\"]\nmulticast_interfaces = []\nadmin_listen = \"none\"\n")
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
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
    fun runsOnAndroidWithParcelFileDescriptor() {
        // The helpers pick the ParcelFileDescriptor path when this class exists.
        assertEquals(ParcelFileDescriptor::class.java, Class.forName("android.os.ParcelFileDescriptor"))
        assertTrue(Build.VERSION.SDK_INT >= 23)
        // A raw descriptor wraps like any other on Android.
        b.listen(7100).use { listener ->
            val server = thread {
                listener.accept(timeoutMs = 20_000).use { it.output.write(it.input.readExactly(4)) }
            }
            val fd = a.tcpConnect(b.address(), 7100u, 20_000u)
            ParcelFileDescriptor.adoptFd(fd).use { pfd ->
                ParcelFileDescriptor.AutoCloseOutputStream(ParcelFileDescriptor.dup(pfd.fileDescriptor))
                    .use { it.write("ping".toByteArray()) }
                ParcelFileDescriptor.AutoCloseInputStream(ParcelFileDescriptor.dup(pfd.fileDescriptor))
                    .use { assertContentEquals("ping".toByteArray(), it.readExactly(4)) }
            }
            server.join(20_000)
        }
    }

    @Test
    fun churnDoesNotLeakOrDoubleClose() {
        // Warm up lazily created descriptors (runtime, epoll, JNA) first.
        b.udp().close()
        val before = openFds()

        b.listen(7101).use { listener ->
            val server = thread {
                repeat(30) {
                    listener.accept(timeoutMs = 20_000).use { conn ->
                        conn.output.write(conn.input.readBytes())   // echo until EOF
                    }
                }
            }
            repeat(30) { i ->
                a.connect(b.address(), 7101, timeoutMs = 20_000).use { s ->
                    val msg = "message $i".toByteArray()
                    s.output.write(msg)
                    s.shutdownOutput()
                    assertContentEquals(msg, s.input.readBytes())
                }
            }
            server.join(30_000)
        }
        repeat(30) {
            // close() detaches the descriptor from Java before the library
            // closes it; a double close would trip fdsan and crash the run.
            b.udp().use { u -> a.udp().use { c -> c.send(b.address(), u.port, byteArrayOf(1)); u.receive() } }
            b.listen(7102).close()
        }

        // Library-side bridges finish asynchronously after the last close.
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        var after = openFds()
        while (after > before + 4 && System.nanoTime() < deadline) {
            Thread.sleep(100)
            after = openFds()
        }
        assertTrue(after <= before + 4, "descriptor leak: $before before, $after after")
    }
}
