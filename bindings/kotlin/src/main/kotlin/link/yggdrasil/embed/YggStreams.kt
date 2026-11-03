// Hand-written helpers on top of the generated bindings (yggdrasil_uniffi.kt):
// Int ports, Java streams over the returned descriptors, UDP framing.
package link.yggdrasil.embed

import java.io.Closeable
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * Turns a raw descriptor from [YggNode] into a [FileDescriptor], taking
 * ownership. Uses `ParcelFileDescriptor.adoptFd` on Android; on a desktop JVM
 * it needs `--add-opens java.base/java.io=ALL-UNNAMED`.
 */
internal object Descriptors {
    private val parcelAdopt = runCatching {
        Class.forName("android.os.ParcelFileDescriptor").getMethod("adoptFd", Int::class.javaPrimitiveType)
    }.getOrNull()

    /** Returns the FileDescriptor and the object that owns (and closes) it. */
    fun adopt(fd: Int): Pair<FileDescriptor, Closeable?> {
        parcelAdopt?.let { adopt ->
            val pfd = adopt.invoke(null, fd) as Closeable
            val fileDescriptor = pfd.javaClass.getMethod("getFileDescriptor").invoke(pfd) as FileDescriptor
            return fileDescriptor to pfd
        }
        val fileDescriptor = FileDescriptor()
        fdField.setInt(fileDescriptor, fd)
        return fileDescriptor to null
    }

    /**
     * Give up ownership without closing, so the descriptor can be handed back
     * to the library (which closes it).
     */
    fun release(fileDescriptor: FileDescriptor, owner: Closeable?) {
        if (owner != null) {
            owner.javaClass.getMethod("detachFd").invoke(owner)
        } else {
            fdField.setInt(fileDescriptor, -1)
        }
    }

    /** Close a raw descriptor the library handed over. */
    fun close(fd: Int) {
        val (fileDescriptor, owner) = adopt(fd)
        owner?.close() ?: FileInputStream(fileDescriptor).close()
    }

    private val fdField by lazy {
        FileDescriptor::class.java.getDeclaredField("fd").apply { isAccessible = true }
    }
}

/** A connected TCP stream over Yggdrasil, as blocking Java streams. */
class YggStream internal constructor(
    /** The underlying descriptor (owned by this object). */
    val fd: Int,
    /** "[address]:port" of the remote side, when known. */
    val peer: String?,
) : Closeable {
    private val fileDescriptor: FileDescriptor
    private val owner: Closeable?

    init {
        val (fdObj, own) = Descriptors.adopt(fd)
        fileDescriptor = fdObj
        owner = own
    }

    val input: InputStream = FileInputStream(fileDescriptor)
    val output: OutputStream = FileOutputStream(fileDescriptor)

    /** Send EOF to the peer; reading stays possible. */
    fun shutdownOutput() = shutdownWrite(fd)

    override fun close() {
        owner?.close() ?: input.close()
    }
}

/** Listener on a Yggdrasil TCP port. */
class YggListener internal constructor(private val node: YggNode, val port: Int) : Closeable {
    /** Readable when a connection is pending (for poll/select integrations). */
    val fd: Int = node.tcpListen(port.toUShort())

    /** Wait for a connection; `timeoutMs` null waits forever, 0 throws [YggException.WouldBlock]. */
    fun accept(timeoutMs: Int? = null): YggStream {
        val accepted = node.tcpAccept(fd, timeoutMs?.toUInt())
        return YggStream(accepted.fd, accepted.peer)
    }

    private var closed = false

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        if (!node.isClosed()) {
            node.tcpListenerClose(fd)
        } else {
            // The node is gone; the handle is ours to close.
            Descriptors.close(fd)
        }
    }
}

/** A received or outgoing datagram. */
data class YggDatagram(val host: String, val port: Int, val payload: ByteArray) {
    override fun equals(other: Any?) =
        other is YggDatagram && host == other.host && port == other.port && payload.contentEquals(other.payload)

    override fun hashCode() = (host.hashCode() * 31 + port) * 31 + payload.contentHashCode()
}

/** UDP socket on a Yggdrasil port. */
class YggUdpSocket internal constructor(private val node: YggNode, requestedPort: Int) : Closeable {
    private val binding = node.udpBind(requestedPort.toUShort())
    val port: Int = binding.port.toInt()
    private val fileDescriptor: FileDescriptor
    private val owner: Closeable?

    init {
        val (fdObj, own) = Descriptors.adopt(binding.fd)
        fileDescriptor = fdObj
        owner = own
    }

    private val input = FileInputStream(fileDescriptor)
    private val output = FileOutputStream(fileDescriptor)
    private val headerLen = udpHeaderLen().toInt()

    /** Send `payload` to `host` (an address, hex key or "<key>.pk.ygg"). */
    fun send(host: String, port: Int, payload: ByteArray) {
        val address = InetAddress.getByName(node.resolve(host)) as Inet6Address
        val frame = ByteBuffer.allocate(headerLen + payload.size)
            .put(address.address).putShort(port.toShort()).put(payload)
        output.write(frame.array())
    }

    /** Block until a datagram arrives. */
    fun receive(maxSize: Int = 65535): YggDatagram {
        val buf = ByteArray(maxSize + headerLen)
        val n = input.read(buf)
        require(n >= headerLen) { "short datagram" }
        val host = formatIpv6(buf.copyOfRange(0, 16))
        val port = ((buf[16].toInt() and 0xff) shl 8) or (buf[17].toInt() and 0xff)
        return YggDatagram(host, port, buf.copyOfRange(headerLen, n))
    }

    override fun close() {
        if (!node.isClosed()) {
            // Hand the descriptor back to the library, which closes it.
            Descriptors.release(fileDescriptor, owner)
            node.udpClose(binding.fd)
        } else {
            owner?.close() ?: input.close()
        }
    }
}

/**
 * RFC 5952 text form of a 16-byte IPv6 address, as the library prints it
 * (`InetAddress.hostAddress` differs between desktop Java and Android).
 */
fun formatIpv6(bytes: ByteArray): String {
    require(bytes.size == 16) { "IPv6 address must be 16 bytes" }
    val groups = IntArray(8) { ((bytes[2 * it].toInt() and 0xff) shl 8) or (bytes[2 * it + 1].toInt() and 0xff) }
    // Longest run of two or more zero groups (first one on ties) becomes "::".
    var bestStart = -1
    var bestLen = 1
    var i = 0
    while (i < 8) {
        if (groups[i] != 0) { i++; continue }
        var j = i
        while (j < 8 && groups[j] == 0) j++
        if (j - i > bestLen) { bestStart = i; bestLen = j - i }
        i = j
    }
    val out = StringBuilder()
    i = 0
    while (i < 8) {
        if (i == bestStart) {
            out.append("::")
            i += bestLen
            continue
        }
        if (out.isNotEmpty() && out.last() != ':') out.append(':')
        out.append(Integer.toHexString(groups[i]))
        i++
    }
    return out.toString()
}

/** Connect over TCP; `host` is an address, hex key or "<key>.pk.ygg". */
fun YggNode.connect(host: String, port: Int, timeoutMs: Int? = null): YggStream =
    YggStream(tcpConnect(host, port.toUShort(), timeoutMs?.toUInt()), null)

/**
 * Connect over TCP without blocking a thread. Cancelling the coroutine
 * abandons the connect.
 */
suspend fun YggNode.connectAsync(host: String, port: Int, timeoutMs: Int? = null): YggStream =
    YggStream(tcpConnectAsync(host, port.toUShort(), timeoutMs?.toUInt()), null)

fun YggNode.listen(port: Int): YggListener = YggListener(this, port)

/**
 * Describe a system interface for multicast discovery, e.g. the one named by
 * `LinkProperties.interfaceName` in an Android `NetworkCallback`.
 */
fun java.net.NetworkInterface.toYgg(): NetworkInterface = NetworkInterface(
    name = name,
    index = index.coerceAtLeast(0).toUInt(),
    addrs = inetAddresses.toList()
        .filterIsInstance<Inet6Address>()
        .map { formatIpv6(it.address) },
)

/** All interfaces that are up and not loopback, for [YggNode.setNetworkInterfaces]. */
fun systemNetworkInterfaces(): List<NetworkInterface> =
    java.net.NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
        .filter { runCatching { it.isUp && !it.isLoopback }.getOrDefault(false) }
        .map { it.toYgg() }

fun YggNode.udp(port: Int = 0): YggUdpSocket = YggUdpSocket(this, port)

/** Round-trip time in milliseconds. */
fun YggNode.pingMillis(host: String, timeoutMs: Int? = null): Double =
    ping(host, timeoutMs?.toUInt()).toDouble() / 1000.0
