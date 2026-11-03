/*
 * ygg.h - embedded Yggdrasil node with a userspace TCP/UDP stack.
 *
 * Connections are handed to the application as ordinary OS sockets (one end
 * of a socket pair; the library bridges the other end to the Yggdrasil
 * network). Use read/write/send/recv/poll/select, epoll, kqueue, IOCP,
 * Python's socket/asyncio etc. on them as usual; the data path never calls
 * into this library. No TUN adapter or elevated privileges are needed.
 *
 *   Unix:    sockets are file descriptors (AF_UNIX socket pairs).
 *   Windows: sockets are SOCKETs (loopback TCP/UDP pairs); call WSAStartup
 *            before using them with Winsock.
 *
 * Conventions
 *   - Functions returning int return >= 0 on success and -YGG_ERR_* on error.
 *   - Functions returning ygg_socket return YGG_INVALID_SOCKET on error, and
 *     functions returning pointers return NULL on error.
 *   - On error, ygg_last_error() / ygg_last_error_message() describe it
 *     (per thread).
 *   - Calls that wait (start, connect, accept, ping, ...) block the calling
 *     thread. Never call ygg_* functions from the log callback.
 *   - A ygg_node may be used from several threads at once, but not after or
 *     during ygg_node_stop().
 */
#ifndef YGG_H
#define YGG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
typedef uintptr_t ygg_socket; /* SOCKET */
#define YGG_INVALID_SOCKET ((ygg_socket)~(uintptr_t)0)
#else
typedef int ygg_socket; /* file descriptor */
#define YGG_INVALID_SOCKET (-1)
#endif

typedef struct YggNode ygg_node;

/* Error codes (functions returning int give them negated). */
#define YGG_OK                     0
#define YGG_ERR_INVALID_ARGUMENT   1
#define YGG_ERR_CONFIG             2
#define YGG_ERR_CONNECTION_REFUSED 3
#define YGG_ERR_TIMED_OUT          4
#define YGG_ERR_ADDR_IN_USE        5
#define YGG_ERR_CLOSED             6
#define YGG_ERR_WOULD_BLOCK        7
#define YGG_ERR_IO                 8
#define YGG_ERR_PANIC              9
#define YGG_ERR_NOT_FOUND          10

/* Log levels passed to the log callback. */
#define YGG_LOG_ERROR 1
#define YGG_LOG_WARN  2
#define YGG_LOG_INFO  3
#define YGG_LOG_DEBUG 4
#define YGG_LOG_TRACE 5

/* ygg_node_start flags. */
#define YGG_START_ADMIN 1u /* also start the admin socket (admin_listen) */

/*
 * Every datagram on a socket from ygg_udp_bind starts with this header:
 *   bytes 0..15  remote IPv6 address (destination when writing, source when reading)
 *   bytes 16..17 remote port, big-endian
 * followed by the payload.
 */
#define YGG_UDP_HEADER_LEN 18

/* ---- Library ----------------------------------------------------------- */

const char *ygg_version(void);
int ygg_last_error(void);
const char *ygg_last_error_message(void); /* valid until the next ygg_* call on this thread */

/* Free strings returned by ygg_generate_config / ygg_node_admin. */
void ygg_free_string(char *s);

/* A new TOML configuration with a fresh private key. */
char *ygg_generate_config(void);

/*
 * Send log output to `callback` (called from library threads). `filter` uses
 * tracing EnvFilter syntax, e.g. "info" or "warn,yggdrasil::links=debug";
 * NULL means "info". Can be installed once per process.
 */
typedef void (*ygg_log_fn)(void *userdata, int level, const char *message);
int ygg_set_logger(ygg_log_fn callback, void *userdata, const char *filter);

/* ---- Node -------------------------------------------------------------- */

/*
 * Start a node. `config_toml` is a Yggdrasil configuration (see
 * ygg_generate_config); NULL or "" starts with defaults and an ephemeral key.
 * TUN settings are ignored. Blocks until links are up.
 */
ygg_node *ygg_node_start(const char *config_toml, uint32_t flags);

/*
 * Like ygg_node_start, also passing the network interfaces for multicast
 * discovery (JSON, see ygg_node_set_network_interfaces; NULL for none). Apps
 * that supply interfaces themselves (e.g. Android, where getifaddrs() is
 * restricted) must pass them here for multicast to follow later updates.
 */
ygg_node *ygg_node_start_ex(const char *config_toml, uint32_t flags, const char *interfaces_json);

/*
 * Stop the node and free it. Sockets it handed out see EOF; the application
 * still closes them itself (close()/closesocket()).
 */
void ygg_node_stop(ygg_node *node);

/* snprintf-style: write a NUL-terminated string (truncated to fit `len`)
 * and return its full length. */
int ygg_node_address(const ygg_node *node, char *buf, size_t len);    /* "200:..." */
int ygg_node_subnet(const ygg_node *node, char *buf, size_t len);     /* "300:.../64" */
int ygg_node_public_key(const ygg_node *node, char *buf, size_t len); /* 64 hex chars */

int ygg_node_add_peer(const ygg_node *node, const char *uri);    /* "tls://host:port" */
int ygg_node_remove_peer(const ygg_node *node, const char *uri);

/*
 * Call when the network changed (interface up/down, Wi-Fi <-> mobile,
 * resume from sleep/Doze): peers that are down are redialled immediately
 * instead of after their backoff, and the node re-announces itself.
 */
int ygg_node_network_changed(const ygg_node *node);

/*
 * Replace the interfaces used by multicast discovery, as JSON:
 *   [{"name":"wlan0","index":3,"addrs":["fe80::1234"]}]
 */
int ygg_node_set_network_interfaces(const ygg_node *node, const char *interfaces_json);

/*
 * Run an admin API request in-process, e.g. "{\"request\":\"getPeers\"}" or
 * "{\"request\":\"getSelf\"}". Returns the JSON response (free with
 * ygg_free_string).
 */
char *ygg_node_admin(const ygg_node *node, const char *request_json);

/* ---- TCP --------------------------------------------------------------- */

/*
 * Connect to `host` port `port`. `host` is an IPv6 address in 200::/7, a hex
 * public key, or "<hex key>.pk.ygg". timeout_ms <= 0 uses the default (30 s).
 * Returns a connected stream socket. Shut down the write side to send FIN;
 * close it when done.
 */
ygg_socket ygg_tcp_connect(const ygg_node *node, const char *host, uint16_t port, int timeout_ms);

/*
 * Non-blocking connect for event loops. ygg_tcp_connect_start returns a
 * pending handle that becomes readable when the outcome is known (do not
 * read or write it). ygg_tcp_connect_finish then returns the connected
 * stream socket, or YGG_INVALID_SOCKET with the connect error; before that
 * it fails with YGG_ERR_WOULD_BLOCK. Once the outcome has been returned the
 * pending handle is closed. ygg_tcp_connect_cancel abandons the connect and
 * closes the handle.
 */
ygg_socket ygg_tcp_connect_start(const ygg_node *node, const char *host, uint16_t port, int timeout_ms);
ygg_socket ygg_tcp_connect_finish(const ygg_node *node, ygg_socket pending);
int ygg_tcp_connect_cancel(const ygg_node *node, ygg_socket pending);

/*
 * Listen on `port` of the node's address. The returned socket is only a
 * notification handle: it becomes readable when ygg_tcp_accept has a
 * connection. Do not read from or write to it; close it with
 * ygg_tcp_listener_close.
 */
ygg_socket ygg_tcp_listen(const ygg_node *node, uint16_t port);

/*
 * Accept a connection. timeout_ms < 0 waits forever, 0 returns immediately
 * (YGG_ERR_WOULD_BLOCK when nothing is pending; readability may be spurious).
 * If `peer_buf` is not NULL, the peer's "[addr]:port" is written to it.
 */
ygg_socket ygg_tcp_accept(const ygg_node *node, ygg_socket listener, char *peer_buf, size_t peer_len,
                          int timeout_ms);

int ygg_tcp_listener_close(const ygg_node *node, ygg_socket listener);

/* ---- UDP --------------------------------------------------------------- */

/*
 * Bind UDP `port` (0 picks one, reported in *bound_port if not NULL).
 * Returns a datagram socket; every datagram carries the YGG_UDP_HEADER_LEN
 * header. The payload must fit the stack MTU (no fragmentation).
 * Close it with ygg_udp_close.
 */
ygg_socket ygg_udp_bind(const ygg_node *node, uint16_t port, uint16_t *bound_port);
int ygg_udp_close(const ygg_node *node, ygg_socket sock);

/* ---- ICMPv6 ------------------------------------------------------------ */

/* Echo request to `host`; returns the RTT in microseconds or -YGG_ERR_*.
 * timeout_ms <= 0 uses 5 s. */
int64_t ygg_ping(const ygg_node *node, const char *host, int timeout_ms);

/* ---- Proxy services ---------------------------------------------------- */

/* Each returns a service id (> 0) for ygg_service_stop. Host addresses are
 * "IP:port"; Yggdrasil targets are "[addr]:port" or "<hex key>.pk.ygg:port". */

/* SOCKS5 server (CONNECT). username/password: both NULL for no auth. */
int ygg_socks5_start(const ygg_node *node, const char *listen, const char *username, const char *password);
/* Host listener -> Yggdrasil target. */
int ygg_forward_local_tcp(const ygg_node *node, const char *listen, const char *target);
int ygg_forward_local_udp(const ygg_node *node, const char *listen, const char *target);
/* Yggdrasil port -> host service. */
int ygg_forward_remote_tcp(const ygg_node *node, uint16_t port, const char *target);
int ygg_forward_remote_udp(const ygg_node *node, uint16_t port, const char *target);
int ygg_service_stop(const ygg_node *node, int id);

#ifdef __cplusplus
}
#endif

#endif /* YGG_H */
