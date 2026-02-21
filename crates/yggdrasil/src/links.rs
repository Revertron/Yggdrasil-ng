use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{ AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use url::Url;

use crate::core::Core;
use crate::version::Metadata;

/// Enum to handle both TCP and TLS streams uniformly.
enum Stream {
    Tcp(TcpStream),
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
    TlsClient(tokio_rustls::client::TlsStream<TcpStream>),
}

impl Stream {
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Stream::Tcp(s) => s.peer_addr(),
            Stream::Tls(s) => s.get_ref().0.peer_addr(),
            Stream::TlsClient(s) => s.get_ref().0.peer_addr(),
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Stream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(s).poll_read(cx, buf),
            Stream::TlsClient(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Stream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => Pin::new(s).poll_write(cx, buf),
            Stream::TlsClient(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Stream::Tcp(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(s).poll_flush(cx),
            Stream::TlsClient(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Stream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(s).poll_shutdown(cx),
            Stream::TlsClient(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

const DEFAULT_BACKOFF_LIMIT: Duration = Duration::from_secs(4096);
const MINIMUM_BACKOFF_LIMIT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(6);
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

// Maximum concurrent incoming connections being processed
const MAX_CONCURRENT_INCOMING: usize = 350;

// Connection throttling settings
const MAX_FAILED_ATTEMPTS: usize = 3; // Ban after this many failed handshakes
const BAN_DURATION: Duration = Duration::from_secs(900); // 15 minutes
const FAILED_ATTEMPT_WINDOW: Duration = Duration::from_secs(60); // Track failures within 1 minute

/// Type of link connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkType {
    Persistent,
    Ephemeral,
    Incoming,
}

/// Options parsed from a peer URI.
#[derive(Clone, Debug)]
pub struct LinkOptions {
    pub pinned_keys: Vec<[u8; 32]>,
    pub priority: u8,
    pub password: Vec<u8>,
    pub max_backoff: Duration,
}

impl Default for LinkOptions {
    fn default() -> Self {
        Self {
            pinned_keys: Vec::new(),
            priority: 0,
            password: Vec::new(),
            max_backoff: DEFAULT_BACKOFF_LIMIT,
        }
    }
}

/// Track failed connection attempts for throttling/banning.
struct FailedAttempt {
    count: usize,
    last_attempt: Instant,
    banned_until: Option<Instant>,
}

/// IP-based connection throttling and banning.
#[derive(Clone)]
pub struct BanList(Arc<Mutex<HashMap<IpAddr, FailedAttempt>>>);

impl BanList {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    /// Check if an IP is currently banned.
    pub async fn is_banned(&self, ip: IpAddr) -> bool {
        let mut map = self.0.lock().await;
        if let Some(entry) = map.get_mut(&ip) {
            if let Some(banned_until) = entry.banned_until {
                if Instant::now() < banned_until {
                    return true;
                } else {
                    // Ban expired, clear it
                    entry.banned_until = None;
                    entry.count = 0;
                    return false;
                }
            }
        }
        false
    }

    /// Record a failed handshake attempt. Returns true if the IP should now be banned.
    pub async fn record_failure(&self, ip: IpAddr, reason: &str) -> bool {
        let mut map = self.0.lock().await;
        let now = Instant::now();

        let entry = map.entry(ip).or_insert(FailedAttempt {
            count: 0,
            last_attempt: now,
            banned_until: None,
        });

        // Reset count if last attempt was outside the window
        if now.duration_since(entry.last_attempt) > FAILED_ATTEMPT_WINDOW {
            entry.count = 0;
        }

        entry.count += 1;
        entry.last_attempt = now;

        if entry.count >= MAX_FAILED_ATTEMPTS {
            entry.banned_until = Some(now + BAN_DURATION);
            tracing::warn!(
                "Banned {} for {} seconds after {} failed attempts (reason: {})",
                ip,
                BAN_DURATION.as_secs(),
                entry.count,
                reason
            );
            true
        } else {
            false
        }
    }

    /// Clean up old entries (call periodically).
    pub async fn cleanup(&self) {
        let mut map = self.0.lock().await;
        let now = Instant::now();
        map.retain(|_, entry| {
            // Keep if banned or if recent failure
            if let Some(banned_until) = entry.banned_until {
                now < banned_until + Duration::from_secs(60)
            } else {
                now.duration_since(entry.last_attempt) < FAILED_ATTEMPT_WINDOW * 2
            }
        });
    }
}

/// Wrapper that counts bytes read/written from a stream.
/// Uses local buffering to minimize atomic operations.
struct CountingStream {
    inner: Stream,
    rx_counter: Arc<AtomicUsize>,
    tx_counter: Arc<AtomicUsize>,
    rx_buffer: usize,
    tx_buffer: usize,
}

const FLUSH_THRESHOLD: usize = 65536; // Flush to atomic counters every 64KB

impl CountingStream {
    fn new(stream: Stream, rx_counter: Arc<AtomicUsize>, tx_counter: Arc<AtomicUsize>) -> Self {
        Self {
            inner: stream,
            rx_counter,
            tx_counter,
            rx_buffer: 0,
            tx_buffer: 0,
        }
    }

    fn flush_rx(&mut self) {
        if self.rx_buffer > 0 {
            self.rx_counter.fetch_add(self.rx_buffer, Ordering::Relaxed);
            self.rx_buffer = 0;
        }
    }

    fn flush_tx(&mut self) {
        if self.tx_buffer > 0 {
            self.tx_counter.fetch_add(self.tx_buffer, Ordering::Relaxed);
            self.tx_buffer = 0;
        }
    }
}

impl AsyncRead for CountingStream {
    fn poll_read(mut self: Pin<&mut Self>,cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let bytes_read = buf.filled().len() - before;
            self.rx_buffer += bytes_read;
            if self.rx_buffer >= FLUSH_THRESHOLD {
                self.flush_rx();
            }
        }
        result
    }
}

impl AsyncWrite for CountingStream {
    fn poll_write(mut self: Pin<&mut Self>,cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            self.tx_buffer += *n;
            if self.tx_buffer >= FLUSH_THRESHOLD {
                self.flush_tx();
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        if let Poll::Ready(Ok(())) = &result {
            self.flush_tx(); // Flush buffered counts on stream flush
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.flush_rx(); // Flush all buffered counts on shutdown
        self.flush_tx();
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for CountingStream {
    fn drop(&mut self) {
        // Ensure any buffered counts are flushed when stream is dropped
        self.flush_rx();
        self.flush_tx();
    }
}

/// Snapshot of a link's current state (for admin API).
#[derive(Clone, Debug)]
pub struct LinkPeerInfo {
    pub uri: String,
    pub up: bool,
    pub inbound: bool,
    pub key: [u8; 32],
    pub priority: u8,
    pub rx_bytes: usize,
    pub tx_bytes: usize,
    pub rx_rate: usize,
    pub tx_rate: usize,
    pub uptime_secs: f64,
    pub latency_ms: f64,
    pub cost: u64,
    pub last_error: Option<String>,
}

/// Shared registry of active link connections.
/// This is separate from `Links` so spawned tasks can update it.
#[derive(Clone)]
pub struct ActiveLinks {
    inner: Arc<Mutex<ActiveLinksInner>>,
    pub ban_list: BanList,
}

pub struct ActiveLinksInner {
    next_id: u64,
    connections: HashMap<u64, ActiveConn>,
}

struct ActiveConn {
    uri: String,
    inbound: bool,
    key: [u8; 32],
    priority: u8,
    rx: Arc<AtomicUsize>,
    tx: Arc<AtomicUsize>,
    rx_rate: Arc<AtomicUsize>,
    tx_rate: Arc<AtomicUsize>,
    last_rx: usize,
    last_tx: usize,
    up: Instant,
}

impl ActiveLinks {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ActiveLinksInner {
                next_id: 0,
                connections: HashMap::new(),
            })),
            ban_list: BanList::new(),
        }
    }

    async fn register(&self,uri: String, inbound: bool, key: [u8; 32], priority: u8) -> (u64, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let mut inner = self.inner.lock().await;
        let id = inner.next_id;
        inner.next_id += 1;
        let rx = Arc::new(AtomicUsize::new(0));
        let tx = Arc::new(AtomicUsize::new(0));
        inner.connections.insert(
            id,
            ActiveConn {
                uri,
                inbound,
                key,
                priority,
                rx: rx.clone(),
                tx: tx.clone(),
                rx_rate: Arc::new(AtomicUsize::new(0)),
                tx_rate: Arc::new(AtomicUsize::new(0)),
                last_rx: 0,
                last_tx: 0,
                up: Instant::now(),
            },
        );
        (id, rx, tx)
    }

    async fn unregister(&self, id: u64) {
        let mut inner = self.inner.lock().await;
        inner.connections.remove(&id);
    }

    /// Update rate counters for all connections (call every ~1 second).
    pub async fn update_rates(&self) {
        let mut inner = self.inner.lock().await;
        for conn in inner.connections.values_mut() {
            let rx = conn.rx.load(Ordering::Relaxed);
            let tx = conn.tx.load(Ordering::Relaxed);
            conn.rx_rate.store(rx.saturating_sub(conn.last_rx), Ordering::Relaxed);
            conn.tx_rate.store(tx.saturating_sub(conn.last_tx), Ordering::Relaxed);
            conn.last_rx = rx;
            conn.last_tx = tx;
        }
    }

    /// Get a snapshot of all active connections for the admin API.
    pub async fn get_peers(&self) -> Vec<LinkPeerInfo> {
        let inner = self.inner.lock().await;
        inner
            .connections
            .values()
            .map(|c| LinkPeerInfo {
                uri: c.uri.clone(),
                up: true,
                inbound: c.inbound,
                key: c.key,
                priority: c.priority,
                rx_bytes: c.rx.load(Ordering::Relaxed),
                tx_bytes: c.tx.load(Ordering::Relaxed),
                rx_rate: c.rx_rate.load(Ordering::Relaxed),
                tx_rate: c.tx_rate.load(Ordering::Relaxed),
                uptime_secs: c.up.elapsed().as_secs_f64(),
                latency_ms: 0.0,
                cost: 0,
                last_error: None,
            })
            .collect()
    }
}

struct PeerEntry {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

/// Manages TCP peer connections and listeners.
pub struct Links {
    core: Option<Arc<Core>>,
    active: ActiveLinks,
    peers: HashMap<String, PeerEntry>,
    /// Track resolved IP:port to detect duplicate peers (e.g., same host via IP and domain)
    peer_addrs: HashMap<String, String>, // "IP:port" -> original URI
    listeners: HashMap<String, (CancellationToken, JoinHandle<()>)>,
    rate_handle: Option<JoinHandle<()>>,
    /// Notifier to wake all sleeping reconnect loops immediately.
    retry_notify: Arc<Notify>,
    /// Global semaphore shared across ALL listeners — enforces total incoming connection limit.
    connection_limiter: Arc<Semaphore>,
}

impl Links {
    pub fn new(active: ActiveLinks) -> Self {
        Self {
            core: None,
            active,
            peers: HashMap::new(),
            peer_addrs: HashMap::new(),
            listeners: HashMap::new(),
            rate_handle: None,
            retry_notify: Arc::new(Notify::new()),
            connection_limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_INCOMING)),
        }
    }

    /// Wake all sleeping peer reconnect loops so they retry immediately.
    pub fn retry_peers_now(&self) {
        self.retry_notify.notify_waiters();
    }

    /// Set the core reference. Must be called before listen/add_peer.
    pub fn set_core(&mut self, core: Arc<Core>) {
        self.core = Some(core);
        // Start rate update and ban list cleanup tasks
        let active = self.active.clone();
        self.rate_handle = Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            let mut cleanup_counter = 0u32;
            loop {
                interval.tick().await;
                active.update_rates().await;

                // Clean up ban list every 60 seconds
                cleanup_counter += 1;
                if cleanup_counter >= 60 {
                    cleanup_counter = 0;
                    active.ban_list.cleanup().await;
                }
            }
        }));
    }

    fn core(&self) -> Result<Arc<Core>, String> {
        self.core.clone().ok_or_else(|| "core not initialized".to_string())
    }

    /// Start listening on an address (e.g. "tcp://0.0.0.0:1234" or "tls://0.0.0.0:2345").
    pub async fn listen(&mut self, addr: &str) -> Result<(), String> {
        let url = Url::parse(addr).map_err(|e| format!("invalid URL: {}", e))?;
        let scheme = url.scheme();
        let use_tls = match scheme {
            "tcp" => false,
            "tls" => true,
            _ => return Err(format!("unsupported scheme: {}", scheme)),
        };

        let host_port = url
            .socket_addrs(|| Some(0))
            .map_err(|e| format!("invalid address: {}", e))?
            .first()
            .ok_or("no address resolved")?
            .to_string();

        let options = parse_link_options(&url)?;
        let core = self.core()?;
        let active = self.active.clone();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let addr_str = addr.to_string();

        let listener = TcpListener::bind(&host_port)
            .await
            .map_err(|e| format!("bind failed: {}", e))?;

        let actual_addr = listener
            .local_addr()
            .map_err(|e| format!("local_addr failed: {}", e))?;
        tracing::info!("Listening on {}://{}", scheme, actual_addr);

        let tls_acceptor = if use_tls {
            let server_config = core.tls_server_config.read().await.clone();
            Some(TlsAcceptor::from(server_config))
        } else {
            None
        };

        // Shared semaphore — global limit across all listeners
        let connection_limiter = self.connection_limiter.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_clone.cancelled() => break,
                    result = listener.accept() => {
                        match result {
                            Ok((stream, remote)) => {
                                // Try to acquire permit for new connection
                                let permit = match connection_limiter.clone().try_acquire_owned() {
                                    Ok(permit) => permit,
                                    Err(_) => {
                                        // Too many concurrent connections, reject immediately
                                        tracing::warn!(
                                            "Rejected connection from {} (too many concurrent connections: {}/{})",
                                            remote,
                                            MAX_CONCURRENT_INCOMING,
                                            MAX_CONCURRENT_INCOMING
                                        );
                                        drop(stream);  // Explicit close
                                        continue;
                                    }
                                };

                                tracing::debug!("Accepted connection from {}", remote);
                                let core = core.clone();
                                let opts = options.clone();
                                let active = active.clone();
                                let acceptor = tls_acceptor.clone();
                                let remote_str = if acceptor.is_some() {
                                    format!("tls://{}", remote)
                                } else {
                                    format!("tcp://{}", remote)
                                };

                                tokio::spawn(async move {
                                    // Permit is held for the duration of this task

                                    // Perform TLS handshake if needed
                                    let wrapped_stream = if let Some(acceptor) = acceptor {
                                        match acceptor.accept(stream).await {
                                            Ok(tls_stream) => Stream::Tls(tls_stream),
                                            Err(e) => {
                                                tracing::debug!("TLS handshake failed from {}: {}", remote, e);
                                                drop(permit);
                                                return;
                                            }
                                        }
                                    } else {
                                        Stream::Tcp(stream)
                                    };

                                    let _ = handle_connection(
                                        LinkType::Incoming,
                                        opts,
                                        wrapped_stream,
                                        &core,
                                        &active,
                                        &remote_str,
                                    ).await;
                                    // Permit automatically released when dropped
                                    drop(permit);
                                });
                            }
                            Err(e) => {
                                tracing::error!("Accept error: {}", e);
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
            }
        });

        self.listeners.insert(addr_str, (cancel, handle));
        Ok(())
    }

    /// Add a persistent peer to connect to.
    pub async fn add_peer(&mut self, uri: &str) -> Result<(), String> {
        if self.peers.contains_key(uri) {
            return Err("peer already exists".to_string());
        }

        let url = Url::parse(uri).map_err(|e| format!("invalid URI: {}", e))?;
        let scheme = url.scheme();
        if scheme != "tcp" && scheme != "tls" {
            return Err(format!("unsupported scheme: {}", scheme));
        }

        let host = url.host_str().ok_or("missing host")?.to_string();
        let port = url.port().ok_or("missing port")?;
        let target = format!("{}:{}", host, port);

        // Resolve DNS to detect duplicates (e.g., same peer via IP and domain)
        let mut resolved_addrs: Vec<_> = tokio::net::lookup_host(&target)
            .await
            .map_err(|e| format!("DNS lookup failed for {}: {}", target, e))?
            .collect();
        resolved_addrs.sort();

        // Check if any resolved IP:port is already connected
        for addr in &resolved_addrs {
            let addr_key = addr.to_string();
            if let Some(existing_uri) = self.peer_addrs.get(&addr_key) {
                return Err(format!("peer {} already connected as {} (resolves to same address {})", uri, existing_uri, addr_key));
            }
        }

        // Get the primary address for tracking
        let primary_addr = resolved_addrs.first().ok_or("failed to resolve address")?;
        let addr_key = primary_addr.to_string();

        let options = parse_link_options(&url)?;
        let core = self.core()?;
        let active = self.active.clone();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let uri_str = uri.to_string();
        let retry_notify = self.retry_notify.clone();

        let use_tls = scheme == "tls";
        let tls_connector = if use_tls {
            let client_config = core.tls_client_config.read().await.clone();
            Some(TlsConnector::from(client_config))
        } else {
            None
        };

        let handle = tokio::spawn(async move {
            let mut backoff: u32 = 0;
            loop {
                if cancel_clone.is_cancelled() {
                    break;
                }

                let result = tokio::time::timeout(
                    DIAL_TIMEOUT,
                    TcpStream::connect(&target),
                )
                .await;

                match result {
                    Ok(Ok(stream)) => {
                        stream.set_nodelay(true).ok();

                        // Perform TLS handshake if needed
                        let wrapped_stream = if let Some(ref connector) = tls_connector {
                            // Use the hostname from the URI for SNI
                            let server_name = rustls::pki_types::ServerName::try_from(host.clone())
                                .unwrap_or_else(|_| {
                                    // Fallback to using IP address as server name if hostname parsing fails
                                    rustls::pki_types::ServerName::IpAddress(
                                        rustls::pki_types::IpAddr::try_from(host.as_str())
                                            .expect("invalid hostname")
                                    )
                                });

                            match connector.connect(server_name, stream).await {
                                Ok(tls_stream) => Stream::TlsClient(tls_stream),
                                Err(e) => {
                                    tracing::debug!("TLS handshake failed to {}: {}", target, e);
                                    // Continue to backoff logic below
                                    backoff = (backoff + 1).min(32);
                                    let wait = Duration::from_secs(1u64 << backoff.min(31))
                                        .min(options.max_backoff);
                                    tokio::select! {
                                        _ = cancel_clone.cancelled() => break,
                                        _ = tokio::time::sleep(wait) => {}
                                        _ = retry_notify.notified() => {}
                                    }
                                    continue;
                                }
                            }
                        } else {
                            Stream::Tcp(stream)
                        };

                        match handle_connection(LinkType::Persistent, options.clone(), wrapped_stream, &core, &active, &uri_str).await {
                            Ok(()) => {
                                // Clean disconnection - reset backoff
                                backoff = 0;
                            }
                            Err(_) => {
                                // Error during connection/handshake
                                // (handle_connection already logged the details)
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!("Failed to connect to {}: {}", target, e);
                    }
                    Err(_) => {
                        tracing::debug!("Connection to {} timed out", target);
                    }
                }

                if backoff < 32 {
                    backoff += 1;
                }
                let wait = Duration::from_secs(1u64 << backoff.min(31))
                    .min(options.max_backoff);

                tokio::select! {
                    _ = cancel_clone.cancelled() => break,
                    _ = tokio::time::sleep(wait) => {}
                    _ = retry_notify.notified() => {}
                }
            }
        });

        self.peers.insert(uri.to_string(), PeerEntry { cancel, handle });
        self.peer_addrs.insert(addr_key, uri.to_string());
        Ok(())
    }

    /// Remove a peer by URI.
    pub async fn remove_peer(&mut self, uri: &str) -> Result<(), String> {
        if let Some(entry) = self.peers.remove(uri) {
            entry.cancel.cancel();
            entry.handle.abort();

            // Also remove from peer_addrs map
            self.peer_addrs.retain(|_, v| v != uri);

            Ok(())
        } else {
            Err("peer not found".to_string())
        }
    }

    /// Stop all listeners and peers.
    pub async fn close(&mut self) {
        if let Some(h) = self.rate_handle.take() {
            h.abort();
        }
        for (_, (cancel, handle)) in self.listeners.drain() {
            cancel.cancel();
            handle.abort();
        }
        for (_, entry) in self.peers.drain() {
            entry.cancel.cancel();
            entry.handle.abort();
        }
        self.peer_addrs.clear();
    }
}

/// Perform the Yggdrasil handshake over a stream (TCP or TLS), then hand off to ironwood.
async fn handle_connection(
    link_type: LinkType,
    options: LinkOptions,
    mut stream: Stream,
    core: &Arc<Core>,
    active: &ActiveLinks,
    uri: &str,
) -> Result<(), String> {
    // Get peer IP address for ban checking
    let peer_ip = match stream.peer_addr() {
        Ok(addr) => Some(addr.ip()),
        Err(_) => None,
    };

    // Check if IP is banned
    if let Some(ip) = peer_ip {
        if active.ban_list.is_banned(ip).await {
            return Err(format!("IP {} is temporarily banned", ip));
        }
    }

    // 6 second handshake timeout
    let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let meta = Metadata::new(core.public_key, options.priority);
        let encoded = meta.encode(&core.signing_key, &options.password);
        stream
            .write_all(&encoded)
            .await
            .map_err(|e| format!("write handshake: {}", e))?;

        // Read directly from stream without BufReader to avoid consuming
        // ironwood protocol data that arrives right after the handshake.
        let mut header = [0u8; 6];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|e| format!("read header: {}", e))?;

        if &header[..4] != b"meta" {
            return Err("invalid preamble".to_string());
        }

        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        if length < 64 {
            return Err("metadata too short".to_string());
        }

        let mut body = vec![0u8; length];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|e| format!("read body: {}", e))?;

        let mut full = Vec::with_capacity(6 + length);
        full.extend_from_slice(&header);
        full.extend_from_slice(&body);

        let mut cursor = std::io::Cursor::new(&full);
        let remote_meta = Metadata::decode(&mut cursor, &options.password)
            .map_err(|e| format!("decode handshake: {}", e))?;

        Ok(remote_meta)
    })
    .await
    .map_err(|_| "handshake timed out".to_string())?;

    let remote_meta = result?;

    if !remote_meta.check() {
        let err_msg = format!(
            "incompatible version {}.{} (local {}.{})",
            remote_meta.major_ver,
            remote_meta.minor_ver,
            crate::version::PROTOCOL_VERSION_MAJOR,
            crate::version::PROTOCOL_VERSION_MINOR
        );

        // Log incompatible version
        if let Some(ip) = peer_ip {
            tracing::info!("Rejected connection from {}: {}", ip, err_msg);
            // Record failure and potentially ban this IP
            active.ban_list.record_failure(ip, "incompatible version").await;
        } else {
            tracing::info!("Rejected connection: {}", err_msg);
        }

        return Err(err_msg);
    }

    // Log if version is newer than ours (but still compatible)
    if !remote_meta.is_exact_match() {
        tracing::debug!(
            "Connected with newer version {}.{} (local {}.{})",
            remote_meta.major_ver,
            remote_meta.minor_ver,
            crate::version::PROTOCOL_VERSION_MAJOR,
            crate::version::PROTOCOL_VERSION_MINOR
        );
    }

    if remote_meta.public_key == core.public_key {
        if let Some(ip) = peer_ip {
            tracing::debug!("Rejected connection from {}: connected to self", ip);
            // Don't ban for self-connection, it's usually a configuration issue
        }
        return Err("connected to self".to_string());
    }

    if !options.pinned_keys.is_empty()
        && !options.pinned_keys.contains(&remote_meta.public_key)
    {
        if let Some(ip) = peer_ip {
            tracing::debug!("Rejected connection from {}: key not in pinned keys", ip);
            // Don't ban for wrong pinned key - could be legitimate peering config mismatch
        }
        return Err("remote key not in pinned keys".to_string());
    }

    if link_type == LinkType::Incoming && !core.is_key_allowed(&remote_meta.public_key) {
        if let Some(ip) = peer_ip {
            tracing::debug!("Rejected connection from {}: key not in allowed list", ip);
            // Record failure for unauthorized keys
            active.ban_list.record_failure(ip, "key not allowed").await;
        }
        return Err("remote key not allowed".to_string());
    }

    let priority = options.priority.max(remote_meta.priority);

    let remote_addr = crate::address::addr_for_key(&remote_meta.public_key);
    let direction = if link_type == LinkType::Incoming {
        "inbound"
    } else {
        "outbound"
    };
    let peer_addr = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    tracing::info!(
        "Connected {}: {} @ {} (v{}.{})",
        direction,
        remote_addr,
        peer_addr,
        remote_meta.major_ver,
        remote_meta.minor_ver
    );

    // Register in active links
    let inbound = link_type == LinkType::Incoming;
    let (conn_id, rx_counter, tx_counter) = active
        .register(uri.to_string(), inbound, remote_meta.public_key, priority)
        .await;

    let conn_start = Instant::now();

    // Wrap stream to count bytes
    let counting_stream = CountingStream::new(stream, rx_counter, tx_counter);

    // Hand off to ironwood (blocks until peer disconnects)
    let result = core
        .handle_conn(remote_meta.public_key, Box::new(counting_stream), priority)
        .await
        .map_err(|e| format!("ironwood: {}", e));

    // Unregister when done
    active.unregister(conn_id).await;

    // Log disconnection
    let uptime = conn_start.elapsed();
    match &result {
        Ok(()) => {
            tracing::info!(
                "Disconnected {}: {} @ {} (uptime: {:.1}s)",
                direction,
                remote_addr,
                peer_addr,
                uptime.as_secs_f64()
            );
        }
        Err(e) => {
            tracing::info!(
                "Disconnected {}: {} @ {} (uptime: {:.1}s, error: {})",
                direction,
                remote_addr,
                peer_addr,
                uptime.as_secs_f64(),
                e
            );
        }
    }

    result
}

/// Parse link options from a URL's query parameters.
fn parse_link_options(url: &Url) -> Result<LinkOptions, String> {
    let mut opts = LinkOptions::default();

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "key" => {
                let bytes =
                    hex::decode(value.as_ref()).map_err(|e| format!("invalid key hex: {}", e))?;
                if bytes.len() != 32 {
                    return Err("pinned key must be 32 bytes".to_string());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                opts.pinned_keys.push(arr);
            }
            "priority" => {
                opts.priority = value
                    .parse()
                    .map_err(|e| format!("invalid priority: {}", e))?;
            }
            "password" => {
                if value.len() > 64 {
                    return Err("password too long (max 64 chars)".to_string());
                }
                opts.password = value.as_bytes().to_vec();
            }
            "maxbackoff" => {
                let secs: u64 = value
                    .parse()
                    .map_err(|e| format!("invalid maxbackoff: {}", e))?;
                let dur = Duration::from_secs(secs);
                if dur < MINIMUM_BACKOFF_LIMIT {
                    return Err(format!(
                        "maxbackoff must be at least {} seconds",
                        MINIMUM_BACKOFF_LIMIT.as_secs()
                    ));
                }
                opts.max_backoff = dur;
            }
            _ => {}
        }
    }

    Ok(opts)
}
