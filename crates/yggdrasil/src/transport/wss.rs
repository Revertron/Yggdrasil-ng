use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ironwood::types::AsyncConn;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::links::LinkOptions;
use super::ws::{ws_client_handshake, ws_server_handshake};
use super::{apply_scope_id, bare_host, Transport, TransportListener, TransportStream};

const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// WSS (WebSocket over TLS) transport.
pub struct WssTransport {
    server_config: Arc<RwLock<Arc<rustls::ServerConfig>>>,
    client_config: Arc<RwLock<Arc<rustls::ClientConfig>>>,
}

impl WssTransport {
    pub fn new(
        server_config: Arc<RwLock<Arc<rustls::ServerConfig>>>,
        client_config: Arc<RwLock<Arc<rustls::ClientConfig>>>,
    ) -> Self {
        Self {
            server_config,
            client_config,
        }
    }
}

#[async_trait]
impl Transport for WssTransport {
    async fn dial(
        &self,
        url: &Url,
        options: &LinkOptions,
    ) -> Result<TransportStream, String> {
        let host = bare_host(url)?;
        let port = url.port().unwrap_or(443);
        let mut addrs = url
            .socket_addrs(|| Some(443))
            .map_err(|e| format!("address resolution failed: {}", e))?;

        // Fix up scope_id for link-local IPv6 addresses (multicast discovery)
        apply_scope_id(&mut addrs, options.scope_id);

        // TCP connect
        let stream = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(addrs.as_slice()))
            .await
            .map_err(|_| "connection timed out".to_string())?
            .map_err(|e| format!("failed to connect: {}", e))?;

        stream.set_nodelay(true).ok();
        let remote_addr = stream
            .peer_addr()
            .map_err(|e| format!("peer_addr: {}", e))?;

        // TLS handshake
        let client_config = self.client_config.read().await.clone();
        let connector = tokio_rustls::TlsConnector::from(client_config);

        let server_name = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
            Err(_) => rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|e| format!("invalid server name '{}': {}", host, e))?,
        };

        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| format!("TLS handshake failed: {}", e))?;

        // WebSocket handshake over the TLS stream
        let boxed: Box<dyn AsyncConn> = Box::new(tls_stream);
        let ws_stream = ws_client_handshake(boxed, &host, port).await?;

        Ok(TransportStream {
            stream: Box::new(ws_stream),
            remote_addr,
        })
    }

    async fn listen(
        &self,
        url: &Url,
    ) -> Result<Box<dyn TransportListener>, String> {
        let host_port = url
            .socket_addrs(|| Some(0))
            .map_err(|e| format!("invalid address: {}", e))?
            .first()
            .ok_or("no address resolved")?
            .to_string();

        let listener = TcpListener::bind(&host_port)
            .await
            .map_err(|e| format!("bind failed: {}", e))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| format!("local_addr: {}", e))?;

        let server_config = self.server_config.read().await.clone();
        let acceptor = TlsAcceptor::from(server_config);

        let (tx, rx) = mpsc::channel::<TransportStream>(64);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_clone.cancelled() => break,
                    result = listener.accept() => {
                        match result {
                            Ok((stream, remote_addr)) => {
                                let tx = tx.clone();
                                let acceptor = acceptor.clone();
                                tokio::spawn(async move {
                                    // TLS handshake
                                    let tls_stream = match acceptor.accept(stream).await {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::debug!("WSS TLS handshake failed from {}: {}", remote_addr, e);
                                            return;
                                        }
                                    };

                                    // WebSocket handshake over TLS
                                    let boxed: Box<dyn AsyncConn> = Box::new(tls_stream);
                                    match ws_server_handshake(boxed).await {
                                        Ok(ws_stream) => {
                                            let _ = tx.send(TransportStream {
                                                stream: Box::new(ws_stream),
                                                remote_addr,
                                            }).await;
                                        }
                                        Err(e) => {
                                            tracing::debug!("WSS WebSocket handshake failed from {}: {}", remote_addr, e);
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!("WSS accept error: {}", e);
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(Box::new(WssTransportListener {
            local_addr,
            rx: Mutex::new(rx),
            cancel,
        }))
    }

    fn scheme(&self) -> &str {
        "wss"
    }
}

struct WssTransportListener {
    local_addr: SocketAddr,
    rx: Mutex<mpsc::Receiver<TransportStream>>,
    cancel: CancellationToken,
}

#[async_trait]
impl TransportListener for WssTransportListener {
    async fn accept(&self) -> Result<TransportStream, String> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| "WSS listener closed".to_string())
    }

    fn local_addr(&self) -> Result<SocketAddr, String> {
        Ok(self.local_addr)
    }

    async fn close(&self) {
        self.cancel.cancel();
    }
}
