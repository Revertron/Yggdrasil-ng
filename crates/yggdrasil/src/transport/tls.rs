use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::links::LinkOptions;
use super::{apply_scope_id, bare_host, Transport, TransportListener, TransportStream};

const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

pub struct TlsTransport {
    server_config: Arc<RwLock<Arc<rustls::ServerConfig>>>,
    client_config: Arc<RwLock<Arc<rustls::ClientConfig>>>,
}

impl TlsTransport {
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
impl Transport for TlsTransport {
    async fn dial(
        &self,
        url: &Url,
        options: &LinkOptions,
    ) -> Result<TransportStream, String> {
        let host = bare_host(url)?;
        let mut addrs = url
            .socket_addrs(|| None)
            .map_err(|e| format!("address resolution failed: {}", e))?;

        // Fix up scope_id for link-local IPv6 addresses (multicast discovery)
        apply_scope_id(&mut addrs, options.scope_id);

        let stream = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(addrs.as_slice()))
            .await
            .map_err(|_| "connection timed out".to_string())?
            .map_err(|e| format!("failed to connect: {}", e))?;

        stream.set_nodelay(true).ok();

        let remote_addr = stream
            .peer_addr()
            .map_err(|e| format!("peer_addr: {}", e))?;

        let client_config = self.client_config.read().await.clone();
        let connector = TlsConnector::from(client_config);

        let server_name = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
            Err(_) => rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|e| format!("invalid server name '{}': {}", host, e))?,
        };

        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| format!("TLS handshake failed: {}", e))?;

        Ok(TransportStream {
            stream: Box::new(tls_stream),
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

        Ok(Box::new(TlsTransportListener {
            listener,
            local_addr,
            acceptor: TlsAcceptor::from(server_config),
            cancel: CancellationToken::new(),
        }))
    }

    fn scheme(&self) -> &str {
        "tls"
    }
}

struct TlsTransportListener {
    listener: TcpListener,
    local_addr: SocketAddr,
    acceptor: TlsAcceptor,
    cancel: CancellationToken,
}

#[async_trait]
impl TransportListener for TlsTransportListener {
    async fn accept(&self) -> Result<TransportStream, String> {
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    return Err("listener closed".to_string());
                }
                result = self.listener.accept() => {
                    let (stream, remote_addr) = result
                        .map_err(|e| format!("accept failed: {}", e))?;
                    stream.set_nodelay(true).ok();

                    let tls_stream = self.acceptor.accept(stream)
                        .await
                        .map_err(|e| format!("TLS handshake failed: {}", e))?;

                    return Ok(TransportStream {
                        stream: Box::new(tls_stream),
                        remote_addr,
                    });
                }
            }
        }
    }

    fn local_addr(&self) -> Result<SocketAddr, String> {
        Ok(self.local_addr)
    }

    async fn close(&self) {
        self.cancel.cancel();
    }
}
