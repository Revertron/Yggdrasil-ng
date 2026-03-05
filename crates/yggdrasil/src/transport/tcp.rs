use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::links::LinkOptions;
use super::{Transport, TransportListener, TransportStream};

const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

pub struct TcpTransport;

impl TcpTransport {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn dial(
        &self,
        url: &Url,
        _options: &LinkOptions,
    ) -> Result<TransportStream, String> {
        let addrs = url
            .socket_addrs(|| None)
            .map_err(|e| format!("address resolution failed: {}", e))?;

        let stream = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(addrs.as_slice()))
            .await
            .map_err(|_| "connection timed out".to_string())?
            .map_err(|e| format!("failed to connect: {}", e))?;

        stream.set_nodelay(true).ok();

        let remote_addr = stream
            .peer_addr()
            .map_err(|e| format!("peer_addr: {}", e))?;

        Ok(TransportStream {
            stream: Box::new(stream),
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

        Ok(Box::new(TcpTransportListener {
            listener,
            local_addr,
            cancel: CancellationToken::new(),
        }))
    }

    fn scheme(&self) -> &str {
        "tcp"
    }
}

struct TcpTransportListener {
    listener: TcpListener,
    local_addr: SocketAddr,
    cancel: CancellationToken,
}

#[async_trait]
impl TransportListener for TcpTransportListener {
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
                    return Ok(TransportStream {
                        stream: Box::new(stream),
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
