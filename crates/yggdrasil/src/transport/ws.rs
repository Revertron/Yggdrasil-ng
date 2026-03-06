use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use ironwood::types::AsyncConn;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::WebSocketStream;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::links::LinkOptions;
use super::{apply_scope_id, bare_host, Transport, TransportListener, TransportStream};

const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const WS_SUBPROTOCOL: &str = "ygg-ws";

pub struct WsTransport;

impl WsTransport {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Transport for WsTransport {
    async fn dial(
        &self,
        url: &Url,
        options: &LinkOptions,
    ) -> Result<TransportStream, String> {
        let host = bare_host(url)?;
        let port = url.port().ok_or("missing port")?;
        let mut addrs = url
            .socket_addrs(|| None)
            .map_err(|e| format!("address resolution failed: {}", e))?;

        // Fix up scope_id for link-local IPv6 addresses (multicast discovery)
        apply_scope_id(&mut addrs, options.scope_id);

        // Connect raw TCP first
        let stream = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(addrs.as_slice()))
            .await
            .map_err(|_| "connection timed out".to_string())?
            .map_err(|e| format!("failed to connect: {}", e))?;

        stream.set_nodelay(true).ok();
        let remote_addr = stream
            .peer_addr()
            .map_err(|e| format!("peer_addr: {}", e))?;

        // Type-erase the stream
        let boxed: Box<dyn AsyncConn> = Box::new(stream);

        // Do WebSocket handshake over the type-erased stream
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
                                tokio::spawn(async move {
                                    let boxed: Box<dyn AsyncConn> = Box::new(stream);
                                    match ws_server_handshake(boxed).await {
                                        Ok(ws_stream) => {
                                            let _ = tx.send(TransportStream {
                                                stream: Box::new(ws_stream),
                                                remote_addr,
                                            }).await;
                                        }
                                        Err(e) => {
                                            tracing::debug!("WebSocket handshake failed from {}: {}", remote_addr, e);
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!("WS accept error: {}", e);
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(Box::new(WsTransportListener {
            local_addr,
            rx: Mutex::new(rx),
            cancel,
        }))
    }

    fn scheme(&self) -> &str {
        "ws"
    }
}

struct WsTransportListener {
    local_addr: SocketAddr,
    rx: Mutex<mpsc::Receiver<TransportStream>>,
    cancel: CancellationToken,
}

#[async_trait]
impl TransportListener for WsTransportListener {
    async fn accept(&self) -> Result<TransportStream, String> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| "WebSocket listener closed".to_string())
    }

    fn local_addr(&self) -> Result<SocketAddr, String> {
        Ok(self.local_addr)
    }

    async fn close(&self) {
        self.cancel.cancel();
    }
}

// ── Shared WS handshake helpers (used by both ws.rs and wss.rs) ──

/// Perform a WebSocket client handshake over an already-connected stream.
pub(crate) async fn ws_client_handshake(
    stream: Box<dyn AsyncConn>,
    host: &str,
    port: u16,
) -> Result<WsStream, String> {
    use tokio_tungstenite::tungstenite::handshake::client::generate_key;
    use tokio_tungstenite::tungstenite::http::{Request, Uri};

    // IPv6 addresses must be bracketed in URIs and Host headers
    let authority = if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };
    let ws_url = format!("ws://{}/", authority);
    let uri: Uri = ws_url
        .parse()
        .map_err(|e| format!("invalid WS URI: {}", e))?;

    let request = Request::builder()
        .uri(&uri)
        .header("Host", &authority)
        .header("Sec-WebSocket-Protocol", WS_SUBPROTOCOL)
        .header("Sec-WebSocket-Key", generate_key())
        .header("Sec-WebSocket-Version", "13")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .body(())
        .map_err(|e| format!("build request: {}", e))?;

    let (ws_stream, _response) = tokio_tungstenite::client_async(request, stream)
        .await
        .map_err(|e| format!("WebSocket handshake failed: {}", e))?;

    Ok(WsStream::new(ws_stream))
}

/// Perform a WebSocket server handshake, checking subprotocol.
pub(crate) async fn ws_server_handshake(
    stream: Box<dyn AsyncConn>,
) -> Result<WsStream, String> {
    use tokio_tungstenite::tungstenite::handshake::server::{
        ErrorResponse, Request as WsRequest, Response as WsResponse,
    };

    let callback =
        |req: &WsRequest, mut response: WsResponse| -> Result<WsResponse, ErrorResponse> {
            // Health check endpoint
            let path = req.uri().path();
            if path == "/health" || path == "/healthz" {
                let mut resp = ErrorResponse::new(Some("OK".to_string()));
                *resp.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::OK;
                return Err(resp);
            }

            // Check and set subprotocol
            let has_subprotocol = req
                .headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(',').any(|s| s.trim() == WS_SUBPROTOCOL))
                .unwrap_or(false);

            if has_subprotocol {
                response.headers_mut().insert(
                    "Sec-WebSocket-Protocol",
                    WS_SUBPROTOCOL.parse().unwrap(),
                );
            }

            Ok(response)
        };

    let ws_stream = tokio_tungstenite::accept_hdr_async(stream, callback)
        .await
        .map_err(|e| format!("WebSocket handshake failed: {}", e))?;

    Ok(WsStream::new(ws_stream))
}

// ── WsStream: adapts WebSocketStream to AsyncRead + AsyncWrite ──

/// Adapts a type-erased WebSocket stream to AsyncRead + AsyncWrite.
///
/// Translates between WebSocket binary message framing and byte-stream semantics:
/// - Read: buffers incoming binary messages, serves bytes sequentially
/// - Write: wraps each write into a binary WebSocket message
pub(crate) struct WsStream {
    sink: tokio::sync::Mutex<SplitSink<WebSocketStream<Box<dyn AsyncConn>>, Message>>,
    recv: tokio::sync::Mutex<WsRecvState>,
}

struct WsRecvState {
    stream: SplitStream<WebSocketStream<Box<dyn AsyncConn>>>,
    buf: Vec<u8>,
    pos: usize,
}

impl WsStream {
    pub(crate) fn new(ws: WebSocketStream<Box<dyn AsyncConn>>) -> Self {
        let (sink, stream) = ws.split();
        Self {
            sink: tokio::sync::Mutex::new(sink),
            recv: tokio::sync::Mutex::new(WsRecvState {
                stream,
                buf: Vec::new(),
                pos: 0,
            }),
        }
    }
}

impl AsyncRead for WsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut recv = match self.recv.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        let state = &mut *recv;

        // Serve from buffer first
        if state.pos < state.buf.len() {
            let remaining = &state.buf[state.pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            state.pos += to_copy;
            if state.pos >= state.buf.len() {
                state.buf.clear();
                state.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Read next WebSocket message
        match state.stream.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(msg))) => match msg {
                Message::Binary(data) => {
                    let to_copy = data.len().min(buf.remaining());
                    buf.put_slice(&data[..to_copy]);
                    if to_copy < data.len() {
                        state.buf = data.to_vec();
                        state.pos = to_copy;
                    }
                    Poll::Ready(Ok(()))
                }
                Message::Close(_) => Poll::Ready(Ok(())),
                // Skip non-binary messages (ping/pong handled by tungstenite)
                _ => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            },
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // Stream ended
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut sink = match self.sink.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        match sink.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => {
                let msg = Message::Binary(buf.to_vec().into());
                match sink.start_send_unpin(msg) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e,
                    ))),
                }
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut sink = match self.sink.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        sink.poll_flush_unpin(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut sink = match self.sink.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        sink.poll_close_unpin(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}
