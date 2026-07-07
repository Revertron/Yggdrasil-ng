//! WebSocket transport primitives (ws:// and, with TLS, wss://).
//!
//! Provides a WebSocket handshake over an already-connected byte stream and a
//! `WsStream` adapter that exposes the binary-framed WebSocket connection as a
//! plain `AsyncRead + AsyncWrite` byte stream for the Yggdrasil handshake.

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use ironwood::types::AsyncConn;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::WebSocketStream;

pub(crate) const WS_SUBPROTOCOL: &str = "ygg-ws";

/// Perform a WebSocket client handshake over an already-connected stream
/// (plain TCP for ws://, or a TLS stream for wss://).
pub(crate) async fn ws_client_handshake(
    stream: Box<dyn AsyncConn>,
    host: &str,
    port: u16,
    path: &str,
    remote_addr: SocketAddr,
) -> Result<WsStream, String> {
    use tokio_tungstenite::tungstenite::handshake::client::generate_key;
    use tokio_tungstenite::tungstenite::http::{Request, Uri};

    // IPv6 addresses must be bracketed in URIs and Host headers
    let authority = if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };
    // Honor the peer URL's path (e.g. `/yws` when behind a reverse proxy).
    // Empty path falls back to root.
    let path = if path.is_empty() { "/" } else { path };
    let ws_url = format!("ws://{}{}", authority, path);
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

    Ok(WsStream::new(ws_stream, remote_addr))
}

/// Perform a WebSocket server handshake, checking the Yggdrasil subprotocol.
pub(crate) async fn ws_server_handshake(
    stream: Box<dyn AsyncConn>,
    remote_addr: SocketAddr,
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

    Ok(WsStream::new(ws_stream, remote_addr))
}

/// Adapts a type-erased WebSocket stream to AsyncRead + AsyncWrite.
///
/// Translates between WebSocket binary message framing and byte-stream semantics:
/// - Read: buffers incoming binary messages, serves bytes sequentially
/// - Write: wraps each write into a binary WebSocket message
pub(crate) struct WsStream {
    sink: tokio::sync::Mutex<SplitSink<WebSocketStream<Box<dyn AsyncConn>>, Message>>,
    recv: tokio::sync::Mutex<WsRecvState>,
    remote_addr: SocketAddr,
}

struct WsRecvState {
    stream: SplitStream<WebSocketStream<Box<dyn AsyncConn>>>,
    buf: Vec<u8>,
    pos: usize,
}

impl WsStream {
    fn new(ws: WebSocketStream<Box<dyn AsyncConn>>, remote_addr: SocketAddr) -> Self {
        let (sink, stream) = ws.split();
        Self {
            sink: tokio::sync::Mutex::new(sink),
            recv: tokio::sync::Mutex::new(WsRecvState {
                stream,
                buf: Vec::new(),
                pos: 0,
            }),
            remote_addr,
        }
    }

    pub(crate) fn peer_addr(&self) -> SocketAddr {
        self.remote_addr
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
