//! SOCKS5 server (RFC 1928) with optional username/password authentication
//! (RFC 1929). Supports CONNECT to IPv6 addresses in 200::/7 and to domain
//! names of the form `<hex key>.pk.ygg`; other names can be mapped through a
//! custom resolver.

use std::io;
use std::net::SocketAddrV6;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::host::{Host, Target};
use crate::YggStack;

const VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_PASSWORD: u8 = 0x02;
const AUTH_UNACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCEEDED: u8 = 0x00;
const REP_FAILURE: u8 = 0x01;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_TTL_EXPIRED: u8 = 0x06;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

type Resolver = dyn Fn(&str) -> Option<Host> + Send + Sync;

/// SOCKS5 proxy into the Yggdrasil network.
///
/// ```no_run
/// # async fn demo(stack: yggdrasil_stack::YggStack) -> std::io::Result<()> {
/// use yggdrasil_stack::proxy::Socks5Server;
/// let listener = tokio::net::TcpListener::bind("127.0.0.1:1080").await?;
/// Socks5Server::new(stack).serve(listener).await
/// # }
/// ```
#[derive(Clone)]
pub struct Socks5Server {
    stack: YggStack,
    credentials: Option<Arc<(String, String)>>,
    resolver: Option<Arc<Resolver>>,
}

impl Socks5Server {
    pub fn new(stack: YggStack) -> Self {
        Self { stack, credentials: None, resolver: None }
    }

    /// Require username/password authentication.
    pub fn with_credentials(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.credentials = Some(Arc::new((username.into(), password.into())));
        self
    }

    /// Map domain names that are not `<key>.pk.ygg` (e.g. from a hosts file).
    /// Names the resolver returns `None` for are reported as unreachable.
    pub fn with_resolver(mut self, resolver: impl Fn(&str) -> Option<Host> + Send + Sync + 'static) -> Self {
        self.resolver = Some(Arc::new(resolver));
        self
    }

    /// Accept clients until `listener` fails. Each client runs in its own task.
    pub async fn serve(self, listener: TcpListener) -> io::Result<()> {
        loop {
            let (client, from) = listener.accept().await?;
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(e) = server.handle(client).await {
                    tracing::debug!("socks5: client {}: {}", from, e);
                }
            });
        }
    }

    /// Serve one client connection to completion.
    pub async fn handle(&self, mut client: TcpStream) -> io::Result<()> {
        let _ = client.set_nodelay(true);
        self.negotiate_auth(&mut client).await?;

        let mut head = [0u8; 4];
        client.read_exact(&mut head).await?;
        if head[0] != VERSION {
            return Err(protocol_error("bad request version"));
        }
        let target = match self.read_target(&mut client, head[3]).await {
            Ok(Some(target)) => target,
            Ok(None) => {
                reply(&mut client, REP_HOST_UNREACHABLE, None).await?;
                return Err(io::Error::new(io::ErrorKind::NotFound, "unresolvable host"));
            }
            Err(code) => {
                reply(&mut client, code, None).await?;
                return Err(protocol_error("unsupported address type"));
            }
        };
        if head[1] != CMD_CONNECT {
            reply(&mut client, REP_COMMAND_NOT_SUPPORTED, None).await?;
            return Err(protocol_error("only CONNECT is supported"));
        }

        let mut remote = match self.stack.tcp_connect_target(&target).await {
            Ok(s) => s,
            Err(e) => {
                reply(&mut client, reply_code(&e), None).await?;
                return Err(e);
            }
        };
        reply(&mut client, REP_SUCCEEDED, Some(remote.local_addr())).await?;
        tracing::debug!("socks5: connected to {}", target);
        tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
        Ok(())
    }

    async fn negotiate_auth(&self, client: &mut TcpStream) -> io::Result<()> {
        let mut head = [0u8; 2];
        client.read_exact(&mut head).await?;
        if head[0] != VERSION {
            return Err(protocol_error("not a SOCKS5 client"));
        }
        let mut methods = vec![0u8; head[1] as usize];
        client.read_exact(&mut methods).await?;

        let wanted = if self.credentials.is_some() { AUTH_PASSWORD } else { AUTH_NONE };
        if !methods.contains(&wanted) {
            client.write_all(&[VERSION, AUTH_UNACCEPTABLE]).await?;
            return Err(protocol_error("no acceptable authentication method"));
        }
        client.write_all(&[VERSION, wanted]).await?;

        if let Some(creds) = &self.credentials {
            // RFC 1929: VER(1) ULEN(1) UNAME PLEN(1) PASSWD
            let mut ver_len = [0u8; 2];
            client.read_exact(&mut ver_len).await?;
            let mut user = vec![0u8; ver_len[1] as usize];
            client.read_exact(&mut user).await?;
            let plen = client.read_u8().await?;
            let mut pass = vec![0u8; plen as usize];
            client.read_exact(&mut pass).await?;
            let ok = ver_len[0] == 0x01 && user == creds.0.as_bytes() && pass == creds.1.as_bytes();
            client.write_all(&[0x01, if ok { 0x00 } else { 0x01 }]).await?;
            if !ok {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "authentication failed"));
            }
        }
        Ok(())
    }

    /// Read DST.ADDR and DST.PORT. `Ok(None)` means a name that does not
    /// resolve; `Err` carries the reply code for an unsupported address type.
    async fn read_target(&self, client: &mut TcpStream, atyp: u8) -> Result<Option<Target>, u8> {
        let io_err = |_| REP_FAILURE;
        let host = match atyp {
            ATYP_IPV6 => {
                let mut addr = [0u8; 16];
                client.read_exact(&mut addr).await.map_err(io_err)?;
                let addr = std::net::Ipv6Addr::from(addr);
                crate::stack::check_remote(&addr).ok().map(|_| Host::Addr(addr))
            }
            ATYP_DOMAIN => {
                let len = client.read_u8().await.map_err(io_err)?;
                let mut name = vec![0u8; len as usize];
                client.read_exact(&mut name).await.map_err(io_err)?;
                let name = String::from_utf8_lossy(&name);
                name.parse::<Host>()
                    .ok()
                    .or_else(|| self.resolver.as_ref().and_then(|r| r(&name)))
            }
            ATYP_IPV4 => {
                // Drain it so the reply is not mixed with unread request bytes.
                let mut rest = [0u8; 6];
                client.read_exact(&mut rest).await.map_err(io_err)?;
                return Err(REP_ADDRESS_NOT_SUPPORTED);
            }
            _ => return Err(REP_ADDRESS_NOT_SUPPORTED),
        };
        let port = client.read_u16().await.map_err(io_err)?;
        Ok(host.map(|host| Target { host, port }))
    }
}

fn protocol_error(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn reply_code(e: &io::Error) -> u8 {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => REP_CONNECTION_REFUSED,
        io::ErrorKind::TimedOut => REP_TTL_EXPIRED,
        io::ErrorKind::InvalidInput => REP_HOST_UNREACHABLE,
        _ => REP_FAILURE,
    }
}

async fn reply(client: &mut TcpStream, code: u8, bound: Option<SocketAddrV6>) -> io::Result<()> {
    let bound = bound.unwrap_or_else(|| SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0));
    let mut msg = Vec::with_capacity(22);
    msg.extend_from_slice(&[VERSION, code, 0x00, ATYP_IPV6]);
    msg.extend_from_slice(&bound.ip().octets());
    msg.extend_from_slice(&bound.port().to_be_bytes());
    client.write_all(&msg).await
}
