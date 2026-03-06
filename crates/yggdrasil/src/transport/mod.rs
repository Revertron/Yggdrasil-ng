use std::net::{SocketAddr, SocketAddrV6};

use async_trait::async_trait;
use ironwood::types::AsyncConn;
use url::Url;

use crate::links::LinkOptions;

pub mod tcp;
pub mod tls;

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "websocket")]
pub mod ws;
#[cfg(feature = "websocket")]
pub mod wss;

/// A connected transport stream with its remote address.
pub struct TransportStream {
    pub stream: Box<dyn AsyncConn>,
    pub remote_addr: SocketAddr,
}

/// Trait for transport protocols (TCP, TLS, QUIC, WebSocket, etc.).
///
/// Mirrors yggdrasil-go's `linkProtocol` interface.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Dial a remote peer.
    async fn dial(
        &self,
        url: &Url,
        options: &LinkOptions,
    ) -> Result<TransportStream, String>;

    /// Start listening for incoming connections.
    async fn listen(
        &self,
        url: &Url,
    ) -> Result<Box<dyn TransportListener>, String>;

    /// URL scheme(s) this transport handles (e.g., "tcp", "tls", "quic").
    fn scheme(&self) -> &str;
}

/// Extract the bare hostname from a URL, stripping IPv6 brackets.
///
/// `url::Url::host_str()` returns `[::1]` for IPv6 addresses (with brackets),
/// which is correct for socket address formatting but breaks TLS/QUIC server
/// name parsing. This helper strips the brackets.
pub(crate) fn bare_host(url: &Url) -> Result<String, String> {
    let host = url.host_str().ok_or("missing host")?;
    Ok(host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_string())
}

/// Fix up resolved addresses with an IPv6 scope ID.
///
/// The `url` crate doesn't support IPv6 zone IDs, so `url.socket_addrs()`
/// always returns `SocketAddrV6` with `scope_id = 0`. For link-local
/// addresses (`fe80::/10`), the kernel needs a non-zero scope_id to know
/// which interface to route through. This function copies the scope_id
/// from `LinkOptions` onto any link-local `SocketAddrV6` in the list.
pub(crate) fn apply_scope_id(addrs: &mut [SocketAddr], scope_id: u32) {
    if scope_id == 0 {
        return;
    }
    for addr in addrs.iter_mut() {
        if let SocketAddr::V6(v6) = addr {
            if is_link_local(v6.ip()) && v6.scope_id() == 0 {
                *addr = SocketAddr::V6(SocketAddrV6::new(
                    *v6.ip(),
                    v6.port(),
                    v6.flowinfo(),
                    scope_id,
                ));
            }
        }
    }
}

/// Check if an IPv6 address is link-local (fe80::/10).
fn is_link_local(ip: &std::net::Ipv6Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
}

/// Parse a URL string that may contain an IPv6 zone ID.
///
/// The `url` crate (WHATWG URL Standard) doesn't support IPv6 zone IDs.
/// This function detects zone IDs in two forms:
///   - Percent-encoded: `tls://[fe80::1%25lo0]:1234`
///   - Raw: `tls://[fe80::1%lo0]:1234`
///
/// It strips the zone ID before passing to `Url::parse`, and resolves
/// the zone to a numeric OS interface index (scope_id).
///
/// Returns `(parsed_url, scope_id)` where scope_id is 0 if no zone ID found.
pub(crate) fn parse_url_with_zone_id(uri: &str) -> Result<(Url, u32), String> {
    let open = uri.find('[');
    let close = uri.find(']');

    if let (Some(open_idx), Some(close_idx)) = (open, close) {
        if open_idx < close_idx {
            let host_part = &uri[open_idx + 1..close_idx];

            // Try %25 first (percent-encoded form), then raw %
            let (zone_str, pct_start) = if let Some(pos) = host_part.find("%25") {
                (Some(&host_part[pos + 3..]), pos)
            } else if let Some(pos) = host_part.rfind('%') {
                (Some(&host_part[pos + 1..]), pos)
            } else {
                (None, 0)
            };

            if let Some(zone) = zone_str {
                if zone.is_empty() {
                    return Err("empty zone ID in IPv6 address".to_string());
                }

                let scope_id = resolve_zone_id(zone)?;

                // Rebuild URI without the zone ID
                let before_zone = &uri[..open_idx + 1 + pct_start];
                let after_bracket = &uri[close_idx..];
                let cleaned = format!("{}{}", before_zone, after_bracket);

                let url = Url::parse(&cleaned)
                    .map_err(|e| format!("invalid URL: {}", e))?;

                return Ok((url, scope_id));
            }
        }
    }

    let url = Url::parse(uri).map_err(|e| format!("invalid URL: {}", e))?;
    Ok((url, 0))
}

/// Resolve a zone ID string to a numeric scope_id.
/// Accepts either a numeric index ("3") or an interface name ("lo0").
fn resolve_zone_id(zone: &str) -> Result<u32, String> {
    if let Ok(idx) = zone.parse::<u32>() {
        return Ok(idx);
    }
    interface_name_to_index(zone)
        .ok_or_else(|| format!("unknown interface '{}' in zone ID", zone))
}

/// Resolve an interface name (e.g., "lo0", "eth0") to its OS index.
pub(crate) fn interface_name_to_index(name: &str) -> Option<u32> {
    use std::ffi::CString;
    let c_name = CString::new(name).ok()?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 { None } else { Some(idx) }
}

/// Resolve an OS interface index to its name (e.g., 14 → "en0").
pub(crate) fn interface_index_to_name(idx: u32) -> Option<String> {
    let mut buf = [0u8; libc::IFNAMSIZ];
    let ptr = unsafe { libc::if_indextoname(idx, buf.as_mut_ptr() as *mut libc::c_char) };
    if ptr.is_null() {
        return None;
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..len].to_vec()).ok()
}

/// Format a `SocketAddr` for use in a URI, replacing a numeric IPv6 zone ID
/// with the interface name (e.g., `[fe80::1%14]:1234` → `[fe80::1%en0]:1234`).
pub(crate) fn format_socket_addr_for_uri(addr: &SocketAddr) -> String {
    if let SocketAddr::V6(v6) = addr {
        let scope = v6.scope_id();
        if scope != 0 {
            let zone = interface_index_to_name(scope)
                .unwrap_or_else(|| scope.to_string());
            return format!("[{}%{}]:{}", v6.ip(), zone, v6.port());
        }
    }
    // IPv4 or IPv6 without scope: use standard display, but wrap IPv6 in brackets.
    match addr {
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
        SocketAddr::V4(_) => addr.to_string(),
    }
}

/// Listener that accepts incoming transport connections.
#[async_trait]
pub trait TransportListener: Send + Sync {
    /// Accept a new incoming connection.
    async fn accept(&self) -> Result<TransportStream, String>;

    /// Get the local address we're listening on.
    fn local_addr(&self) -> Result<SocketAddr, String>;

    /// Close the listener.
    async fn close(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url_no_zone() {
        let (url, scope) = parse_url_with_zone_id("tls://192.168.1.1:1234").unwrap();
        assert_eq!(scope, 0);
        assert_eq!(url.host_str(), Some("192.168.1.1"));
    }

    #[test]
    fn test_parse_url_ipv6_no_zone() {
        let (url, scope) = parse_url_with_zone_id("tls://[fe80::1]:1234").unwrap();
        assert_eq!(scope, 0);
        assert_eq!(url.port(), Some(1234));
    }

    #[test]
    fn test_parse_url_percent_encoded_zone_numeric() {
        let (url, scope) = parse_url_with_zone_id("tls://[fe80::1%251]:1234").unwrap();
        assert_eq!(scope, 1);
        assert_eq!(url.port(), Some(1234));
        // Zone ID stripped — host should be bare fe80::1
        let host = bare_host(&url).unwrap();
        assert_eq!(host, "fe80::1");
    }

    #[test]
    fn test_parse_url_raw_percent_zone_numeric() {
        let (url, scope) = parse_url_with_zone_id("tls://[fe80::1%3]:1234").unwrap();
        assert_eq!(scope, 3);
        assert_eq!(url.port(), Some(1234));
    }

    #[test]
    fn test_parse_url_with_query_params() {
        let (url, scope) = parse_url_with_zone_id(
            "tls://[fe80::1%252]:1234?key=aabb&priority=1"
        ).unwrap();
        assert_eq!(scope, 2);
        assert_eq!(url.query(), Some("key=aabb&priority=1"));
    }

    #[test]
    fn test_parse_url_empty_zone_error() {
        assert!(parse_url_with_zone_id("tls://[fe80::1%25]:1234").is_err());
        assert!(parse_url_with_zone_id("tls://[fe80::1%]:1234").is_err());
    }

    #[test]
    fn test_parse_url_interface_name_zone() {
        // Use lo0 (macOS) or lo (Linux) — should exist on any system
        let lo = if cfg!(target_os = "macos") { "lo0" } else { "lo" };
        let uri = format!("tls://[fe80::1%25{}]:1234", lo);
        let (url, scope) = parse_url_with_zone_id(&uri).unwrap();
        assert!(scope > 0, "scope_id should be non-zero for {}", lo);
        assert_eq!(url.port(), Some(1234));
    }

    #[test]
    fn test_parse_url_unknown_interface_error() {
        let result = parse_url_with_zone_id("tls://[fe80::1%25nonexistent_iface_xyz]:1234");
        assert!(result.is_err());
    }
}
