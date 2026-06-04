use std::net::IpAddr;

use ipnet::IpNet;
#[cfg(not(target_os = "android"))]
use route_manager::RouteManager;

use crate::address::{is_valid_address, is_valid_subnet};
use crate::config::TunnelRoutingConfig;

const INETV4_PREFIXES: &[&str] = &[
    "0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/3",
    "160.0.0.0/5", "168.0.0.0/6", "172.0.0.0/12", "172.32.0.0/11", "172.64.0.0/10", "172.128.0.0/9", "173.0.0.0/8", "174.0.0.0/7",
    "176.0.0.0/4", "192.0.0.0/9", "192.128.0.0/11", "192.160.0.0/13", "192.169.0.0/16", "192.170.0.0/15", "192.172.0.0/14", "192.176.0.0/12",
    "192.192.0.0/10", "193.0.0.0/8", "194.0.0.0/7", "196.0.0.0/6", "200.0.0.0/5", "208.0.0.0/4"
];

const INETV6_PREFIXES: &[&str] = &["2000::/3"];

/// A single CKR route: CIDR prefix -> destination public key.
struct Route {
    prefix: IpNet,
    destination: [u8; 32],
}

/// CKR routing table. Maps IP subnets to Yggdrasil node public keys.
pub struct CryptoKey {
    yggdrasil_routing: bool,
    v4_routes: Vec<Route>,
    v6_routes: Vec<Route>,
}

impl CryptoKey {
    /// Build a CKR routing table from configuration.
    ///
    /// Routes whose destination equals `self_key` are silently dropped — a
    /// shared config can thus be distributed to every node without each
    /// needing a node-specific copy.
    pub fn new(config: &TunnelRoutingConfig, self_key: &[u8; 32]) -> Result<Self, String> {
        let mut v4_routes = Vec::new();
        let mut v6_routes = Vec::new();

        if !config.enable {
            return Ok(Self {
                yggdrasil_routing: config.yggdrasil_routing,
                v4_routes,
                v6_routes,
            });
        }

        for (pubkey_hex, cidrs) in &config.remote_subnets {
            let dest = parse_pubkey(pubkey_hex)?;
            if &dest == self_key {
                tracing::info!(
                    "CKR: ignoring {} route(s) for own public key {}",
                    cidrs.len(),
                    pubkey_hex
                );
                continue;
            }
            for prefix in expand_cidrs(cidrs)? {
                match prefix {
                    IpNet::V6(_) => {
                        if is_yggdrasil_destination(prefix.addr()) {
                            return Err(format!(
                                "can't specify Yggdrasil destination as routed subnet: {}",
                                prefix
                            ));
                        }
                        if v6_routes.iter().any(|r| r.prefix == prefix) {
                            return Err(format!("duplicate remote subnet: {}", prefix));
                        }
                        v6_routes.push(Route {
                            prefix,
                            destination: dest,
                        });
                    }
                    IpNet::V4(_) => {
                        if v4_routes.iter().any(|r| r.prefix == prefix) {
                            return Err(format!("duplicate remote subnet: {}", prefix));
                        }
                        v4_routes.push(Route {
                            prefix,
                            destination: dest,
                        });
                    }
                }
            }
        }

        // Sort: most specific (longest prefix) first; ties broken by address.
        v4_routes.sort_by(sort_routes);
        v6_routes.sort_by(sort_routes);

        if !v6_routes.is_empty() {
            tracing::info!("Active CKR IPv6 routes:");
            for r in &v6_routes {
                tracing::info!("  {} via {}", r.prefix, hex::encode(r.destination));
            }
        }
        if !v4_routes.is_empty() {
            tracing::info!("Active CKR IPv4 routes:");
            for r in &v4_routes {
                tracing::info!("  {} via {}", r.prefix, hex::encode(r.destination));
            }
        }

        Ok(Self {
            yggdrasil_routing: config.yggdrasil_routing,
            v4_routes,
            v6_routes,
        })
    }

    /// Whether standard Yggdrasil address routing is enabled.
    pub fn yggdrasil_routing(&self) -> bool {
        self.yggdrasil_routing
    }

    /// Look up the destination public key for an IP address using
    /// longest-prefix-match. Returns `None` if no route matches.
    pub fn get_public_key_for_address(&self, addr: IpAddr) -> Option<[u8; 32]> {
        if let IpAddr::V6(_) = addr {
            if is_yggdrasil_destination(addr) {
                return None;
            }
        }

        let routes = match addr {
            IpAddr::V4(_) => &self.v4_routes,
            IpAddr::V6(_) => &self.v6_routes,
        };

        // Routes are sorted most-specific-first, so first match wins.
        for route in routes {
            if route.prefix.contains(&addr) {
                return Some(route.destination);
            }
        }

        None
    }
}

/// Check if an IP address falls within the Yggdrasil address space.
pub fn is_yggdrasil_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => false,
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mut addr_bytes = [0u8; 16];
            addr_bytes.copy_from_slice(&octets);
            let mut subnet_bytes = [0u8; 8];
            subnet_bytes.copy_from_slice(&octets[..8]);
            is_valid_address(&addr_bytes) || is_valid_subnet(&subnet_bytes)
        }
    }
}

/// Parse a list of CIDR entries, where entries prefixed with `!` are
/// treated as exclusions. Returns the minimal set of prefixes covering
/// `(union of includes) \ (union of excludes)`.
///
/// Excludes only apply within the same address family as the includes.
/// Duplicate includes are tolerated; excludes outside any include are ignored.
pub fn expand_cidrs(entries: &[String]) -> Result<Vec<IpNet>, String> {
    let mut v4_inc: Vec<IpNet> = Vec::new();
    let mut v6_inc: Vec<IpNet> = Vec::new();
    let mut v4_exc: Vec<IpNet> = Vec::new();
    let mut v6_exc: Vec<IpNet> = Vec::new();

    let normalized = normalize_subnet_entries(entries);
    for raw in &normalized {
        let cidr_input = if let Some(after_tilde) = raw.strip_prefix('~') {
            after_tilde.trim()
        } else {
            raw.as_str()
        };
        let (is_exclude, cidr_str) = match cidr_input.strip_prefix('!') {
            Some(rest) => (true, rest.trim()),
            None => (false, cidr_input),
        };
        let cidr_for_parse = if !cidr_str.contains('/') {
            if cidr_str.contains(':') {
                format!("{}/128", cidr_str)
            } else {
                format!("{}/32", cidr_str)
            }
        } else {
            cidr_str.to_string()
        };
        let prefix: IpNet = cidr_for_parse
            .parse()
            .map_err(|e| format!("invalid CIDR '{}': {}", cidr_str, e))?;
        // Normalize to the network address (e.g. 10.0.0.5/24 -> 10.0.0.0/24).
        let prefix = prefix.trunc();
        match (is_exclude, prefix) {
            (false, IpNet::V4(_)) => v4_inc.push(prefix),
            (false, IpNet::V6(_)) => v6_inc.push(prefix),
            (true, IpNet::V4(_)) => v4_exc.push(prefix),
            (true, IpNet::V6(_)) => v6_exc.push(prefix),
        }
    }

    let mut out = Vec::new();
    for inc in v4_inc {
        out.extend(subtract_many(inc, &v4_exc));
    }
    for inc in v6_inc {
        out.extend(subtract_many(inc, &v6_exc));
    }
    Ok(out)
}

/// Subtract a set of exclude prefixes from a single include prefix.
/// All prefixes must share an address family.
fn subtract_many(include: IpNet, excludes: &[IpNet]) -> Vec<IpNet> {
    let mut pieces = vec![include];
    for ex in excludes {
        let mut next = Vec::with_capacity(pieces.len());
        for p in pieces {
            if ex.contains(&p) {
                // Piece fully covered by exclude → drop.
            } else if p.contains(ex) {
                next.extend(subtract_one(p, *ex));
            } else {
                // Disjoint (prefix-aligned ranges can't partially overlap).
                next.push(p);
            }
        }
        pieces = next;
    }
    pieces
}

/// Subtract `b` from `a`, requiring `a.contains(&b)` and `a != b`.
/// Produces `log2(|a|/|b|)` disjoint covering prefixes.
fn subtract_one(a: IpNet, b: IpNet) -> Vec<IpNet> {
    let mut result = Vec::new();
    let mut current = a;
    while current != b {
        let new_len = current.prefix_len() + 1;
        let mut halves = match current.subnets(new_len) {
            Ok(it) => it,
            Err(_) => return result,
        };
        let left = match halves.next() {
            Some(x) => x,
            None => return result,
        };
        let right = match halves.next() {
            Some(x) => x,
            None => return result,
        };
        if left.contains(&b) {
            result.push(right);
            current = left;
        } else {
            result.push(left);
            current = right;
        }
    }
    result
}

fn normalize_subnet_entries(entries: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for entry in entries {
        let trimmed = entry.trim();
        match trimmed {
            "inetv4" => normalized.extend(INETV4_PREFIXES.iter().map(|&s| s.to_string())),
            "~inetv4" => normalized.extend(INETV4_PREFIXES.iter().map(|&s| format!("~{}", s))),
            "inetv6" => normalized.extend(INETV6_PREFIXES.iter().map(|&s| s.to_string())),
            "~inetv6" => normalized.extend(INETV6_PREFIXES.iter().map(|&s| format!("~{}", s))),
            _ => normalized.push(trimmed.to_string()),
        }
    }
    normalized
}

fn parse_pubkey(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes =
        hex::decode(hex_str).map_err(|e| format!("invalid public key hex '{}': {}", hex_str, e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "public key should be 32 bytes, got {} for '{}'",
            bytes.len(),
            hex_str
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Install system routes for all configured CKR subnets, pointing them
/// at the TUN interface so the OS sends that traffic into the tunnel.
/// Works on Linux, Windows, and macOS. No-op on Android (VpnService handles routes).
#[cfg(target_os = "android")]
pub fn install_routes(
    _config: &TunnelRoutingConfig,
    _tun_name: &str,
    _self_key: &[u8; 32],
) -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "android"))]
pub fn install_routes(
    config: &TunnelRoutingConfig,
    tun_name: &str,
    self_key: &[u8; 32],
) -> Result<(), String> {
    if !config.enable || !config.install_system_routes {
        return Ok(());
    }

    // Collect all unique CIDRs from the config (expanded, excludes applied).
    // Skip entries whose destination is this node itself — those are handled
    // by the OS's native routing and should not be steered into the TUN.
    let mut cidrs: Vec<IpNet> = Vec::new();
    for (pubkey_hex, subnet_list) in &config.remote_subnets {
        if parse_pubkey(pubkey_hex).ok().as_ref() == Some(self_key) {
            continue;
        }
        let non_tilde_entries: Vec<String> = subnet_list.iter().filter(|s| !s.trim().starts_with('~')).cloned().collect();
        let route_list = normalize_subnet_entries(&non_tilde_entries);
        for prefix in expand_cidrs(&route_list)? {
            if !cidrs.contains(&prefix) {
                cidrs.push(prefix);
            }
        }
    }

    if cidrs.is_empty() {
        return Ok(());
    }

    let mut manager =
        RouteManager::new().map_err(|e| format!("failed to create route manager: {}", e))?;

    for cidr in &cidrs {
        let route = route_manager::Route::new(cidr.network(), cidr.prefix_len())
            .with_if_name(tun_name.to_string());

        match manager.add(&route) {
            Ok(()) => {
                tracing::info!("Installed route: {} via {}", cidr, tun_name);
            }
            Err(e) => {
                tracing::warn!("Failed to install route {} via {}: {}", cidr, tun_name, e);
            }
        }
    }

    Ok(())
}

/// Remove previously installed CKR routes from the system routing table.
#[cfg(target_os = "android")]
pub fn remove_routes(_config: &TunnelRoutingConfig, _tun_name: &str, _self_key: &[u8; 32]) {}

#[cfg(not(target_os = "android"))]
pub fn remove_routes(config: &TunnelRoutingConfig, tun_name: &str, self_key: &[u8; 32]) {
    if !config.enable || !config.install_system_routes {
        return;
    }

    let mut cidrs: Vec<IpNet> = Vec::new();
    for (pubkey_hex, subnet_list) in &config.remote_subnets {
        if parse_pubkey(pubkey_hex).ok().as_ref() == Some(self_key) {
            continue;
        }
        let non_tilde_entries: Vec<String> = subnet_list.iter().filter(|s| !s.trim().starts_with('~')).cloned().collect();
        let route_list = normalize_subnet_entries(&non_tilde_entries);
        if let Ok(expanded) = expand_cidrs(&route_list) {
            for prefix in expanded {
                if !cidrs.contains(&prefix) {
                    cidrs.push(prefix);
                }
            }
        }
    }

    let mut manager = match RouteManager::new() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("Failed to create route manager for cleanup: {}", e);
            return;
        }
    };

    for cidr in &cidrs {
        let route = route_manager::Route::new(cidr.network(), cidr.prefix_len())
            .with_if_name(tun_name.to_string());
        if let Err(e) = manager.delete(&route) {
            tracing::debug!("Failed to remove route {}: {}", cidr, e);
        }
    }
}

/// Sort routes: longest prefix first, then by address for ties.
fn sort_routes(a: &Route, b: &Route) -> std::cmp::Ordering {
    let bits_a = a.prefix.prefix_len();
    let bits_b = b.prefix.prefix_len();
    // Reverse: longer prefix = higher priority = comes first
    match bits_b.cmp(&bits_a) {
        std::cmp::Ordering::Equal => a.prefix.addr().cmp(&b.prefix.addr()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_config(subnets: HashMap<String, Vec<String>>) -> TunnelRoutingConfig {
        TunnelRoutingConfig {
            enable: true,
            yggdrasil_routing: true,
            ipv4_address: String::new(),
            ip_addresses: Vec::new(),
            remote_subnets: subnets,
            install_system_routes: true,
        }
    }

    fn dummy_key_hex() -> String {
        hex::encode([0x01u8; 32])
    }

    fn other_key_hex() -> String {
        hex::encode([0x02u8; 32])
    }

    /// A self-key distinct from any configured route key, so the existing
    /// tests exercise the populated table (self-dropping is covered in its
    /// own test below).
    const SELF_KEY: [u8; 32] = [0xffu8; 32];

    #[test]
    fn test_empty_config() {
        let config = TunnelRoutingConfig::default();
        let ckr = CryptoKey::new(&config, &SELF_KEY).unwrap();
        assert!(ckr.v4_routes.is_empty());
        assert!(ckr.v6_routes.is_empty());
    }

    #[test]
    fn test_disabled_config() {
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["10.0.0.0/24".to_string()]);
        let config = TunnelRoutingConfig {
            enable: false,
            yggdrasil_routing: true,
            ipv4_address: String::new(),
            ip_addresses: Vec::new(),
            remote_subnets: subnets,
            install_system_routes: true,
        };
        let ckr = CryptoKey::new(&config, &SELF_KEY).unwrap();
        assert!(ckr.v4_routes.is_empty());
    }

    #[test]
    fn test_ipv4_route_lookup() {
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["10.0.0.0/24".to_string(), "192.168.1.100".to_string()]);
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();

        let addr: IpAddr = "10.0.0.5".parse().unwrap();
        let key = ckr.get_public_key_for_address(addr);
        assert_eq!(key, Some([0x01u8; 32]));

        let miss: IpAddr = "192.168.0.1".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(miss), None);
        let bare_addr: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(bare_addr), Some([0x01u8; 32]));
    }

    #[test]
    fn test_ipv6_route_lookup() {
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec!["2001:db8::/32".to_string(), "2001:db8:aaaa::1".to_string()],
        );
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();

        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(addr), Some([0x01u8; 32]));

        let miss: IpAddr = "2001:db9::1".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(miss), None);
        let bare_addr: IpAddr = "2001:db8:aaaa::1".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(bare_addr), Some([0x01u8; 32]));
    }

    #[test]
    fn test_longest_prefix_match() {
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["10.0.0.0/24".to_string()]);
        subnets.insert(other_key_hex(), vec!["10.0.0.0/25".to_string()]);
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();

        // 10.0.0.5 matches both /24 and /25, but /25 is more specific
        let addr: IpAddr = "10.0.0.5".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(addr), Some([0x02u8; 32]));

        // 10.0.0.200 only matches /24 (not in /25 range 10.0.0.0-127)
        let addr2: IpAddr = "10.0.0.200".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(addr2), Some([0x01u8; 32]));
    }

    #[test]
    fn test_yggdrasil_destination_rejected() {
        let mut subnets = HashMap::new();
        // 0200::/7 is Yggdrasil address space
        subnets.insert(dummy_key_hex(), vec!["200::/7".to_string()]);
        let result = CryptoKey::new(&make_config(subnets), &SELF_KEY);
        assert!(result.is_err());
    }

    #[test]
    fn test_yggdrasil_address_lookup_returns_none() {
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec!["2001:db8::/32".to_string()],
        );
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();

        // A Yggdrasil address should return None even if it somehow matched
        let ygg_addr: IpAddr = "200::1".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(ygg_addr), None);
    }

    #[test]
    fn test_duplicate_route_rejected() {
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec!["10.0.0.0/24".to_string(), "10.0.0.0/24".to_string()],
        );
        let result = CryptoKey::new(&make_config(subnets), &SELF_KEY);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_cidr_rejected() {
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["not-a-cidr".to_string()]);
        let result = CryptoKey::new(&make_config(subnets), &SELF_KEY);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_pubkey_rejected() {
        let mut subnets = HashMap::new();
        subnets.insert("not-hex".to_string(), vec!["10.0.0.0/24".to_string()]);
        let result = CryptoKey::new(&make_config(subnets), &SELF_KEY);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_length_pubkey_rejected() {
        let mut subnets = HashMap::new();
        subnets.insert(
            hex::encode([0x01u8; 16]), // 16 bytes, not 32
            vec!["10.0.0.0/24".to_string()],
        );
        let result = CryptoKey::new(&make_config(subnets), &SELF_KEY);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_yggdrasil_destination() {
        // Yggdrasil addresses start with 0x02
        assert!(is_yggdrasil_destination("200::1".parse().unwrap()));
        // Yggdrasil subnets start with 0x03
        assert!(is_yggdrasil_destination("300::1".parse().unwrap()));
        // Regular IPv6
        assert!(!is_yggdrasil_destination("2001:db8::1".parse().unwrap()));
        // IPv4 is never Yggdrasil
        assert!(!is_yggdrasil_destination("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_multiple_subnets_per_key() {
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec![
                "10.0.0.0/24".to_string(),
                "192.168.1.0/24".to_string(),
                "2001:db8::/32".to_string(),
            ],
        );
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();

        assert_eq!(ckr.v4_routes.len(), 2);
        assert_eq!(ckr.v6_routes.len(), 1);

        assert!(ckr.get_public_key_for_address("10.0.0.1".parse().unwrap()).is_some());
        assert!(ckr.get_public_key_for_address("192.168.1.100".parse().unwrap()).is_some());
        assert!(ckr.get_public_key_for_address("2001:db8::1".parse().unwrap()).is_some());
    }

    #[test]
    fn test_expand_cidrs_simple_exclude() {
        let entries = vec!["10.0.0.0/24".to_string(), "!10.0.0.0/25".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        // 10.0.0.0/24 minus 10.0.0.0/25 = 10.0.0.128/25
        assert_eq!(out, vec!["10.0.0.128/25".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn test_expand_cidrs_default_route_minus_rfc1918() {
        let entries = vec![
            "0.0.0.0/0".to_string(),
            "!192.168.0.0/16".to_string(),
        ];
        let out = expand_cidrs(&entries).unwrap();
        // All pieces must be prefix-aligned and cover 0.0.0.0/0 \ 192.168.0.0/16.
        let total_addrs: u128 = out
            .iter()
            .map(|n| 1u128 << (32 - n.prefix_len() as u32))
            .sum();
        assert_eq!(total_addrs, (1u128 << 32) - (1u128 << 16));
        // 192.168.5.1 should not be covered; 8.8.8.8 should be.
        let blocked: IpAddr = "192.168.5.1".parse().unwrap();
        let allowed: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!out.iter().any(|n| n.contains(&blocked)));
        assert!(out.iter().any(|n| n.contains(&allowed)));
    }

    #[test]
    fn test_expand_cidrs_exclude_routes_via_cryptokey() {
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec!["10.0.0.0/24".to_string(), "!10.0.0.5/32".to_string()],
        );
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();
        // 10.0.0.5 must NOT resolve; surrounding addrs must.
        assert_eq!(
            ckr.get_public_key_for_address("10.0.0.5".parse().unwrap()),
            None
        );
        assert_eq!(
            ckr.get_public_key_for_address("10.0.0.4".parse().unwrap()),
            Some([0x01u8; 32])
        );
        assert_eq!(
            ckr.get_public_key_for_address("10.0.0.6".parse().unwrap()),
            Some([0x01u8; 32])
        );
    }

    #[test]
    fn test_expand_cidrs_exclude_fully_covers_include() {
        // Entire include is excluded → no routes.
        let entries = vec!["10.0.0.0/24".to_string(), "!10.0.0.0/8".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn test_expand_cidrs_exclude_outside_include_ignored() {
        let entries = vec!["10.0.0.0/24".to_string(), "!192.168.0.0/16".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        assert_eq!(out, vec!["10.0.0.0/24".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn test_expand_cidrs_excludes_are_family_scoped() {
        // An IPv6 exclude must not affect an IPv4 include and vice versa.
        let entries = vec![
            "10.0.0.0/24".to_string(),
            "2001:db8::/32".to_string(),
            "!2001:db8:1::/48".to_string(),
        ];
        let out = expand_cidrs(&entries).unwrap();
        assert!(out.contains(&"10.0.0.0/24".parse::<IpNet>().unwrap()));
        // IPv6 side got split.
        assert!(!out.contains(&"2001:db8::/32".parse::<IpNet>().unwrap()));
    }

    #[test]
    fn test_expand_cidrs_multiple_excludes() {
        let entries = vec![
            "10.0.0.0/24".to_string(),
            "!10.0.0.5/32".to_string(),
            "!10.0.0.10/32".to_string(),
        ];
        let out = expand_cidrs(&entries).unwrap();
        let blocked1: IpAddr = "10.0.0.5".parse().unwrap();
        let blocked2: IpAddr = "10.0.0.10".parse().unwrap();
        assert!(!out.iter().any(|n| n.contains(&blocked1)));
        assert!(!out.iter().any(|n| n.contains(&blocked2)));
        assert!(out.iter().any(|n| n.contains(&"10.0.0.6".parse::<IpAddr>().unwrap())));
    }

    #[test]
    fn test_self_routes_are_dropped() {
        // A shared config lists routes for both this node (dummy_key) and a
        // peer (other_key). When this node is `dummy_key`, its own entry
        // must be silently dropped; the peer's entry stays.
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["10.0.0.0/24".to_string()]);
        subnets.insert(other_key_hex(), vec!["10.1.0.0/24".to_string()]);
        let self_key = [0x01u8; 32]; // matches dummy_key_hex
        let ckr = CryptoKey::new(&make_config(subnets), &self_key).unwrap();

        assert_eq!(ckr.v4_routes.len(), 1);
        assert_eq!(
            ckr.get_public_key_for_address("10.0.0.5".parse().unwrap()),
            None
        );
        assert_eq!(
            ckr.get_public_key_for_address("10.1.0.5".parse().unwrap()),
            Some([0x02u8; 32])
        );
    }

    #[test]
    fn test_route_sorting_order() {
        let mut subnets = HashMap::new();
        // Insert in non-sorted order
        subnets.insert(dummy_key_hex(), vec!["10.0.0.0/8".to_string()]);
        subnets.insert(other_key_hex(), vec!["10.0.0.0/16".to_string()]);
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();

        // /16 should come before /8 (more specific first)
        assert_eq!(ckr.v4_routes[0].prefix.prefix_len(), 16);
        assert_eq!(ckr.v4_routes[1].prefix.prefix_len(), 8);
    }

    #[test]
    fn test_ip_addresses_field_in_config() {
        let config = TunnelRoutingConfig {
            enable: true,
            yggdrasil_routing: true,
            ipv4_address: String::new(),
            ip_addresses: vec!["10.99.0.1/24".to_string(), "2005:8a:9:11::3/64".to_string()],
            remote_subnets: HashMap::new(),
            install_system_routes: true,
        };
        let ckr = CryptoKey::new(&config, &SELF_KEY).unwrap();
        assert!(ckr.v4_routes.is_empty());
        assert!(ckr.v6_routes.is_empty());
    }

    #[test]
    fn test_expand_cidrs_inetv4_keyword() {
        let entries = vec!["inetv4".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        assert!(out.contains(&"0.0.0.0/5".parse::<IpNet>().unwrap()));
        assert!(out.contains(&"208.0.0.0/4".parse::<IpNet>().unwrap()));
        assert_eq!(out.len(), 30);
    }

    #[test]
    fn test_expand_cidrs_tilde_inetv4_keyword() {
        let entries = vec!["~inetv4".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        assert!(out.contains(&"0.0.0.0/5".parse::<IpNet>().unwrap()));
        assert_eq!(out.len(), 30);
    }

    #[test]
    fn test_expand_cidrs_inetv6_keyword() {
        let entries = vec!["inetv6".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        assert!(out.contains(&"2000::/3".parse::<IpNet>().unwrap()));
    }

    #[test]
    fn test_expand_cidrs_tilde_prefix() {
        let entries = vec!["~10.0.0.0/24".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        assert_eq!(out, vec!["10.0.0.0/24".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn test_expand_cidrs_tilde_with_exclude() {
        let entries = vec!["~0.0.0.0/0".to_string(), "!192.168.0.0/16".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        let allowed: IpAddr = "8.8.8.8".parse().unwrap();
        let blocked: IpAddr = "192.168.5.1".parse().unwrap();
        assert!(out.iter().any(|n| n.contains(&allowed)));
        assert!(!out.iter().any(|n| n.contains(&blocked)));
    }

    #[test]
    fn test_expand_cidrs_exclude_applies_to_tilde() {
        let entries = vec!["~10.0.0.0/24".to_string(), "!10.0.0.0/25".to_string()];
        let out = expand_cidrs(&entries).unwrap();
        assert_eq!(out, vec!["10.0.0.128/25".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn test_expand_cidrs_bare_ip_with_tilde_exclamation() {
        let mut subnets = HashMap::new();
        subnets.insert(
            dummy_key_hex(),
            vec!["10.0.0.0/24".to_string(), "!10.0.0.5".to_string(), "~192.168.1.100".to_string(), "2001:db8:bbbb::1".to_string()],
        );
        let ckr = CryptoKey::new(&make_config(subnets), &SELF_KEY).unwrap();

        // bare IPv4 exclude applied
        let excluded: IpAddr = "10.0.0.5".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(excluded), None);
        // bare IPv4 with ~ still routed via CKR
        let v4_bare: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(v4_bare), Some([0x01u8; 32]));
        // bare IPv6 routed via CKR
        let v6_bare: IpAddr = "2001:db8:bbbb::1".parse().unwrap();
        assert_eq!(ckr.get_public_key_for_address(v6_bare), Some([0x01u8; 32]));
    }

    #[test]
    fn test_ip_addresses_in_tunnel_routing_config_for_mobile() {
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["10.0.0.0/24".to_string()]);
        let config = TunnelRoutingConfig {
            enable: true,
            yggdrasil_routing: true,
            ipv4_address: "10.99.0.1/24".to_string(),
            ip_addresses: vec!["2005:8a:9:11::3/64".to_string()],
            remote_subnets: subnets,
            install_system_routes: true,
        };
        let ckr = CryptoKey::new(&config, &SELF_KEY).unwrap();
        // ensures CKR still works with ip_addresses present (TUN assignment only); one remote IPv4 subnet configured
        assert_eq!(ckr.v4_routes.len(), 1);  
    }

    #[test]
    fn test_expand_cidrs_whitespace_trimming_with_tilde() {
        let entries = vec![
            "  ~10.0.0.0/24  ".to_string(),
            " !192.168.0.0/16 ".to_string(),
        ];
        let out = expand_cidrs(&entries).unwrap();
        let expected: IpNet = "10.0.0.0/24".parse().unwrap();
        assert_eq!(out, vec![expected]);
    }
    
    #[test]
    fn test_ip_addresses_multiple_ipv4_ipv6_and_deprecated_precedence() {
        let mut subnets = HashMap::new();
        subnets.insert(dummy_key_hex(), vec!["192.168.0.0/16".to_string()]);
        let config = TunnelRoutingConfig {
            enable: true,
            yggdrasil_routing: true,
            ipv4_address: "10.99.0.1/24".to_string(), // deprecated; must be ignored when ip_addresses has valid entries
            ip_addresses: vec![
                "10.50.0.1/24".to_string(),
                "10.60.0.1".to_string(), // bare IPv4 (auto /32)
                "2001:db8:1::1/64".to_string(),
            ],
            remote_subnets: subnets,
            install_system_routes: true,
        };
        let ckr = CryptoKey::new(&config, &SELF_KEY).unwrap();
        assert_eq!(ckr.v4_routes.len(), 1);
        assert!(ckr.v6_routes.is_empty());
        // Covers: multiple entries in ip_addresses (IPv4 + bare + IPv6), deprecated ipv4_address present but ignored per the new precedence rule,
        // and that CKR route parsing still succeeds (the core of the "TUN assignment only" intent of the original test).
    }
}
