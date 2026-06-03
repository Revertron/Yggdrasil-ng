#[cfg(feature = "ckr")]
use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

/// Per-interface multicast discovery configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MulticastInterfaceConfig {
    /// Glob pattern to match network interface names.
    /// Accepts the legacy name `regex` for backwards compatibility
    /// (the value has always been interpreted as a glob, despite the old name).
    #[serde(default = "default_multicast_filter", alias = "regex")]
    pub filter: String,
    /// Whether to send beacons on matching interfaces.
    #[serde(default = "default_true")]
    pub beacon: bool,
    /// Whether to listen for beacons on matching interfaces.
    #[serde(default = "default_true")]
    pub listen: bool,
    /// TLS listener port for this interface (0 = auto-assign).
    #[serde(default)]
    pub port: u16,
    /// Connection priority for peers discovered on this interface.
    #[serde(default)]
    pub priority: u8,
    /// Password for authentication (must match on both sides).
    #[serde(default)]
    pub password: String,
}

fn default_multicast_filter() -> String {
    "*".to_string()
}

fn default_true() -> bool {
    true
}

fn default_multicast_interfaces() -> Vec<MulticastInterfaceConfig> {
    vec![MulticastInterfaceConfig {
        filter: "*".to_string(),
        beacon: true,
        listen: true,
        port: 0,
        priority: 0,
        password: String::new(),
    }]
}

/// Yggdrasil node configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Ed25519 private key as hex string (128 hex chars = 64 bytes).
    #[serde(default)]
    pub private_key: String,

    /// Peer URIs to connect to, e.g. `["tcp://host:port"]`.
    #[serde(default)]
    pub peers: Vec<String>,

    /// Listen addresses, e.g. `["tcp://[::]:1234"]`.
    #[serde(default)]
    pub listen: Vec<String>,

    /// Admin socket listen address, e.g. `"tcp://localhost:9001"`.
    #[serde(default = "default_admin_listen")]
    pub admin_listen: String,

    /// TUN interface name. "auto" for auto-name, "none" to disable.
    #[serde(default = "default_if_name")]
    pub if_name: String,

    /// TUN MTU (default 65535).
    #[serde(default = "default_mtu")]
    pub if_mtu: u64,

    /// Custom node info (arbitrary TOML value).
    #[serde(default = "default_node_info")]
    pub node_info: toml::Value,

    /// If true, don't expose node info to other nodes.
    #[serde(default)]
    pub node_info_privacy: bool,

    /// If non-empty, only allow peering with these public keys (hex).
    #[serde(default)]
    pub allowed_public_keys: Vec<String>,

    /// Multicast interface configurations for LAN peer discovery.
    #[serde(default = "default_multicast_interfaces")]
    pub multicast_interfaces: Vec<MulticastInterfaceConfig>,

    /// Tunnel routing (CKR) configuration.
    #[cfg(feature = "ckr")]
    #[serde(default)]
    pub tunnel_routing: TunnelRoutingConfig,

    /// Built-in stateful firewall configuration.
    #[serde(default)]
    pub firewall: FirewallConfig,

    /// Closed-network group password. When non-empty, this node only completes
    /// encrypted sessions with peers that share the same password (folded into
    /// the ironwood handshake signature). Empty = open network. This is separate
    /// from the per-peer/per-multicast `password`, which gates direct peering.
    #[serde(default)]
    pub group_password: String,
}

/// Built-in stateful firewall configuration. Default-off; when enabled,
/// inbound mesh traffic is dropped unless it matches an outbound flow
/// (stateful return), comes from `open_all_for`, or hits an open port.
/// Outbound is always allowed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirewallConfig {
    /// Master switch. False = no filtering (preserves legacy behavior).
    #[serde(default)]
    pub enable: bool,

    /// Inbound TCP destination ports that are open to the mesh.
    #[serde(default)]
    pub open_tcp: Vec<u16>,

    /// Inbound UDP destination ports that are open to the mesh.
    #[serde(default)]
    pub open_udp: Vec<u16>,

    /// IPv6 source CIDRs (mesh addresses) for which all inbound is allowed.
    /// Use a /128 to whitelist a single peer; a /64 whitelists their subnet.
    #[serde(default)]
    pub open_all_for: Vec<String>,

    /// Allow inbound ICMPv6 Echo Request (ping). Default: true.
    #[serde(default = "default_true")]
    pub allow_icmp_echo: bool,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enable: false,
            open_tcp: Vec::new(),
            open_udp: Vec::new(),
            open_all_for: Vec::new(),
            allow_icmp_echo: true,
        }
    }
}

/// Crypto-Key Routing (CKR) tunnel configuration.
/// Maps IP subnets to Yggdrasil node public keys for VPN tunneling.
#[cfg(feature = "ckr")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelRoutingConfig {
    /// Enable or disable tunnel routing.
    #[serde(default)]
    pub enable: bool,

    /// Also route standard Yggdrasil 0200::/7 traffic (default: true).
    #[serde(default = "default_true")]
    pub yggdrasil_routing: bool,

    /// IPv4 address to assign to the TUN interface, in CIDR notation.
    /// Required for exit-node / VPN scenarios where IPv4 traffic is tunneled.
    /// Example: "10.99.0.1/24"
    /// DEPRECATED: kept for backward compatibility; use `ip_addresses` 
    /// for any number of IPv4/IPv6 addresses.
    #[serde(default)]
    pub ipv4_address: String,

    /// Additional IP addresses (IPv4 or IPv6, in CIDR notation; 
    /// prefix optional — IPv4 defaults to /32, IPv6 to /128) to assign
    /// to the TUN interface. Supports any number of addresses. New preferred
    /// option for exit-node / VPN to replace deprecated ‘ipv4_address’.
    /// Example: ["10.99.0.1/24", "2005:8a:9:11::3/64"]
    #[serde(default)]
    pub ip_addresses: Vec<String>,

    /// Remote subnets: maps hex public key -> list of CIDRs (bare IP addresses 
    /// without prefix are supported and treated as /32 for IPv4 or /128 for IPv6; 
    /// this also applies to addresses beginning with "~" and "!").
    /// Example: { "aabbcc...01": ["10.0.0.0/24", "192.168.1.0/24"] }
    /// Supported syntax in the lists (when built with --features ckr):
    /// - "CIDR" (or bare IP) → CKR + system route
    /// - "~CIDR" (or ~bare IP) → CKR tunnel only (no system route)
    /// - "!CIDR" (or !bare IP) → exclude from CKR (applies to both normal and ‘~’ entries)
    /// - "inetv4" / "~inetv4" → full public IPv4 internet (excl. internals) +/– routes
    /// - "inetv6" / "~inetv6" → 2000::/3 +/– routes
    #[serde(default)]
    pub remote_subnets: HashMap<String, Vec<String>>,

    /// Install OS routes via the system route manager. Disable on platforms
    /// that own routing themselves (e.g. Android VpnService).
    #[serde(default = "default_true")]
    pub install_system_routes: bool,
}

#[cfg(feature = "ckr")]
impl Default for TunnelRoutingConfig {
    fn default() -> Self {
        Self {
            enable: false,
            yggdrasil_routing: true,
            ipv4_address: String::new(),
            ip_addresses: Vec::new(),
            remote_subnets: HashMap::new(),
            install_system_routes: true,
        }
    }
}
fn default_admin_listen() -> String {
    "tcp://localhost:9001".to_string()
}

fn default_if_name() -> String {
    "auto".to_string()
}

fn default_mtu() -> u64 {
    65535
}

fn default_node_info() -> toml::Value {
    toml::Value::Table(toml::map::Map::new())
}

impl Default for Config {
    fn default() -> Self {
        Self {
            private_key: String::new(),
            peers: Vec::new(),
            listen: vec!["tcp://[::]:0".to_string()],
            admin_listen: "tcp://localhost:9001".to_string(),
            if_name: default_if_name(),
            if_mtu: default_mtu(),
            node_info: toml::Value::Table(toml::map::Map::new()),
            node_info_privacy: false,
            allowed_public_keys: Vec::new(),
            multicast_interfaces: default_multicast_interfaces(),
            #[cfg(feature = "ckr")]
            tunnel_routing: TunnelRoutingConfig::default(),
            firewall: FirewallConfig::default(),
            group_password: String::new(),
        }
    }
}

const CONFIG_TEMPLATE: &str = include_str!("config_template.toml");

impl Config {
    /// Generate a new config with a fresh random keypair.
    pub fn generate() -> Self {
        let text = Self::generate_config_text();
        toml::from_str(&text).expect("config template must be valid TOML")
    }

    /// Generate a commented config file as a TOML string with a fresh keypair.
    pub fn generate_config_text() -> String {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let key_hex = hex::encode(signing_key.to_keypair_bytes());
        CONFIG_TEMPLATE.replace("{{PRIVATE_KEY}}", &key_hex)
    }

    /// Read a TOML config string, add any fields missing from the user's input
    /// (with their template comments), and return the merged document.
    /// Preserves user values, formatting, comments, and unknown keys.
    pub fn normalize_config_text(user_toml: &str) -> Result<String, NormalizeError> {
        use toml_edit::DocumentMut;

        let mut user_doc: DocumentMut = user_toml.parse().map_err(NormalizeError::ParseUser)?;
        // Strip the {{PRIVATE_KEY}} placeholder so absent user keys stay empty
        // (genconf is the path that mints keys; normalize must be deterministic).
        let template_text = CONFIG_TEMPLATE.replace("{{PRIVATE_KEY}}", "");
        let template_doc: DocumentMut =
            template_text.parse().map_err(NormalizeError::ParseTemplate)?;

        merge_missing(user_doc.as_table_mut(), template_doc.as_table());
        Ok(user_doc.to_string())
    }
}

/// Errors returned by [`Config::normalize_config_text`].
#[derive(Debug, thiserror::Error)]
pub enum NormalizeError {
    #[error("invalid input TOML: {0}")]
    ParseUser(toml_edit::TomlError),
    #[error("internal: template TOML is invalid: {0}")]
    ParseTemplate(toml_edit::TomlError),
}

/// Walk `from` in declaration order; for each key absent from `into`, splice
/// in a clone of the template entry (with its leading comment decor). For
/// keys present on both sides as tables, recurse. Never overwrite the user's
/// values, never delete unknown keys.
fn merge_missing(into: &mut toml_edit::Table, from: &toml_edit::Table) {
    for (key, template_item) in from.iter() {
        match into.get_mut(key) {
            None => {
                into.insert(key, template_item.clone());
                // Preserve the template's leading comment decor on the key.
                if let Some(template_key) = from.key(key) {
                    if let Some(mut user_key) = into.key_mut(key) {
                        *user_key.leaf_decor_mut() = template_key.leaf_decor().clone();
                    }
                }
            }
            Some(user_item) => {
                if let (Some(user_tbl), Some(template_tbl)) =
                    (user_item.as_table_mut(), template_item.as_table())
                {
                    merge_missing(user_tbl, template_tbl);
                }
                // Arrays-of-tables and scalars: leave the user's choice alone.
            }
        }
    }
}

impl Config {

    /// Parse the private key from hex.
    pub fn signing_key(&self) -> Result<SigningKey, String> {
        if self.private_key.is_empty() {
            return Err("no private key configured".to_string());
        }
        let bytes = hex::decode(&self.private_key)
            .map_err(|e| format!("invalid private key hex: {}", e))?;
        if bytes.len() != 64 {
            return Err(format!(
                "private key should be 64 bytes, got {}",
                bytes.len()
            ));
        }
        let key_bytes: [u8; 64] = bytes.try_into().unwrap();
        SigningKey::from_keypair_bytes(&key_bytes)
            .map_err(|e| format!("invalid ed25519 key: {}", e))
    }

    /// Get the set of allowed public keys (parsed from hex).
    pub fn allowed_keys(&self) -> Vec<[u8; 32]> {
        self.allowed_public_keys
            .iter()
            .filter_map(|s| {
                let bytes = hex::decode(s).ok()?;
                if bytes.len() != 32 {
                    return None;
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            })
            .collect()
    }

    /// Get node info as JSON string (for protocol responses).
    /// Automatically adds build info if node_info_privacy is false.
    pub fn node_info_json(&self) -> String {
        // Start with user-provided config
        let mut json_value = toml_to_json(&self.node_info);

        // Ensure we have an object to work with
        let map = match json_value {
            serde_json::Value::Object(ref mut m) => m,
            _ => {
                // If user config is not an object, create empty one
                json_value = serde_json::Value::Object(serde_json::Map::new());
                if let serde_json::Value::Object(ref mut m) = json_value {
                    m
                } else {
                    unreachable!()
                }
            }
        };

        // If privacy is disabled, add build info automatically
        if !self.node_info_privacy {
            map.insert("buildname".to_string(), serde_json::Value::String(env!("CARGO_PKG_NAME").to_string()));
            map.insert("buildversion".to_string(), serde_json::Value::String(env!("CARGO_PKG_VERSION").to_string()));
            map.insert("buildplatform".to_string(), serde_json::Value::String(std::env::consts::OS.to_string()));
            map.insert("buildarch".to_string(), serde_json::Value::String(std::env::consts::ARCH.to_string()));
        }

        serde_json::to_string(&json_value).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Convert TOML value to JSON value.
fn toml_to_json(toml_val: &toml::Value) -> serde_json::Value {
    match toml_val {
        toml::Value::String(s) => serde_json::Value::String(s.clone()),
        toml::Value::Integer(i) => serde_json::Value::Number((*i).into()),
        toml::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        toml::Value::Boolean(b) => serde_json::Value::Bool(*b),
        toml::Value::Datetime(dt) => serde_json::Value::String(dt.to_string()),
        toml::Value::Array(arr) => {
            let json_arr: Vec<serde_json::Value> = arr.iter().map(toml_to_json).collect();
            serde_json::Value::Array(json_arr)
        }
        toml::Value::Table(tbl) => {
            let json_obj: serde_json::Map<String, serde_json::Value> = tbl
                .iter()
                .map(|(k, v)| (k.clone(), toml_to_json(v)))
                .collect();
            serde_json::Value::Object(json_obj)
        }
    }
}

#[cfg(test)]
mod normalize_tests {
    use super::*;

    #[test]
    fn round_trip_full_config_is_stable() {
        let generated = Config::generate_config_text();
        let normalized = Config::normalize_config_text(&generated).unwrap();
        // After re-running normalize on the output, no further changes should appear.
        let twice = Config::normalize_config_text(&normalized).unwrap();
        assert_eq!(normalized, twice, "normalize must be idempotent");
        // The generated config already deserializes — the normalized one must too.
        toml::from_str::<Config>(&normalized).expect("normalized output is valid Config TOML");
    }

    #[test]
    fn user_inline_comment_is_preserved() {
        let input = "if_mtu = 1280  # custom for my LTE link\n";
        let out = Config::normalize_config_text(input).unwrap();
        assert!(
            out.contains("# custom for my LTE link"),
            "user comment dropped:\n{out}"
        );
        assert!(out.contains("1280"), "user value dropped:\n{out}");
    }

    #[test]
    fn missing_firewall_section_is_added() {
        let input = "private_key = \"\"\n";
        let out = Config::normalize_config_text(input).unwrap();
        assert!(out.contains("[firewall]"), "[firewall] not added:\n{out}");
        assert!(
            out.contains("enable = false"),
            "firewall defaults missing:\n{out}"
        );
        assert!(out.contains("open_tcp"), "open_tcp missing:\n{out}");
    }

    #[test]
    fn user_value_is_not_overwritten() {
        let input = "if_mtu = 1280\n";
        let out = Config::normalize_config_text(input).unwrap();
        assert!(out.contains("if_mtu = 1280"), "if_mtu rewritten:\n{out}");
        assert!(
            !out.contains("if_mtu = 65535"),
            "template default leaked over user value:\n{out}"
        );
    }

    #[test]
    fn empty_array_with_user_comment_is_preserved() {
        let input = "peers = []  # I'll add some later\n";
        let out = Config::normalize_config_text(input).unwrap();
        assert!(
            out.contains("# I'll add some later"),
            "user array comment dropped:\n{out}"
        );
        assert!(out.contains("peers = []"), "peers rewritten:\n{out}");
    }

    #[test]
    fn unknown_user_keys_are_kept() {
        let input = "experimental_thing = \"x\"\n";
        let out = Config::normalize_config_text(input).unwrap();
        assert!(
            out.contains("experimental_thing = \"x\""),
            "unknown key dropped:\n{out}"
        );
    }

    #[test]
    fn custom_node_info_table_passes_through() {
        let input = "[node_info]\nname = \"foo\"  # set by ansible\n";
        let out = Config::normalize_config_text(input).unwrap();
        assert!(out.contains("[node_info]"));
        assert!(out.contains("name = \"foo\""));
        assert!(out.contains("# set by ansible"));
    }

    #[test]
    fn invalid_toml_returns_parse_user_error() {
        let bad = "this is = = not toml\n";
        let err = Config::normalize_config_text(bad).unwrap_err();
        match err {
            NormalizeError::ParseUser(_) => {}
            other => panic!("expected ParseUser, got {other:?}"),
        }
    }

    #[test]
    fn empty_input_yields_template_minus_private_key() {
        let out = Config::normalize_config_text("").unwrap();
        // Should have all the schema scaffolding…
        assert!(out.contains("[firewall]"));
        assert!(out.contains("if_name"));
        // …but no fresh keypair (genconf's job).
        assert!(
            out.contains("private_key = \"\""),
            "normalize must not mint a key:\n{out}"
        );
    }
}
