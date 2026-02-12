use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

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
    #[serde(default)]
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
}
