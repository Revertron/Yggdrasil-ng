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
