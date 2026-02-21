//! Protocol message handling for remote queries.
//!
//! Implements the in-band protocol for debug_remote* and getNodeInfo commands.
//! Messages are sent as TYPE_SESSION_PROTO packets through the mesh.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ironwood::Addr;
use serde_json::Value as JsonValue;
use tokio::sync::{mpsc, oneshot, Mutex};

/// Protocol message types (second byte after TYPE_SESSION_PROTO).
#[allow(dead_code)]
const TYPE_PROTO_DUMMY: u8 = 0;
const TYPE_PROTO_NODEINFO_REQUEST: u8 = 1;
const TYPE_PROTO_NODEINFO_RESPONSE: u8 = 2;
const TYPE_PROTO_DEBUG: u8 = 255;

/// Debug message subtypes (third byte after TYPE_PROTO_DEBUG).
#[allow(dead_code)]
const TYPE_DEBUG_DUMMY: u8 = 0;
const TYPE_DEBUG_GET_SELF_REQUEST: u8 = 1;
const TYPE_DEBUG_GET_SELF_RESPONSE: u8 = 2;
const TYPE_DEBUG_GET_PEERS_REQUEST: u8 = 3;
const TYPE_DEBUG_GET_PEERS_RESPONSE: u8 = 4;
const TYPE_DEBUG_GET_TREE_REQUEST: u8 = 5;
const TYPE_DEBUG_GET_TREE_RESPONSE: u8 = 6;

/// Timeout for remote requests.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(6);

/// Cleanup interval for expired callbacks.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

/// Callback timeout (longer than request timeout for cleanup margin).
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(60);

/// Pending request callback.
type Callback = oneshot::Sender<Vec<u8>>;

/// Protocol handler for remote queries.
pub struct ProtoHandler {
    /// Callbacks for GetSelf requests (indexed by target key).
    self_callbacks: Arc<Mutex<HashMap<[u8; 32], (Callback, Instant)>>>,
    /// Callbacks for GetPeers requests.
    peers_callbacks: Arc<Mutex<HashMap<[u8; 32], (Callback, Instant)>>>,
    /// Callbacks for GetTree requests.
    tree_callbacks: Arc<Mutex<HashMap<[u8; 32], (Callback, Instant)>>>,
    /// Callbacks for NodeInfo requests.
    nodeinfo_callbacks: Arc<Mutex<HashMap<[u8; 32], (Callback, Instant)>>>,
    /// Channel to send outgoing protocol messages.
    proto_tx: mpsc::Sender<(Addr, Vec<u8>)>,
}

impl ProtoHandler {
    /// Create a new protocol handler.
    pub fn new(proto_tx: mpsc::Sender<(Addr, Vec<u8>)>) -> Arc<Self> {
        let handler = Arc::new(Self {
            self_callbacks: Arc::new(Mutex::new(HashMap::new())),
            peers_callbacks: Arc::new(Mutex::new(HashMap::new())),
            tree_callbacks: Arc::new(Mutex::new(HashMap::new())),
            nodeinfo_callbacks: Arc::new(Mutex::new(HashMap::new())),
            proto_tx,
        });

        // Spawn cleanup task
        let handler_clone = handler.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(CLEANUP_INTERVAL).await;
                handler_clone.cleanup_expired().await;
            }
        });

        handler
    }

    /// Handle incoming protocol message from remote node.
    pub async fn handle_proto_message(
        &self,
        from_key: [u8; 32],
        payload: &[u8],
        our_key: &[u8; 32],
        routing_entries: usize,
        get_peers_keys: impl Fn() -> Vec<[u8; 32]>,
        get_tree_keys: impl Fn() -> Vec<[u8; 32]>,
        nodeinfo_json: &str,
    ) -> Option<(Addr, Vec<u8>)> {
        if payload.is_empty() {
            return None;
        }

        let proto_type = payload[0];
        let rest = &payload[1..];

        match proto_type {
            TYPE_PROTO_DEBUG => {
                if rest.is_empty() {
                    return None;
                }
                let debug_type = rest[0];
                let data = &rest[1..];
                self.handle_debug_message(from_key, debug_type, data, our_key, routing_entries, get_peers_keys, get_tree_keys).await
            }
            TYPE_PROTO_NODEINFO_REQUEST => {
                self.handle_nodeinfo_request(from_key, nodeinfo_json).await
            }
            TYPE_PROTO_NODEINFO_RESPONSE => {
                self.handle_nodeinfo_response(from_key, rest).await;
                None
            }
            _ => None,
        }
    }

    /// Handle debug protocol message.
    async fn handle_debug_message(
        &self,
        from_key: [u8; 32],
        debug_type: u8,
        _data: &[u8],
        our_key: &[u8; 32],
        routing_entries: usize,
        get_peers_keys: impl Fn() -> Vec<[u8; 32]>,
        get_tree_keys: impl Fn() -> Vec<[u8; 32]>,
    ) -> Option<(Addr, Vec<u8>)> {
        match debug_type {
            TYPE_DEBUG_GET_SELF_REQUEST => {
                // Build GetSelf response
                let response = serde_json::json!({
                    "key": hex::encode(our_key),
                    "routing_entries": routing_entries.to_string(),
                });
                let json_bytes = serde_json::to_vec(&response).ok()?;

                let mut msg = Vec::with_capacity(3 + json_bytes.len());
                msg.push(TYPE_PROTO_DEBUG);
                msg.push(TYPE_DEBUG_GET_SELF_RESPONSE);
                msg.extend_from_slice(&json_bytes);

                Some((Addr(from_key), msg))
            }
            TYPE_DEBUG_GET_SELF_RESPONSE => {
                self.handle_get_self_response(from_key, _data).await;
                None
            }
            TYPE_DEBUG_GET_PEERS_REQUEST => {
                // Build GetPeers response (raw concatenated keys)
                let peer_keys = get_peers_keys();
                let mut msg = Vec::with_capacity(2 + peer_keys.len() * 32);
                msg.push(TYPE_PROTO_DEBUG);
                msg.push(TYPE_DEBUG_GET_PEERS_RESPONSE);
                for key in peer_keys {
                    msg.extend_from_slice(&key);
                }

                Some((Addr(from_key), msg))
            }
            TYPE_DEBUG_GET_PEERS_RESPONSE => {
                self.handle_get_peers_response(from_key, _data).await;
                None
            }
            TYPE_DEBUG_GET_TREE_REQUEST => {
                // Build GetTree response (raw concatenated keys)
                let tree_keys = get_tree_keys();
                let mut msg = Vec::with_capacity(2 + tree_keys.len() * 32);
                msg.push(TYPE_PROTO_DEBUG);
                msg.push(TYPE_DEBUG_GET_TREE_RESPONSE);
                for key in tree_keys {
                    msg.extend_from_slice(&key);
                }

                Some((Addr(from_key), msg))
            }
            TYPE_DEBUG_GET_TREE_RESPONSE => {
                self.handle_get_tree_response(from_key, _data).await;
                None
            }
            _ => None,
        }
    }

    /// Handle GetSelf response.
    async fn handle_get_self_response(&self, from_key: [u8; 32], data: &[u8]) {
        let mut callbacks = self.self_callbacks.lock().await;
        if let Some((callback, _)) = callbacks.remove(&from_key) {
            let _ = callback.send(data.to_vec());
        }
    }

    /// Handle GetPeers response.
    async fn handle_get_peers_response(&self, from_key: [u8; 32], data: &[u8]) {
        let mut callbacks = self.peers_callbacks.lock().await;
        if let Some((callback, _)) = callbacks.remove(&from_key) {
            let _ = callback.send(data.to_vec());
        }
    }

    /// Handle GetTree response.
    async fn handle_get_tree_response(&self, from_key: [u8; 32], data: &[u8]) {
        let mut callbacks = self.tree_callbacks.lock().await;
        if let Some((callback, _)) = callbacks.remove(&from_key) {
            let _ = callback.send(data.to_vec());
        }
    }

    /// Handle NodeInfo request.
    async fn handle_nodeinfo_request(&self, from_key: [u8; 32], nodeinfo_json: &str) -> Option<(Addr, Vec<u8>)> {
        let mut msg = Vec::with_capacity(1 + nodeinfo_json.len());
        msg.push(TYPE_PROTO_NODEINFO_RESPONSE);
        msg.extend_from_slice(nodeinfo_json.as_bytes());
        Some((Addr(from_key), msg))
    }

    /// Handle NodeInfo response.
    async fn handle_nodeinfo_response(&self, from_key: [u8; 32], data: &[u8]) {
        let mut callbacks = self.nodeinfo_callbacks.lock().await;
        if let Some((callback, _)) = callbacks.remove(&from_key) {
            let _ = callback.send(data.to_vec());
        }
    }

    /// Send GetSelf request to remote node.
    pub async fn send_get_self_request(&self, target_key: [u8; 32]) -> Result<JsonValue, String> {
        let (tx, rx) = oneshot::channel();

        {
            let mut callbacks = self.self_callbacks.lock().await;
            callbacks.insert(target_key, (tx, Instant::now()));
        }

        // Send request
        let msg = vec![TYPE_PROTO_DEBUG, TYPE_DEBUG_GET_SELF_REQUEST];
        self.proto_tx.send((Addr(target_key), msg)).await
            .map_err(|_| "Failed to send request")?;

        // Wait for response with timeout
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(data)) => {
                serde_json::from_slice(&data)
                    .map_err(|e| format!("Invalid JSON response: {}", e))
            }
            Ok(Err(_)) => Err("Request cancelled".to_string()),
            Err(_) => Err("Request timeout".to_string()),
        }
    }

    /// Send GetPeers request to remote node.
    pub async fn send_get_peers_request(&self, target_key: [u8; 32]) -> Result<Vec<[u8; 32]>, String> {
        let (tx, rx) = oneshot::channel();

        {
            let mut callbacks = self.peers_callbacks.lock().await;
            callbacks.insert(target_key, (tx, Instant::now()));
        }

        // Send request
        let msg = vec![TYPE_PROTO_DEBUG, TYPE_DEBUG_GET_PEERS_REQUEST];
        self.proto_tx.send((Addr(target_key), msg)).await
            .map_err(|_| "Failed to send request")?;

        // Wait for response with timeout
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(data)) => {
                // Parse raw key bytes (32 bytes each)
                let mut keys = Vec::new();
                for chunk in data.chunks_exact(32) {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(chunk);
                    keys.push(key);
                }
                Ok(keys)
            }
            Ok(Err(_)) => Err("Request cancelled".to_string()),
            Err(_) => Err("Request timeout".to_string()),
        }
    }

    /// Send GetTree request to remote node.
    pub async fn send_get_tree_request(&self, target_key: [u8; 32]) -> Result<Vec<[u8; 32]>, String> {
        let (tx, rx) = oneshot::channel();

        {
            let mut callbacks = self.tree_callbacks.lock().await;
            callbacks.insert(target_key, (tx, Instant::now()));
        }

        // Send request
        let msg = vec![TYPE_PROTO_DEBUG, TYPE_DEBUG_GET_TREE_REQUEST];
        self.proto_tx.send((Addr(target_key), msg)).await
            .map_err(|_| "Failed to send request")?;

        // Wait for response with timeout
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(data)) => {
                // Parse raw key bytes (32 bytes each)
                let mut keys = Vec::new();
                for chunk in data.chunks_exact(32) {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(chunk);
                    keys.push(key);
                }
                Ok(keys)
            }
            Ok(Err(_)) => Err("Request cancelled".to_string()),
            Err(_) => Err("Request timeout".to_string()),
        }
    }

    /// Send NodeInfo request to remote node.
    pub async fn send_nodeinfo_request(&self, target_key: [u8; 32]) -> Result<JsonValue, String> {
        let (tx, rx) = oneshot::channel();

        {
            let mut callbacks = self.nodeinfo_callbacks.lock().await;
            callbacks.insert(target_key, (tx, Instant::now()));
        }

        // Send request
        let msg = vec![TYPE_PROTO_NODEINFO_REQUEST];
        self.proto_tx.send((Addr(target_key), msg)).await
            .map_err(|_| "Failed to send request")?;

        // Wait for response with timeout
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(data)) => {
                serde_json::from_slice(&data)
                    .map_err(|e| format!("Invalid JSON response: {}", e))
            }
            Ok(Err(_)) => Err("Request cancelled".to_string()),
            Err(_) => Err("Request timeout".to_string()),
        }
    }

    /// Clean up expired callbacks.
    async fn cleanup_expired(&self) {
        let now = Instant::now();

        self.self_callbacks.lock().await.retain(|_, (_, created)| {
            now.duration_since(*created) < CALLBACK_TIMEOUT
        });

        self.peers_callbacks.lock().await.retain(|_, (_, created)| {
            now.duration_since(*created) < CALLBACK_TIMEOUT
        });

        self.tree_callbacks.lock().await.retain(|_, (_, created)| {
            now.duration_since(*created) < CALLBACK_TIMEOUT
        });

        self.nodeinfo_callbacks.lock().await.retain(|_, (_, created)| {
            now.duration_since(*created) < CALLBACK_TIMEOUT
        });
    }
}
