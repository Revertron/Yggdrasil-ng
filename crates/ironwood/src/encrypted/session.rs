//! Session state machine for encrypted communication.
//!
//! Implements Init/Ack/Traffic handshake with 3-tier key ratcheting
//! and forward secrecy using XSalsa20-Poly1305 (via RustCrypto's `crypto_box` crate).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crypto_box::SalsaBox;

use crate::crypto::{Crypto, PublicKey};
use crate::types::Error;
use crate::wire;

use super::crypto::{
    box_open, box_open_precomputed, box_seal, box_seal_precomputed,
    ed25519_public_to_curve25519, make_salsa_box, new_box_keys, CurvePrivateKey, CurvePublicKey,
    BOX_OVERHEAD,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Minimum traffic overhead: type(1) + varint(1) + varint(1) + varint(1) + box_overhead(16) + nextPub(32)
const SESSION_TRAFFIC_OVERHEAD_MIN: usize = 1 + 1 + 1 + 1 + BOX_OVERHEAD + 32;

/// Maximum traffic overhead: type(1) + varint(9) + varint(9) + varint(9) + box_overhead(16) + nextPub(32)
pub(crate) const SESSION_TRAFFIC_OVERHEAD: u64 = (SESSION_TRAFFIC_OVERHEAD_MIN + 9 + 9 + 9) as u64;

/// Init message size: type(1) + ephemeral_pub(32) + encrypted(sig(64) + current(32) + next(32) + keySeq(8) + seq(8) + overhead(16))
const SESSION_INIT_SIZE: usize = 1 + 32 + BOX_OVERHEAD + 64 + 32 + 32 + 8 + 8;

/// Session message types.
const SESSION_TYPE_DUMMY: u8 = 0;
const SESSION_TYPE_INIT: u8 = 1;
const SESSION_TYPE_ACK: u8 = 2;
const SESSION_TYPE_TRAFFIC: u8 = 3;

// ---------------------------------------------------------------------------
// SessionInit
// ---------------------------------------------------------------------------

/// Handshake init/ack message content.
#[derive(Clone, Debug)]
pub(crate) struct SessionInit {
    pub current: CurvePublicKey,
    pub next: CurvePublicKey,
    pub key_seq: u64,
    pub seq: u64,
}

impl SessionInit {
    pub fn new(current: &CurvePublicKey, next: &CurvePublicKey, key_seq: u64) -> Self {
        let seq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            current: *current,
            next: *next,
            key_seq,
            seq,
        }
    }

    /// Encrypt an init message from our Ed25519 key to the recipient's Ed25519 key.
    ///
    /// Wire format: [type(1)][ephemeral_pub(32)][encrypted_payload]
    /// Encrypted payload: [sig(64)][current(32)][next(32)][keySeq(8)][seq(8)]
    pub fn encrypt(
        &self,
        our_ed_priv: &ed25519_dalek::SigningKey,
        to_ed_pub: &PublicKey,
        msg_type: u8,
    ) -> Result<Vec<u8>, Error> {
        // Generate ephemeral Curve25519 keypair
        let (from_pub, from_priv) = new_box_keys();

        // Convert recipient's Ed25519 public key to Curve25519
        let to_box = ed25519_public_to_curve25519(to_ed_pub).map_err(|_| Error::BadKey)?;

        // Build signature bytes: [fromPub][current][next][keySeq(8)][seq(8)]
        let mut sig_bytes = Vec::with_capacity(32 + 32 + 32 + 8 + 8);
        sig_bytes.extend_from_slice(&from_pub);
        sig_bytes.extend_from_slice(&self.current);
        sig_bytes.extend_from_slice(&self.next);
        sig_bytes.extend_from_slice(&self.key_seq.to_be_bytes());
        sig_bytes.extend_from_slice(&self.seq.to_be_bytes());

        // Sign with our Ed25519 key
        let sig = Crypto::sign_with_key(our_ed_priv, &sig_bytes);

        // Build payload to encrypt: [sig(64)][current(32)][next(32)][keySeq(8)][seq(8)]
        let mut payload = Vec::with_capacity(64 + 32 + 32 + 8 + 8);
        payload.extend_from_slice(&sig);
        payload.extend_from_slice(&self.current);
        payload.extend_from_slice(&self.next);
        payload.extend_from_slice(&self.key_seq.to_be_bytes());
        payload.extend_from_slice(&self.seq.to_be_bytes());

        // Encrypt with ephemeral DH
        let ciphertext = box_seal(&payload, 0, &to_box, &from_priv).map_err(|_| Error::Encode)?;

        // Assemble: [type][fromPub][ciphertext]
        let mut data = Vec::with_capacity(1 + 32 + ciphertext.len());
        data.push(msg_type);
        data.extend_from_slice(&from_pub);
        data.extend_from_slice(&ciphertext);

        debug_assert_eq!(data.len(), SESSION_INIT_SIZE);
        Ok(data)
    }

    /// Decrypt an init/ack message.
    pub fn decrypt(
        data: &[u8],
        our_curve_priv: &CurvePrivateKey,
        from_ed_pub: &PublicKey,
    ) -> Result<Self, Error> {
        if data.len() != SESSION_INIT_SIZE {
            return Err(Error::Decode);
        }

        // Extract ephemeral public key
        let mut from_box = [0u8; 32];
        from_box.copy_from_slice(&data[1..33]);

        // Decrypt payload
        let ciphertext = &data[33..];
        let payload = box_open(ciphertext, 0, &from_box, our_curve_priv)
            .map_err(|_| Error::Decode)?;

        if payload.len() != 64 + 32 + 32 + 8 + 8 {
            return Err(Error::Decode);
        }

        // Parse payload
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&payload[0..64]);
        let mut current = [0u8; 32];
        current.copy_from_slice(&payload[64..96]);
        let mut next = [0u8; 32];
        next.copy_from_slice(&payload[96..128]);
        let key_seq = u64::from_be_bytes(payload[128..136].try_into().unwrap());
        let seq = u64::from_be_bytes(payload[136..144].try_into().unwrap());

        // Verify signature: sigBytes = [fromBox][current][next][keySeq][seq]
        let mut sig_bytes = Vec::with_capacity(32 + 32 + 32 + 8 + 8);
        sig_bytes.extend_from_slice(&from_box);
        sig_bytes.extend_from_slice(&current);
        sig_bytes.extend_from_slice(&next);
        sig_bytes.extend_from_slice(&key_seq.to_be_bytes());
        sig_bytes.extend_from_slice(&seq.to_be_bytes());

        if !Crypto::verify(from_ed_pub, &sig_bytes, &sig) {
            return Err(Error::BadMessage);
        }

        Ok(Self {
            current,
            next,
            key_seq,
            seq,
        })
    }
}

// ---------------------------------------------------------------------------
// SessionInfo — active session with key ratcheting state
// ---------------------------------------------------------------------------

/// An active encrypted session with a remote peer.
pub(crate) struct SessionInfo {
    // Remote state
    pub seq: u64,
    pub remote_key_seq: u64,
    pub current: CurvePublicKey, // remote's current key
    pub next: CurvePublicKey,    // remote's next key

    // Local key material (3-tier ratcheting)
    pub local_key_seq: u64,
    pub recv_priv: CurvePrivateKey,
    pub recv_pub: CurvePublicKey,
    pub recv_shared: SalsaBox,
    pub recv_nonce: u64,

    pub send_priv: CurvePrivateKey,
    pub send_pub: CurvePublicKey,
    pub send_shared: SalsaBox,
    pub send_nonce: u64,

    pub next_priv: CurvePrivateKey,
    pub next_pub: CurvePublicKey,

    // Forward secrecy preparation
    pub next_send_shared: SalsaBox,
    pub next_send_nonce: u64,
    pub next_recv_shared: SalsaBox,
    pub next_recv_nonce: u64,

    // Timing
    pub since: Instant,
    pub rotated: Option<Instant>,
    pub last_activity: Instant,

    // Stats
    pub rx: u64,
    pub tx: u64,
}

impl SessionInfo {
    /// Create a new session with the given remote keys.
    pub fn new(
        current: CurvePublicKey,
        next: CurvePublicKey,
        seq: u64,
    ) -> Self {
        let (recv_pub, recv_priv) = new_box_keys();
        let (send_pub, send_priv) = new_box_keys();
        let (next_pub, next_priv) = new_box_keys();

        let recv_shared = make_salsa_box(&current, &recv_priv);
        let send_shared = make_salsa_box(&current, &send_priv);
        let next_send_shared = make_salsa_box(&next, &send_priv);
        let next_recv_shared = make_salsa_box(&next, &recv_priv);

        Self {
            seq: seq.wrapping_sub(1), // so first update works
            remote_key_seq: 0,
            current,
            next,
            local_key_seq: 0,
            recv_priv,
            recv_pub,
            recv_shared,
            recv_nonce: 0,
            send_priv,
            send_pub,
            send_shared,
            send_nonce: 0,
            next_priv,
            next_pub,
            next_send_shared,
            next_send_nonce: 0,
            next_recv_shared,
            next_recv_nonce: 0,
            since: Instant::now(),
            rotated: None,
            last_activity: Instant::now(),
            rx: 0,
            tx: 0,
        }
    }

    /// Recompute all shared secrets after key changes.
    fn fix_shared(&mut self, recv_nonce: u64, send_nonce: u64) {
        self.recv_shared = make_salsa_box(&self.current, &self.recv_priv);
        self.send_shared = make_salsa_box(&self.current, &self.send_priv);
        self.next_send_shared = make_salsa_box(&self.next, &self.send_priv);
        self.next_recv_shared = make_salsa_box(&self.next, &self.recv_priv);
        self.next_send_nonce = 0;
        self.next_recv_nonce = 0;
        self.recv_nonce = recv_nonce;
        self.send_nonce = send_nonce;
    }

    /// Handle an init/ack update: ratchet keys forward.
    pub fn handle_update(&mut self, init: &SessionInit) {
        self.current = init.current;
        self.next = init.next;
        self.seq = init.seq;
        self.remote_key_seq = init.key_seq;

        // Ratchet: recv = send, send = next, new next
        self.recv_pub = self.send_pub;
        self.recv_priv = self.send_priv;
        self.send_pub = self.next_pub;
        self.send_priv = self.next_priv;
        let (new_next_pub, new_next_priv) = new_box_keys();
        self.next_pub = new_next_pub;
        self.next_priv = new_next_priv;
        self.local_key_seq += 1;

        // Preserve send nonce
        self.fix_shared(0, self.send_nonce);
        self.last_activity = Instant::now();
    }

    /// Encrypt and produce a traffic message.
    ///
    /// Wire format: [type(1)][varint(localKeySeq)][varint(remoteKeySeq)][varint(sendNonce)][encrypted([nextPub(32)][msg])]
    pub fn do_send(&mut self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        self.send_nonce += 1;

        if self.send_nonce == 0 {
            // Nonce overflow: ratchet
            self.recv_pub = self.send_pub;
            self.recv_priv = self.send_priv;
            self.send_pub = self.next_pub;
            self.send_priv = self.next_priv;
            let (new_next_pub, new_next_priv) = new_box_keys();
            self.next_pub = new_next_pub;
            self.next_priv = new_next_priv;
            self.local_key_seq += 1;
            self.fix_shared(0, 0);
        }

        // Build header
        let mut bs = Vec::with_capacity(SESSION_TRAFFIC_OVERHEAD as usize + msg.len());
        bs.push(SESSION_TYPE_TRAFFIC);
        wire::encode_uvarint(&mut bs, self.local_key_seq);
        wire::encode_uvarint(&mut bs, self.remote_key_seq);
        wire::encode_uvarint(&mut bs, self.send_nonce);

        // Build inner payload: [nextPub(32)][msg]
        let mut inner = Vec::with_capacity(32 + msg.len());
        inner.extend_from_slice(&self.next_pub);
        inner.extend_from_slice(msg);

        // Encrypt
        let ciphertext =
            box_seal_precomputed(&inner, self.send_nonce, &self.send_shared)
                .map_err(|_| Error::Encode)?;
        bs.extend_from_slice(&ciphertext);

        self.tx += msg.len() as u64;
        self.last_activity = Instant::now();
        Ok(bs)
    }

    /// Decrypt an incoming traffic message.
    ///
    /// Returns (decrypted_payload, need_init) where need_init means we should send an init.
    pub fn do_recv(&mut self, msg: &[u8]) -> Result<Vec<u8>, RecvAction> {
        if msg.len() < SESSION_TRAFFIC_OVERHEAD_MIN || msg[0] != SESSION_TYPE_TRAFFIC {
            return Err(RecvAction::Drop);
        }

        let mut offset = 1;
        let (remote_key_seq, len) =
            wire::decode_uvarint(&msg[offset..]).ok_or(RecvAction::Drop)?;
        offset += len;
        let (local_key_seq, len) =
            wire::decode_uvarint(&msg[offset..]).ok_or(RecvAction::Drop)?;
        offset += len;
        let (nonce, len) = wire::decode_uvarint(&msg[offset..]).ok_or(RecvAction::Drop)?;
        offset += len;

        let encrypted = &msg[offset..];

        let from_current = remote_key_seq == self.remote_key_seq;
        let from_next = remote_key_seq == self.remote_key_seq + 1;
        let to_recv = local_key_seq + 1 == self.local_key_seq;
        let to_send = local_key_seq == self.local_key_seq;

        enum DecryptCase {
            CurrentToRecv,
            NextToSend,
            NextToRecv,
        }

        let case = if from_current && to_recv {
            if !(self.recv_nonce < nonce) {
                return Err(RecvAction::Drop);
            }
            DecryptCase::CurrentToRecv
        } else if from_next && to_send {
            if !(self.next_send_nonce < nonce) {
                return Err(RecvAction::Drop);
            }
            DecryptCase::NextToSend
        } else if from_next && to_recv {
            if !(self.next_recv_nonce < nonce) {
                return Err(RecvAction::Drop);
            }
            DecryptCase::NextToRecv
        } else {
            return Err(RecvAction::SendInit);
        };

        // Decrypt with the appropriate shared key
        let shared = match case {
            DecryptCase::CurrentToRecv => &self.recv_shared,
            DecryptCase::NextToSend => &self.next_send_shared,
            DecryptCase::NextToRecv => &self.next_recv_shared,
        };

        let unboxed = box_open_precomputed(encrypted, nonce, shared)
            .map_err(|_| RecvAction::SendInit)?;

        if unboxed.len() < 32 {
            return Err(RecvAction::Drop);
        }

        // Extract inner key and message
        let mut inner_key = [0u8; 32];
        inner_key.copy_from_slice(&unboxed[..32]);
        let payload = unboxed[32..].to_vec();

        // Post-decrypt actions based on case
        match case {
            DecryptCase::CurrentToRecv => {
                self.recv_nonce = nonce;
            }
            DecryptCase::NextToSend => {
                self.next_send_nonce = nonce;
                self.maybe_ratchet_on_recv(inner_key, nonce);
            }
            DecryptCase::NextToRecv => {
                self.next_recv_nonce = nonce;
                self.maybe_ratchet_on_recv(inner_key, nonce);
            }
        }

        self.rx += payload.len() as u64;
        self.last_activity = Instant::now();
        Ok(payload)
    }

    /// Possibly ratchet keys when receiving from remote's "next" key.
    fn maybe_ratchet_on_recv(&mut self, inner_key: CurvePublicKey, nonce: u64) {
        let should_rotate = self
            .rotated
            .map_or(true, |t| t.elapsed() > Duration::from_secs(60));

        if should_rotate {
            // Rotate remote keys
            self.current = self.next;
            self.next = inner_key;
            self.remote_key_seq += 1;

            // Rotate local keys
            self.recv_pub = self.send_pub;
            self.recv_priv = self.send_priv;
            self.send_pub = self.next_pub;
            self.send_priv = self.next_priv;
            self.local_key_seq += 1;

            let (new_next_pub, new_next_priv) = new_box_keys();
            self.next_pub = new_next_pub;
            self.next_priv = new_next_priv;

            self.fix_shared(nonce, 0);
            self.rotated = Some(Instant::now());
        }
    }

    /// Check if the session has timed out.
    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > SESSION_TIMEOUT
    }
}

/// Action needed after receiving a packet.
pub(crate) enum RecvAction {
    /// Drop the packet silently.
    Drop,
    /// Send a new init to resync.
    SendInit,
}

// ---------------------------------------------------------------------------
// SessionBuffer — queued outgoing data before session established
// ---------------------------------------------------------------------------

/// Buffer for data waiting for a session to be established.
pub(crate) struct SessionBuffer {
    pub data: Option<Vec<u8>>,
    pub init: SessionInit,
    pub current_priv: CurvePrivateKey,
    pub next_priv: CurvePrivateKey,
    pub created: Instant,
}

// ---------------------------------------------------------------------------
// SessionManager — manages all sessions
// ---------------------------------------------------------------------------

/// Manages all encrypted sessions.
pub(crate) struct SessionManager {
    pub sessions: HashMap<PublicKey, SessionInfo>,
    pub buffers: HashMap<PublicKey, SessionBuffer>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            buffers: HashMap::new(),
        }
    }

    /// Create a new session from init message keys.
    pub fn new_session(
        &mut self,
        ed: &PublicKey,
        init: &SessionInit,
    ) -> &mut SessionInfo {
        let mut info = SessionInfo::new(init.current, init.next, init.seq);

        // If there's a buffer, migrate its keys
        if let Some(buf) = self.buffers.remove(ed) {
            info.send_pub = buf.init.current;
            info.send_priv = buf.current_priv;
            info.next_pub = buf.init.next;
            info.next_priv = buf.next_priv;
            info.fix_shared(0, 0);
        }

        self.sessions.insert(*ed, info);
        self.sessions.get_mut(ed).unwrap()
    }

    /// Get or create a session from an init message.
    /// Returns (session, buffered_data) where buffered_data is Some if a buffer was consumed.
    pub fn session_for_init(
        &mut self,
        ed: &PublicKey,
        init: &SessionInit,
    ) -> Option<Vec<u8>> {
        if self.sessions.contains_key(ed) {
            return None;
        }

        let buffered_data = self
            .buffers
            .get(ed)
            .and_then(|b| b.data.clone());

        self.new_session(ed, init);
        buffered_data
    }

    /// Handle incoming init message.
    pub fn handle_init(
        &mut self,
        from: &PublicKey,
        init: &SessionInit,
        our_ed_priv: &ed25519_dalek::SigningKey,
    ) -> Vec<OutAction> {
        let mut actions = Vec::new();
        let buffered_data = self.session_for_init(from, init);

        if let Some(info) = self.sessions.get_mut(from) {
            if init.seq <= info.seq {
                // Send ack anyway for existing session
            } else {
                info.handle_update(init);
            }

            // Send ack
            let ack_init = SessionInit::new(&info.send_pub, &info.next_pub, info.local_key_seq);
            if let Ok(data) = ack_init.encrypt(our_ed_priv, from, SESSION_TYPE_ACK) {
                actions.push(OutAction::SendToInner {
                    dest: *from,
                    data,
                });
            }

            // Send buffered data
            if let Some(buf_data) = buffered_data {
                if let Ok(traffic_data) = info.do_send(&buf_data) {
                    actions.push(OutAction::SendToInner {
                        dest: *from,
                        data: traffic_data,
                    });
                }
            }
        }

        actions
    }

    /// Handle incoming ack message.
    pub fn handle_ack(
        &mut self,
        from: &PublicKey,
        ack: &SessionInit,
        _our_ed_priv: &ed25519_dalek::SigningKey,
    ) -> Vec<OutAction> {
        let mut actions = Vec::new();
        let is_old = self.sessions.contains_key(from);

        let buffered_data = self.session_for_init(from, ack);

        if let Some(info) = self.sessions.get_mut(from) {
            if is_old {
                // Existing session: treat as ack
                if ack.seq > info.seq {
                    info.handle_update(ack);
                }
            } else {
                // New session from ack: handle as init
                if ack.seq > info.seq {
                    info.handle_update(ack);
                }
            }

            // Send buffered data
            if let Some(buf_data) = buffered_data {
                if let Ok(traffic_data) = info.do_send(&buf_data) {
                    actions.push(OutAction::SendToInner {
                        dest: *from,
                        data: traffic_data,
                    });
                }
            }
        }

        actions
    }

    /// Handle incoming traffic message.
    pub fn handle_traffic(
        &mut self,
        from: &PublicKey,
        data: &[u8],
        our_ed_priv: &ed25519_dalek::SigningKey,
    ) -> Vec<OutAction> {
        let mut actions = Vec::new();

        if let Some(info) = self.sessions.get_mut(from) {
            match info.do_recv(data) {
                Ok(payload) => {
                    actions.push(OutAction::Deliver {
                        source: *from,
                        data: payload,
                    });
                }
                Err(RecvAction::SendInit) => {
                    // Send init to resync
                    let init =
                        SessionInit::new(&info.send_pub, &info.next_pub, info.local_key_seq);
                    if let Ok(data) = init.encrypt(our_ed_priv, from, SESSION_TYPE_INIT) {
                        actions.push(OutAction::SendToInner {
                            dest: *from,
                            data,
                        });
                    }
                }
                Err(RecvAction::Drop) => {}
            }
        } else {
            // Unknown sender: send ephemeral init (anti-spoofing)
            let (current_pub, _) = new_box_keys();
            let (next_pub, _) = new_box_keys();
            let init = SessionInit::new(&current_pub, &next_pub, 0);
            if let Ok(data) = init.encrypt(our_ed_priv, from, SESSION_TYPE_INIT) {
                actions.push(OutAction::SendToInner {
                    dest: *from,
                    data,
                });
            }
        }

        actions
    }

    /// Handle outbound write.
    pub fn write_to(
        &mut self,
        dest: &PublicKey,
        msg: &[u8],
        our_ed_priv: &ed25519_dalek::SigningKey,
    ) -> Vec<OutAction> {
        let mut actions = Vec::new();

        if let Some(info) = self.sessions.get_mut(dest) {
            if let Ok(traffic_data) = info.do_send(msg) {
                actions.push(OutAction::SendToInner {
                    dest: *dest,
                    data: traffic_data,
                });
            }
        } else {
            actions.extend(self.buffer_and_init(dest, msg, our_ed_priv));
        }

        actions
    }

    /// Buffer data and send init for a new session.
    fn buffer_and_init(
        &mut self,
        dest: &PublicKey,
        msg: &[u8],
        our_ed_priv: &ed25519_dalek::SigningKey,
    ) -> Vec<OutAction> {
        let mut actions = Vec::new();

        let buf = self.buffers.entry(*dest).or_insert_with(|| {
            let (current_pub, current_priv) = new_box_keys();
            let (next_pub, next_priv) = new_box_keys();
            SessionBuffer {
                data: None,
                init: SessionInit::new(&current_pub, &next_pub, 0),
                current_priv,
                next_priv,
                created: Instant::now(),
            }
        });

        buf.data = Some(msg.to_vec());

        if let Ok(data) = buf.init.encrypt(our_ed_priv, dest, SESSION_TYPE_INIT) {
            actions.push(OutAction::SendToInner {
                dest: *dest,
                data,
            });
        }

        actions
    }

    /// Handle incoming data (dispatch by message type).
    pub fn handle_data(
        &mut self,
        from: &PublicKey,
        data: &[u8],
        our_curve_priv: &CurvePrivateKey,
        our_ed_priv: &ed25519_dalek::SigningKey,
    ) -> Vec<OutAction> {
        if data.is_empty() {
            return Vec::new();
        }

        match data[0] {
            SESSION_TYPE_DUMMY => Vec::new(),
            SESSION_TYPE_INIT => {
                match SessionInit::decrypt(data, our_curve_priv, from) {
                    Ok(init) => self.handle_init(from, &init, our_ed_priv),
                    Err(_) => Vec::new(),
                }
            }
            SESSION_TYPE_ACK => {
                match SessionInit::decrypt(data, our_curve_priv, from) {
                    Ok(ack) => self.handle_ack(from, &ack, our_ed_priv),
                    Err(_) => Vec::new(),
                }
            }
            SESSION_TYPE_TRAFFIC => {
                self.handle_traffic(from, data, our_ed_priv)
            }
            _ => Vec::new(),
        }
    }

    /// Clean up expired sessions and buffers.
    pub fn cleanup_expired(&mut self) {
        self.sessions.retain(|_, info| !info.is_expired());
        self.buffers.retain(|_, buf| buf.created.elapsed() < SESSION_TIMEOUT);
    }
}

/// Actions produced by the session manager.
pub(crate) enum OutAction {
    /// Send encrypted data to a peer via the inner PacketConn.
    SendToInner { dest: PublicKey, data: Vec<u8> },
    /// Deliver decrypted data to the application.
    Deliver { source: PublicKey, data: Vec<u8> },
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::crypto::ed25519_private_to_curve25519;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_keys() -> (SigningKey, PublicKey, CurvePrivateKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_key = signing_key.verifying_key().to_bytes();
        let curve_priv = ed25519_private_to_curve25519(&signing_key);
        (signing_key, pub_key, curve_priv)
    }

    #[test]
    fn init_encrypt_decrypt() {
        let (priv_a, pub_a, _curve_priv_a) = make_keys();
        let (_priv_b, pub_b, curve_priv_b) = make_keys();

        let (current, _) = new_box_keys();
        let (next, _) = new_box_keys();
        let init = SessionInit::new(&current, &next, 0);

        let encrypted = init.encrypt(&priv_a, &pub_b, SESSION_TYPE_INIT).unwrap();
        assert_eq!(encrypted.len(), SESSION_INIT_SIZE);
        assert_eq!(encrypted[0], SESSION_TYPE_INIT);

        let decrypted = SessionInit::decrypt(&encrypted, &curve_priv_b, &pub_a).unwrap();
        assert_eq!(decrypted.current, current);
        assert_eq!(decrypted.next, next);
        assert_eq!(decrypted.key_seq, 0);
    }

    #[test]
    fn ack_encrypt_decrypt() {
        let (priv_a, pub_a, _) = make_keys();
        let (_, pub_b, curve_priv_b) = make_keys();

        let (current, _) = new_box_keys();
        let (next, _) = new_box_keys();
        let init = SessionInit::new(&current, &next, 5);

        let encrypted = init.encrypt(&priv_a, &pub_b, SESSION_TYPE_ACK).unwrap();
        assert_eq!(encrypted[0], SESSION_TYPE_ACK);

        let decrypted = SessionInit::decrypt(&encrypted, &curve_priv_b, &pub_a).unwrap();
        assert_eq!(decrypted.key_seq, 5);
    }

    #[test]
    fn session_send_recv() {
        let (priv_a, pub_a, curve_priv_a) = make_keys();
        let (priv_b, pub_b, curve_priv_b) = make_keys();

        let mut mgr_a = SessionManager::new();
        let mut mgr_b = SessionManager::new();

        // A writes to B (triggers buffer + init)
        let actions = mgr_a.write_to(&pub_b, b"hello from A", &priv_a);
        assert_eq!(actions.len(), 1); // SendToInner (init)

        // B receives the init
        if let OutAction::SendToInner { dest, data } = &actions[0] {
            assert_eq!(*dest, pub_b);
            let b_actions = mgr_b.handle_data(&pub_a, data, &curve_priv_b, &priv_b);
            // B should send an ack back
            assert!(!b_actions.is_empty());

            // Send the ack back to A
            for action in &b_actions {
                if let OutAction::SendToInner { dest, data } = action {
                    assert_eq!(*dest, pub_a);
                    let a_actions = mgr_a.handle_data(&pub_b, data, &curve_priv_a, &priv_a);
                    // A should now send the buffered traffic
                    for a_action in &a_actions {
                        if let OutAction::SendToInner { dest, data } = a_action {
                            assert_eq!(*dest, pub_b);
                            // B receives the traffic
                            let b2_actions =
                                mgr_b.handle_data(&pub_a, data, &curve_priv_b, &priv_b);
                            // Should deliver the message
                            for b2_action in &b2_actions {
                                if let OutAction::Deliver { source, data } = b2_action {
                                    assert_eq!(*source, pub_a);
                                    assert_eq!(data, b"hello from A");
                                    return; // Test passed!
                                }
                            }
                        }
                    }
                }
            }
        }
        panic!("expected message delivery");
    }

    #[test]
    fn session_bidirectional() {
        let (priv_a, pub_a, curve_priv_a) = make_keys();
        let (priv_b, pub_b, curve_priv_b) = make_keys();

        let mut mgr_a = SessionManager::new();
        let mut mgr_b = SessionManager::new();

        // Establish session: A→B init, B→A ack
        let a_actions = mgr_a.write_to(&pub_b, b"msg1", &priv_a);
        let init_data = match &a_actions[0] {
            OutAction::SendToInner { data, .. } => data.clone(),
            _ => panic!("expected SendToInner"),
        };

        let b_actions = mgr_b.handle_data(&pub_a, &init_data, &curve_priv_b, &priv_b);
        let ack_data = match &b_actions[0] {
            OutAction::SendToInner { data, .. } => data.clone(),
            _ => panic!("expected SendToInner"),
        };

        let a_actions2 = mgr_a.handle_data(&pub_b, &ack_data, &curve_priv_a, &priv_a);

        // Process A's buffered traffic on B's side
        for action in &a_actions2 {
            if let OutAction::SendToInner { data, .. } = action {
                let b_recv = mgr_b.handle_data(&pub_a, data, &curve_priv_b, &priv_b);
                for ba in &b_recv {
                    if let OutAction::Deliver { data, .. } = ba {
                        assert_eq!(data, b"msg1");
                    }
                }
            }
        }

        // Now B can send to A directly (session already exists on both sides)
        let b_send = mgr_b.write_to(&pub_a, b"msg2", &priv_b);
        for action in &b_send {
            if let OutAction::SendToInner { data, .. } = action {
                let a_recv = mgr_a.handle_data(&pub_b, data, &curve_priv_a, &priv_a);
                for aa in &a_recv {
                    if let OutAction::Deliver { data, .. } = aa {
                        assert_eq!(data, b"msg2");
                        return;
                    }
                }
            }
        }
        panic!("expected msg2 delivery");
    }
}
