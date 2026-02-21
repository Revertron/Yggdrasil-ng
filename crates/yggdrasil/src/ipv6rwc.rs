use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ironwood::Addr;
use tokio::sync::Mutex;

use crate::address::{addr_for_key, is_valid_address, is_valid_subnet, subnet_for_key, Address, Subnet};
use crate::core::Core;

const KEY_STORE_TIMEOUT: Duration = Duration::from_secs(120);
const IPV6_HEADER_LEN: usize = 40;

/// Cached mapping from address/subnet to public key.
struct KeyInfo {
    address: Address,
    subnet: Subnet,
    last_seen: Instant,
}

/// Packet buffered while waiting for a key lookup to complete.
struct BufferedPacket {
    data: Vec<u8>,
    time: Instant,
}

/// Bridges IPv6 traffic (TUN) with the ironwood-based Core.
pub struct ReadWriteCloser {
    core: Arc<Core>,
    address: Address,
    subnet: Subnet,
    inner: Mutex<KeyStoreInner>,
    mtu: u64,
}

struct KeyStoreInner {
    key_to_info: HashMap<[u8; 32], KeyInfo>,
    addr_to_info: HashMap<[u8; 16], [u8; 32]>,
    subnet_to_info: HashMap<[u8; 8], [u8; 32]>,
    addr_buffer: HashMap<[u8; 16], BufferedPacket>,
    subnet_buffer: HashMap<[u8; 8], BufferedPacket>,
}

impl ReadWriteCloser {
    pub fn new(core: Arc<Core>, mtu: u64) -> Arc<Self> {
        let address = *core.address();
        let subnet = *core.subnet();
        Arc::new(Self {
            core,
            address,
            subnet,
            inner: Mutex::new(KeyStoreInner {
                key_to_info: HashMap::new(),
                addr_to_info: HashMap::new(),
                subnet_to_info: HashMap::new(),
                addr_buffer: HashMap::new(),
                subnet_buffer: HashMap::new(),
            }),
            mtu,
        })
    }

    /// Read a packet from the network (Core) destined for the TUN.
    /// Returns the number of bytes written to `buf`.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        loop {
            let mut inner_buf = vec![0u8; 65536];
            let (n, from_addr) = self
                .core
                .read_from(&mut inner_buf)
                .await
                .map_err(|e| format!("core read: {}", e))?;

            if n == 0 {
                continue;
            }

            let packet = &inner_buf[..n];
            tracing::debug!("RWC read {} bytes from {:?}, first byte={:#x}", n, from_addr, packet[0]);

            // Must be IPv6
            if packet[0] & 0xf0 != 0x60 {
                tracing::debug!("RWC dropping non-IPv6 packet (version={})", packet[0] >> 4);
                continue;
            }

            if n < IPV6_HEADER_LEN {
                tracing::debug!("RWC dropping short packet ({} < {})", n, IPV6_HEADER_LEN);
                continue;
            }

            // MTU enforcement: if packet too large, send ICMPv6 PTB back
            if n as u64 > self.mtu {
                let ptb = build_icmpv6_ptb(packet, self.mtu as u32);
                if let Some(ptb) = ptb {
                    let _ = self.core.write_to(&ptb, &from_addr).await;
                }
                continue;
            }

            // Extract src and dst IPv6 addresses
            let mut src_ip = [0u8; 16];
            let mut dst_ip = [0u8; 16];
            src_ip.copy_from_slice(&packet[8..24]);
            dst_ip.copy_from_slice(&packet[24..40]);

            // Verify destination is us
            let dst_is_addr = dst_ip == self.address.0;
            let mut dst_subnet_bytes = [0u8; 8];
            dst_subnet_bytes.copy_from_slice(&dst_ip[..8]);
            let dst_is_subnet = dst_subnet_bytes == self.subnet.0;

            if !dst_is_addr && !dst_is_subnet {
                tracing::debug!("RWC dropping: dst {:x?} is neither our addr nor subnet", &dst_ip[..4]);
                continue;
            }

            // Update key mapping from source
            let from_key = from_addr.0;
            self.update_key(from_key).await;

            // Verify source address matches the key we got it from
            let src_valid = {
                let store = self.inner.lock().await;
                if let Some(info) = store.key_to_info.get(&from_key) {
                    let src_addr_match = src_ip == info.address.0;
                    let mut src_subnet_bytes = [0u8; 8];
                    src_subnet_bytes.copy_from_slice(&src_ip[..8]);
                    let src_subnet_match = src_subnet_bytes == info.subnet.0;
                    src_addr_match || src_subnet_match
                } else {
                    false
                }
            };

            if !src_valid {
                tracing::debug!("RWC dropping: src addr doesn't match sender key");
                continue;
            }

            tracing::debug!("RWC delivering {} bytes to TUN", n);
            let copy_len = n.min(buf.len());
            buf[..copy_len].copy_from_slice(&packet[..copy_len]);
            return Ok(copy_len);
        }
    }

    /// Write a packet from the TUN to the network (Core).
    pub async fn write(&self, buf: &[u8]) -> Result<usize, String> {
        if buf.len() < IPV6_HEADER_LEN {
            return Err("packet too short".to_string());
        }

        // Must be IPv6
        if buf[0] & 0xf0 != 0x60 {
            return Err("not an IPv6 packet".to_string());
        }

        // Extract src and dst
        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        src_ip.copy_from_slice(&buf[8..24]);
        dst_ip.copy_from_slice(&buf[24..40]);

        // Verify source is us
        let src_is_addr = src_ip == self.address.0;
        let mut src_subnet_bytes = [0u8; 8];
        src_subnet_bytes.copy_from_slice(&src_ip[..8]);
        let src_is_subnet = src_subnet_bytes == self.subnet.0;

        if !src_is_addr && !src_is_subnet {
            tracing::trace!("RWC write: invalid source address {:x?}", &src_ip[..4]);
            return Err("invalid source address".to_string());
        }

        // Determine destination key
        let dst_addr_valid = is_valid_address(&dst_ip);
        let mut dst_subnet_prefix = [0u8; 8];
        dst_subnet_prefix.copy_from_slice(&dst_ip[..8]);
        let dst_subnet_valid = is_valid_subnet(&dst_subnet_prefix);

        if !dst_addr_valid && !dst_subnet_valid {
            tracing::trace!("RWC write: invalid destination address {:x?}", &dst_ip[..4]);
            return Err("invalid destination address".to_string());
        }

        // Look up the destination key
        let key = {
            let store = self.inner.lock().await;
            if dst_addr_valid {
                store.addr_to_info.get(&dst_ip).copied()
            } else {
                store.subnet_to_info.get(&dst_subnet_prefix).copied()
            }
        };

        if let Some(key) = key {
            // Known destination, send directly
            tracing::debug!("RWC write: sending {} bytes to known key", buf.len());
            let addr = Addr(key);
            self.core
                .write_to(buf, &addr)
                .await
                .map_err(|e| format!("core write: {}", e))
        } else {
            // Unknown destination, buffer the packet and send lookup
            tracing::debug!("RWC write: key unknown {}, buffering + lookup", Address(dst_ip));
            let mut store = self.inner.lock().await;

            let buffered = BufferedPacket {
                data: buf.to_vec(),
                time: Instant::now(),
            };

            // Determine the lookup key from the address/subnet
            let lookup_key = if dst_addr_valid {
                store.addr_buffer.insert(dst_ip, buffered);
                Address(dst_ip).get_key()
            } else {
                store.subnet_buffer.insert(dst_subnet_prefix, buffered);
                Subnet(dst_subnet_prefix).get_key()
            };

            drop(store);

            // Send lookup
            self.core.send_lookup(Addr(lookup_key)).await;

            Ok(buf.len())
        }
    }

    /// Update key mappings when we learn about a key (from ironwood path notify or packet receipt).
    pub async fn update_key(&self, key: [u8; 32]) {
        let address = addr_for_key(&key);
        let subnet = subnet_for_key(&key);
        tracing::trace!("RWC update_key: learned {} -> {}", address, hex::encode(&key[..8]));
        let now = Instant::now();

        let mut store = self.inner.lock().await;

        // Update or insert key info
        let info = KeyInfo {
            address,
            subnet,
            last_seen: now,
        };
        store.key_to_info.insert(key, info);
        store.addr_to_info.insert(address.0, key);
        store.subnet_to_info.insert(subnet.0, key);

        // Flush any buffered packets for this address/subnet
        let addr_buf = store.addr_buffer.remove(&address.0);
        let subnet_buf = store.subnet_buffer.remove(&subnet.0);
        drop(store);

        if let Some(buffered) = addr_buf {
            if buffered.time.elapsed() < KEY_STORE_TIMEOUT {
                let addr = Addr(key);
                let _ = self.core.write_to(&buffered.data, &addr).await;
            }
        }

        if let Some(buffered) = subnet_buf {
            if buffered.time.elapsed() < KEY_STORE_TIMEOUT {
                let addr = Addr(key);
                let _ = self.core.write_to(&buffered.data, &addr).await;
            }
        }
    }

    /// Clean up expired entries from the key store.
    pub async fn cleanup(&self) {
        let mut store = self.inner.lock().await;

        // Remove expired key infos
        let expired_keys: Vec<[u8; 32]> = store
            .key_to_info
            .iter()
            .filter(|(_, info)| info.last_seen.elapsed() > KEY_STORE_TIMEOUT)
            .map(|(key, _)| *key)
            .collect();

        for key in expired_keys {
            if let Some(info) = store.key_to_info.remove(&key) {
                store.addr_to_info.remove(&info.address.0);
                store.subnet_to_info.remove(&info.subnet.0);
            }
        }

        // Remove expired buffers
        store
            .addr_buffer
            .retain(|_, buf| buf.time.elapsed() < KEY_STORE_TIMEOUT);
        store
            .subnet_buffer
            .retain(|_, buf| buf.time.elapsed() < KEY_STORE_TIMEOUT);
    }

    pub fn mtu(&self) -> u64 {
        self.mtu
    }
}

/// Build an ICMPv6 Packet Too Big message.
/// Takes the original oversized packet and the MTU to report.
fn build_icmpv6_ptb(original: &[u8], mtu: u32) -> Option<Vec<u8>> {
    if original.len() < IPV6_HEADER_LEN {
        return None;
    }

    // Source and dest from original packet (we swap them for the response)
    let orig_src = &original[8..24];
    let orig_dst = &original[24..40];

    // ICMPv6 body: up to 512 bytes of the original packet
    let copy_len = original.len().min(512);

    // ICMPv6 Packet Too Big:
    //   Type (1) = 2
    //   Code (1) = 0
    //   Checksum (2) = computed
    //   MTU (4) = big-endian
    //   Data (variable) = original packet (truncated)
    let icmp_len = 8 + copy_len;
    let mut icmp = vec![0u8; icmp_len];
    icmp[0] = 2; // Type: Packet Too Big
    icmp[1] = 0; // Code
    // Checksum at [2..4], fill later
    icmp[4..8].copy_from_slice(&mtu.to_be_bytes());
    icmp[8..8 + copy_len].copy_from_slice(&original[..copy_len]);

    // Compute ICMPv6 checksum using pseudo-header
    let checksum = icmpv6_checksum(orig_dst, orig_src, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    // Build IPv6 header
    let total_len = IPV6_HEADER_LEN + icmp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60; // Version 6
    let payload_len = icmp_len as u16;
    packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    packet[6] = 58; // Next header: ICMPv6
    packet[7] = 255; // Hop limit
    packet[8..24].copy_from_slice(orig_dst); // src = original dst (us)
    packet[24..40].copy_from_slice(orig_src); // dst = original src
    packet[IPV6_HEADER_LEN..].copy_from_slice(&icmp);

    Some(packet)
}

/// Compute ICMPv6 checksum with IPv6 pseudo-header.
fn icmpv6_checksum(src: &[u8], dst: &[u8], icmp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: src addr (16) + dst addr (16) + upper-layer length (4) + next header (4)
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
    }
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
    }
    let len = icmp_data.len() as u32;
    sum += (len >> 16) as u32;
    sum += (len & 0xFFFF) as u32;
    sum += 58u32; // ICMPv6 protocol number

    // ICMPv6 data
    let mut i = 0;
    while i + 1 < icmp_data.len() {
        sum += u16::from_be_bytes([icmp_data[i], icmp_data[i + 1]]) as u32;
        i += 2;
    }
    if i < icmp_data.len() {
        sum += (icmp_data[i] as u32) << 8;
    }

    // Fold carries
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmpv6_ptb_construction() {
        // Create a minimal IPv6 packet
        let mut packet = vec![0u8; 60];
        packet[0] = 0x60; // IPv6
        // src addr
        packet[8] = 0x02;
        packet[9] = 0x01;
        // dst addr
        packet[24] = 0x02;
        packet[25] = 0x02;

        let ptb = build_icmpv6_ptb(&packet, 1280);
        assert!(ptb.is_some());
        let ptb = ptb.unwrap();

        // Verify it's IPv6
        assert_eq!(ptb[0] & 0xf0, 0x60);
        // Verify next header is ICMPv6
        assert_eq!(ptb[6], 58);
        // Verify ICMPv6 type is Packet Too Big
        assert_eq!(ptb[40], 2);
        // Verify MTU
        let mtu = u32::from_be_bytes([ptb[44], ptb[45], ptb[46], ptb[47]]);
        assert_eq!(mtu, 1280);
        // Verify src/dst swapped
        assert_eq!(&ptb[8..24], &packet[24..40]); // response src = orig dst
        assert_eq!(&ptb[24..40], &packet[8..24]); // response dst = orig src
    }
}
