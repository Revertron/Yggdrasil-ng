use arc_swap::ArcSwap;
use rustc_hash::FxHashMap as HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ironwood::Addr;
use tokio::sync::Mutex;

use crate::address::{addr_for_key, is_valid_address, is_valid_subnet, subnet_for_key, Address, Subnet};
use crate::core::Core;
#[cfg(feature = "ckr")]
use {
    std::net::IpAddr,
    crate::ckr::CryptoKey,
    crate::config::TunnelRoutingConfig,
};
use crate::firewall::Firewall;

const KEY_STORE_TIMEOUT: Duration = Duration::from_secs(120);
const IPV6_HEADER_LEN: usize = 40;

/// Cached mapping from address/subnet to public key.
#[derive(Clone)]
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
/// When the `ckr` feature is enabled, also handles IPv4 and CKR-routed traffic.
pub struct ReadWriteCloser {
    core: Arc<Core>,
    address: Address,
    subnet: Subnet,
    lookups: ArcSwap<KeyStoreLookups>,
    /// Serializes writers to `lookups` so concurrent updates don't lose changes.
    lookups_write: std::sync::Mutex<()>,
    buffers: Mutex<KeyStoreBuffers>,
    /// Overlay payload cap advertised via ICMPv6 PTB.
    /// Starts as `core.mtu()`, then `set_mtu()` lowers it to the TUN
    /// interface MTU after the kernel may have clamped `if_mtu`.
    mtu: AtomicU64,
    #[cfg(feature = "ckr")]
    ckr: Option<CryptoKey>,
    firewall: Option<Arc<Firewall>>,
}

#[derive(Clone)]
struct KeyStoreLookups {
    key_to_info: HashMap<[u8; 32], KeyInfo>,
    addr_to_info: HashMap<[u8; 16], [u8; 32]>,
    subnet_to_info: HashMap<[u8; 8], [u8; 32]>,
}

struct KeyStoreBuffers {
    addr_buffer: HashMap<[u8; 16], BufferedPacket>,
    subnet_buffer: HashMap<[u8; 8], BufferedPacket>,
}

impl ReadWriteCloser {
    pub fn new(
        core: Arc<Core>,
        mtu: u64,
        #[cfg(feature = "ckr")] ckr_config: Option<&TunnelRoutingConfig>,
        firewall: Option<Arc<Firewall>>,
    ) -> Arc<Self> {
        let address = *core.address();
        let subnet = *core.subnet();

        #[cfg(feature = "ckr")]
        let ckr = ckr_config
            .filter(|c| c.enable)
            .map(|c| {
                CryptoKey::new(c, core.public_key()).unwrap_or_else(|e| {
                    tracing::error!("Failed to configure CKR: {}", e);
                    panic!("CKR configuration error: {}", e);
                })
            });

        Arc::new(Self {
            core,
            address,
            subnet,
            lookups: ArcSwap::from_pointee(KeyStoreLookups {
                key_to_info: HashMap::default(),
                addr_to_info: HashMap::default(),
                subnet_to_info: HashMap::default(),
            }),
            lookups_write: std::sync::Mutex::new(()),
            buffers: Mutex::new(KeyStoreBuffers {
                addr_buffer: HashMap::default(),
                subnet_buffer: HashMap::default(),
            }),
            mtu: AtomicU64::new(mtu.clamp(1280, 65535)),
            #[cfg(feature = "ckr")]
            ckr,
            firewall,
        })
    }

    /// Read a packet from the network (Core) destined for the TUN.
    /// Returns the slice of `buf` holding the packet.
    pub async fn read<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], String> {
        // The loop yields an owned range rather than a slice: a borrow of `buf`
        // cannot outlive an iteration that reborrows it mutably.
        let range = loop {
            let (range, from_addr) = self
                .core
                .read_from(&mut *buf)
                .await
                .map_err(|e| format!("core read: {}", e))?;

            let n = range.len();
            if n == 0 {
                continue;
            }

            let packet = &buf[range.clone()];
            tracing::debug!("RWC read {} bytes from {:?}, first byte={:#x}", n, from_addr, packet[0]);

            let is_ip4 = packet[0] & 0xf0 == 0x40;
            let is_ip6 = packet[0] & 0xf0 == 0x60;

            #[cfg(feature = "ckr")]
            let ckr_active = self.ckr.is_some();
            #[cfg(not(feature = "ckr"))]
            let ckr_active = false;

            if !ckr_active {
                // Standard mode: IPv6 only
                if !is_ip6 {
                    tracing::debug!("RWC dropping non-IPv6 packet (version={})", packet[0] >> 4);
                    continue;
                }
            } else if !is_ip4 && !is_ip6 {
                // CKR mode: IPv4 or IPv6
                tracing::debug!("RWC dropping non-IP packet (version={})", packet[0] >> 4);
                continue;
            }

            if is_ip6 && n < IPV6_HEADER_LEN {
                tracing::debug!("RWC dropping short packet ({} < {})", n, IPV6_HEADER_LEN);
                continue;
            }

            // MTU enforcement. Use the TUN-clamped overlay MTU, not the
            // ironwood cap from construction.
            let overlay_mtu = self.mtu.load(Ordering::Relaxed);
            if n as u64 > overlay_mtu {
                if is_ip6 {
                    let ptb = build_icmpv6_ptb(packet, overlay_mtu as u32);
                    if let Some(ptb) = ptb {
                        let _ = self.core.write_to(&ptb, &from_addr).await;
                    }
                }
                continue;
            }

            let from_key = from_addr.0;
            self.update_key(from_key).await;

            // CKR path: dual-mode validation
            #[cfg(feature = "ckr")]
            if let Some(ref ckr) = self.ckr {
                let accepted = self.ckr_read_validate(ckr, packet, is_ip4, is_ip6, &from_key).await;
                if !accepted {
                    continue;
                }
                if let Some(fw) = &self.firewall {
                    if fw.enabled() && is_ip6 && !fw.check_inbound(packet) {
                        tracing::debug!("RWC firewall: drop inbound (CKR path)");
                        continue;
                    }
                }
                break range;
            }

            // Standard (non-CKR) path: IPv6 only validation
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

            // Verify source address matches the key we got it from
            let src_valid = {
                let lookups = self.lookups.load();
                if let Some(info) = lookups.key_to_info.get(&from_key) {
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

            if let Some(fw) = &self.firewall {
                if fw.enabled() && !fw.check_inbound(packet) {
                    tracing::debug!("RWC firewall: drop inbound");
                    continue;
                }
            }

            tracing::debug!("RWC delivering {} bytes to TUN", n);
            break range;
        };

        Ok(&buf[range])
    }

    /// Write a packet from the TUN to the network (Core).
    pub async fn write(&self, buf: &[u8]) -> Result<usize, String> {
        let is_ip6 = buf.first().map_or(false, |b| b & 0xf0 == 0x60);

        // Firewall: observe outbound IPv6 flows so matching inbound replies pass.
        // Outbound is never blocked.
        if is_ip6 {
            if let Some(fw) = &self.firewall {
                if fw.enabled() {
                    fw.observe_outbound(buf);
                }
            }
        }

        // CKR path: handle IPv4 and non-Yggdrasil IPv6 destinations
        #[cfg(feature = "ckr")]
        if let Some(ref ckr) = self.ckr {
            let is_ip4 = buf.first().map_or(false, |b| b & 0xf0 == 0x40);
            if !is_ip4 && !is_ip6 {
                return Ok(buf.len()); // silently drop non-IP
            }
            if is_ip6 && buf.len() < IPV6_HEADER_LEN {
                return Ok(buf.len());
            }
            return self.ckr_write(ckr, buf, is_ip4, is_ip6).await;
        }

        // Standard (non-CKR) path: IPv6 only
        if buf.len() < IPV6_HEADER_LEN {
            return Err("packet too short".to_string());
        }

        if !is_ip6 {
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

        // Look up the destination key (read-only)
        let key = {
            let lookups = self.lookups.load();
            if dst_addr_valid {
                lookups.addr_to_info.get(&dst_ip).copied()
            } else {
                lookups.subnet_to_info.get(&dst_subnet_prefix).copied()
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
            let mut buffers = self.buffers.lock().await;

            let buffered = BufferedPacket {
                data: buf.to_vec(),
                time: Instant::now(),
            };

            // Determine the lookup key from the address/subnet
            let lookup_key = if dst_addr_valid {
                buffers.addr_buffer.insert(dst_ip, buffered);
                Address(dst_ip).get_key()
            } else {
                buffers.subnet_buffer.insert(dst_subnet_prefix, buffered);
                Subnet(dst_subnet_prefix).get_key()
            };

            drop(buffers);

            // Send lookup
            self.core.send_lookup(Addr(lookup_key)).await;

            Ok(buf.len())
        }
    }

    /// Update key mappings when we learn about a key (from ironwood path notify or packet receipt).
    pub async fn update_key(&self, key: [u8; 32]) {
        // Fast path: if key is already known and fresh, skip the write entirely.
        // The lock-free `ArcSwap::load` makes this nearly free on the hot path.
        {
            let lookups = self.lookups.load();
            if let Some(info) = lookups.key_to_info.get(&key) {
                if info.last_seen.elapsed() < KEY_STORE_TIMEOUT / 2 {
                    return;
                }
            }
        }

        let address = addr_for_key(&key);
        let subnet = subnet_for_key(&key);
        tracing::trace!("RWC update_key: learned {} -> {}", address, hex::encode(&key[..8]));
        let now = Instant::now();

        // Update lookup maps via clone-and-swap (writer mutex serializes concurrent updaters).
        {
            let _w = self.lookups_write.lock().unwrap();
            let mut new = (**self.lookups.load()).clone();
            let info = KeyInfo {
                address,
                subnet,
                last_seen: now,
            };
            new.key_to_info.insert(key, info);
            new.addr_to_info.insert(address.0, key);
            new.subnet_to_info.insert(subnet.0, key);
            self.lookups.store(Arc::new(new));
        }

        // Flush any buffered packets for this address/subnet
        let (addr_buf, subnet_buf) = {
            let mut buffers = self.buffers.lock().await;
            let a = buffers.addr_buffer.remove(&address.0);
            let s = buffers.subnet_buffer.remove(&subnet.0);
            (a, s)
        };

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
        // Remove expired key infos
        {
            let _w = self.lookups_write.lock().unwrap();
            let cur = self.lookups.load();
            let expired_keys: Vec<[u8; 32]> = cur
                .key_to_info
                .iter()
                .filter(|(_, info)| info.last_seen.elapsed() > KEY_STORE_TIMEOUT)
                .map(|(key, _)| *key)
                .collect();

            if !expired_keys.is_empty() {
                let mut new = (**cur).clone();
                for key in expired_keys {
                    if let Some(info) = new.key_to_info.remove(&key) {
                        new.addr_to_info.remove(&info.address.0);
                        new.subnet_to_info.remove(&info.subnet.0);
                    }
                }
                self.lookups.store(Arc::new(new));
            }
        }

        // Remove expired buffers
        {
            let mut buffers = self.buffers.lock().await;
            buffers
                .addr_buffer
                .retain(|_, buf| buf.time.elapsed() < KEY_STORE_TIMEOUT);
            buffers
                .subnet_buffer
                .retain(|_, buf| buf.time.elapsed() < KEY_STORE_TIMEOUT);
        }
    }

    pub fn mtu(&self) -> u64 {
        self.mtu.load(Ordering::Relaxed)
    }

    /// Lower the overlay MTU to the TUN interface's actual MTU.
    ///
    /// `ReadWriteCloser::new` runs before the TUN exists and stores
    /// `core.mtu()` (~65535). After `TunAdapter` probes the kernel,
    /// call this with `device.mtu()`. Incoming packets larger than
    /// the new value are dropped in `read()` and answered with
    /// ICMPv6 Packet Too Big so the sender can shrink.
    ///
    /// Never raises the cap above what `new()` stored (ironwood
    /// payload limit). Values below 1280 are raised to the IPv6
    /// minimum.
    pub fn set_mtu(&self, mtu: u64) {
        let mtu = clamp_overlay_mtu(self.mtu.load(Ordering::Relaxed), mtu);
        self.mtu.store(mtu, Ordering::Relaxed);
    }

    // --- CKR helper methods ---

    /// CKR inbound validation: check whether a received packet should be
    /// delivered to the TUN based on CKR routing rules.
    /// Returns true if the packet is accepted.
    #[cfg(feature = "ckr")]
    async fn ckr_read_validate(
        &self,
        ckr: &CryptoKey,
        packet: &[u8],
        is_ip4: bool,
        is_ip6: bool,
        from_key: &[u8; 32],
    ) -> bool {
        // For IPv6 + yggdrasil_routing: check if source matches sender's Ygg address/subnet
        if is_ip6 && ckr.yggdrasil_routing() {
            let mut src_ip = [0u8; 16];
            src_ip.copy_from_slice(&packet[8..24]);

            let lookups = self.lookups.load();
            if let Some(info) = lookups.key_to_info.get(from_key) {
                let src_addr_match = src_ip == info.address.0;
                let mut src_subnet_bytes = [0u8; 8];
                src_subnet_bytes.copy_from_slice(&src_ip[..8]);
                let src_subnet_match = src_subnet_bytes == info.subnet.0;
                if src_addr_match || src_subnet_match {
                    return true;
                }
            }
        }

        // For IPv4 or non-Ygg IPv6: validate source against CKR routing table
        let src_addr = if is_ip4 {
            if packet.len() < 20 {
                return false;
            }
            let mut addr_bytes = [0u8; 4];
            addr_bytes.copy_from_slice(&packet[12..16]);
            IpAddr::from(addr_bytes)
        } else {
            // IPv6
            let mut addr_bytes = [0u8; 16];
            addr_bytes.copy_from_slice(&packet[8..24]);
            IpAddr::from(addr_bytes)
        };

        // Look up the source address in CKR table and verify
        // the route's public key matches the actual sender
        if let Some(expected_key) = ckr.get_public_key_for_address(src_addr) {
            if &expected_key == from_key {
                return true;
            }
            tracing::debug!("CKR dropping: source {} key mismatch", src_addr);
        } else {
            tracing::debug!("CKR dropping: no route for source {}", src_addr);
        }

        false
    }

    /// CKR outbound routing: route a packet from TUN to the network
    /// using CKR routing table for non-Yggdrasil destinations.
    #[cfg(feature = "ckr")]
    async fn ckr_write(
        &self,
        ckr: &CryptoKey,
        buf: &[u8],
        is_ip4: bool,
        is_ip6: bool,
    ) -> Result<usize, String> {
        // Extract destination address
        let mut dst_addr_bytes = [0u8; 16];
        let mut dst_subnet_prefix = [0u8; 8];

        if is_ip4 {
            if buf.len() < 20 {
                return Ok(buf.len());
            }
            dst_addr_bytes[..4].copy_from_slice(&buf[16..20]);
        } else {
            dst_addr_bytes.copy_from_slice(&buf[24..40]);
            dst_subnet_prefix.copy_from_slice(&buf[24..32]);
        }

        // Try Yggdrasil routing first (if enabled and it's IPv6)
        if is_ip6 && ckr.yggdrasil_routing() {
            let dst_addr_valid = is_valid_address(&dst_addr_bytes);
            let dst_subnet_valid = is_valid_subnet(&dst_subnet_prefix);

            if dst_addr_valid || dst_subnet_valid {
                // Use standard Yggdrasil routing path (read-only lookup)
                let key = {
                    let lookups = self.lookups.load();
                    if dst_addr_valid {
                        lookups.addr_to_info.get(&dst_addr_bytes).copied()
                    } else {
                        lookups.subnet_to_info.get(&dst_subnet_prefix).copied()
                    }
                };

                if let Some(key) = key {
                    let addr = Addr(key);
                    return self
                        .core
                        .write_to(buf, &addr)
                        .await
                        .map_err(|e| format!("core write: {}", e));
                } else {
                    // Buffer and lookup
                    let mut buffers = self.buffers.lock().await;
                    let buffered = BufferedPacket {
                        data: buf.to_vec(),
                        time: Instant::now(),
                    };
                    let lookup_key = if dst_addr_valid {
                        buffers.addr_buffer.insert(dst_addr_bytes, buffered);
                        Address(dst_addr_bytes).get_key()
                    } else {
                        buffers.subnet_buffer.insert(dst_subnet_prefix, buffered);
                        Subnet(dst_subnet_prefix).get_key()
                    };
                    drop(buffers);
                    self.core.send_lookup(Addr(lookup_key)).await;
                    return Ok(buf.len());
                }
            }
        }

        // CKR routing: look up destination in CKR table
        let dst_ip = if is_ip4 {
            let mut addr4 = [0u8; 4];
            addr4.copy_from_slice(&buf[16..20]);
            IpAddr::from(addr4)
        } else {
            IpAddr::from(dst_addr_bytes)
        };

        if let Some(key) = ckr.get_public_key_for_address(dst_ip) {
            let addr = Addr(key);
            self.core
                .write_to(buf, &addr)
                .await
                .map_err(|e| format!("core write: {}", e))
        } else {
            // No route, silently drop (matches Go behavior)
            Ok(buf.len())
        }
    }
}

/// Resulting overlay MTU: IPv6 floor..65535, and never above `current`.
fn clamp_overlay_mtu(current: u64, requested: u64) -> u64 {
    requested.clamp(1280, 65535).min(current)
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

    #[test]
    fn clamp_overlay_mtu_lowers_to_stock_netbsd_tunmtu() {
        assert_eq!(clamp_overlay_mtu(65535, 1500), 1500);
    }

    #[test]
    fn clamp_overlay_mtu_does_not_raise_above_current() {
        // Custom kernel already probed to 1500; a later 65535 must not
        // lift the overlay cap back up.
        assert_eq!(clamp_overlay_mtu(1500, 65535), 1500);
    }

    #[test]
    fn clamp_overlay_mtu_rejects_below_ipv6_minimum() {
        assert_eq!(clamp_overlay_mtu(65535, 100), 1280);
    }

    #[test]
    fn clamp_overlay_mtu_keeps_matching_jumbo() {
        assert_eq!(clamp_overlay_mtu(65535, 65535), 65535);
    }
}
