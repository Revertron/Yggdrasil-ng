//! Stateful packet firewall for the Yggdrasil TUN.
//!
//! Sits between ironwood and the TUN in `ipv6rwc`. When enabled it drops
//! inbound mesh packets unless one of:
//!   1. source IPv6 is inside an `open_all_for` subnet,
//!   2. the packet matches an existing outbound flow (stateful return),
//!   3. it's a TCP SYN to a port in `open_tcp`, or a UDP packet to a port in `open_udp`,
//!   4. it's an ICMPv6 Echo Request and `allow_icmp_echo` is true,
//!   5. it's an ICMPv6 error (types 1-4).
//!
//! Outbound is always allowed; observe-only.

use ipnet::{IpNet, Ipv6Net};
use rustc_hash::{FxHashMap, FxHashSet};
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use crate::config::FirewallConfig;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const DEST_OPTS: u8 = 60;

const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_ACK: u8 = 0x10;

const ICMP_ECHO_REQUEST: u8 = 128;
const ICMP_ECHO_REPLY: u8 = 129;

const TCP_SYN_TIMEOUT: Duration = Duration::from_secs(30);
const TCP_ESTABLISHED_TIMEOUT: Duration = Duration::from_secs(300);
const TCP_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_TIMEOUT: Duration = Duration::from_secs(60);
const ICMP_TIMEOUT: Duration = Duration::from_secs(30);
const GC_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
struct FlowKey {
    proto: u8,
    our_ip: [u8; 16],
    our_port: u16,
    peer_ip: [u8; 16],
    peer_port: u16,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum TcpState {
    SynSent,
    Established,
    FinSeen,
    Closed,
}

struct FlowEntry {
    last_seen: Instant,
    tcp_state: Option<TcpState>,
}

impl FlowEntry {
    fn timeout(&self, proto: u8) -> Duration {
        match proto {
            PROTO_TCP => match self.tcp_state {
                Some(TcpState::SynSent) => TCP_SYN_TIMEOUT,
                Some(TcpState::Established) => TCP_ESTABLISHED_TIMEOUT,
                Some(TcpState::FinSeen) | Some(TcpState::Closed) => TCP_CLOSE_TIMEOUT,
                None => TCP_SYN_TIMEOUT,
            },
            PROTO_UDP => UDP_TIMEOUT,
            PROTO_ICMPV6 => ICMP_TIMEOUT,
            _ => UDP_TIMEOUT,
        }
    }
}

struct Parsed {
    proto: u8,
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    icmp_type: u8,
}

pub struct Firewall {
    enable: bool,
    open_tcp: FxHashSet<u16>,
    open_udp: FxHashSet<u16>,
    open_all_for: Vec<Ipv6Net>,
    allow_icmp_echo: bool,
    table: Mutex<FxHashMap<FlowKey, FlowEntry>>,
}

impl Firewall {
    pub fn new(cfg: &FirewallConfig) -> Result<Self, String> {
        let mut subnets = Vec::with_capacity(cfg.open_all_for.len());
        for s in &cfg.open_all_for {
            let net = IpNet::from_str(s.as_str())
                .map_err(|e| format!("firewall: invalid open_all_for entry '{}': {}", s, e))?;
            match net {
                IpNet::V6(v6) => subnets.push(v6),
                IpNet::V4(_) => {
                    return Err(format!(
                        "firewall: open_all_for entry '{}' is IPv4, only IPv6 is supported",
                        s
                    ));
                }
            }
        }

        Ok(Self {
            enable: cfg.enable,
            open_tcp: cfg.open_tcp.iter().copied().collect(),
            open_udp: cfg.open_udp.iter().copied().collect(),
            open_all_for: subnets,
            allow_icmp_echo: cfg.allow_icmp_echo,
            table: Mutex::new(FxHashMap::default()),
        })
    }

    #[inline]
    pub fn enabled(&self) -> bool {
        self.enable
    }

    /// Spawn a periodic background task that evicts stale conntrack entries.
    /// The task exits automatically once all strong references to `self` are dropped.
    pub fn spawn_gc(self: &Arc<Self>) {
        let weak: Weak<Self> = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(GC_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let Some(fw) = weak.upgrade() else { break };
                fw.gc();
            }
        });
    }

    fn gc(&self) {
        let now = Instant::now();
        // A poisoned lock skips this sweep rather than mutating a table that may be
        // half-updated; the next sweep picks it up.
        if let Ok(mut t) = lock!(self.table) {
            t.retain(|key, entry| {
                let max = entry.timeout(key.proto);
                now.duration_since(entry.last_seen) < max
            });
        }
    }

    /// Record an outbound flow. Outbound is never blocked.
    pub fn observe_outbound(&self, pkt: &[u8]) {
        let p = match parse(pkt) {
            Some(p) => p,
            None => return,
        };
        // Only track protocols we actually filter on.
        if !is_tracked(p.proto) {
            return;
        }
        let key = FlowKey {
            proto: p.proto,
            our_ip: p.src_ip,
            our_port: p.src_port,
            peer_ip: p.dst_ip,
            peer_port: p.dst_port,
        };
        let now = Instant::now();
        // Nothing can be recorded for this flow, so the return packet will find no
        // matching flow and be denied. That is the fail-closed direction, so it is
        // left to the caller's normal path rather than special-cased here.
        let Ok(mut t) = lock!(self.table) else {
            return;
        };
        let entry = t.entry(key).or_insert(FlowEntry {
            last_seen: now,
            tcp_state: if p.proto == PROTO_TCP {
                Some(TcpState::SynSent)
            } else {
                None
            },
        });
        entry.last_seen = now;
        if p.proto == PROTO_TCP {
            entry.tcp_state = Some(advance_tcp(entry.tcp_state, p.tcp_flags));
        }
    }

    /// Decide whether an inbound packet should be delivered.
    /// Returns true if accepted, false if it should be dropped.
    pub fn check_inbound(&self, pkt: &[u8]) -> bool {
        let p = match parse(pkt) {
            Some(p) => p,
            // Unparseable / non-first fragment / non-IPv6 → drop on inbound.
            None => return false,
        };

        // 1. open_all_for bypass
        let src = Ipv6Addr::from(p.src_ip);
        for net in &self.open_all_for {
            if net.contains(&src) {
                return true;
            }
        }

        // 2. ICMPv6 short-circuits: errors and echo
        if p.proto == PROTO_ICMPV6 {
            // Always allow ICMPv6 errors (types 1..=4); they're informational
            // and small. No conntrack tracking needed.
            if matches!(p.icmp_type, 1..=4) {
                return true;
            }
            if p.icmp_type == ICMP_ECHO_REQUEST {
                if self.allow_icmp_echo {
                    return true;
                }
                // fall through to conntrack — caller might have initiated
                // a "ping me back" via outbound somehow (rare); otherwise drop.
            }
            // Echo reply is conntrack-driven (matched against outbound echo).
        }

        // 3. Conntrack: reverse the packet's src/dst to match the outbound key.
        let key = FlowKey {
            proto: p.proto,
            our_ip: p.dst_ip,
            our_port: p.dst_port,
            peer_ip: p.src_ip,
            peer_port: p.src_port,
        };
        {
            let Ok(mut t) = lock!(self.table) else {
                // Cannot confirm the flow; deny rather than allow on state we cannot read.
                return false;
            };
            if let Some(entry) = t.get_mut(&key) {
                entry.last_seen = Instant::now();
                if p.proto == PROTO_TCP {
                    entry.tcp_state = Some(advance_tcp(entry.tcp_state, p.tcp_flags));
                }
                return true;
            }
        }

        // 4. Open-port whitelist creates a new flow if accepted.
        match p.proto {
            PROTO_TCP => {
                let is_syn = (p.tcp_flags & TCP_FLAG_SYN) != 0
                    && (p.tcp_flags & TCP_FLAG_ACK) == 0;
                if is_syn && self.open_tcp.contains(&p.dst_port) {
                    let now = Instant::now();
                    // Denied rather than allowed: the flow cannot be recorded, so the
                    // return packet would not match it either.
                    let Ok(mut t) = lock!(self.table) else {
                        return false;
                    };
                    t.insert(
                        key,
                        FlowEntry {
                            last_seen: now,
                            tcp_state: Some(TcpState::SynSent),
                        },
                    );
                    return true;
                }
            }
            PROTO_UDP => {
                if self.open_udp.contains(&p.dst_port) {
                    let now = Instant::now();
                    let Ok(mut t) = lock!(self.table) else {
                        return false;
                    };
                    t.insert(
                        key,
                        FlowEntry {
                            last_seen: now,
                            tcp_state: None,
                        },
                    );
                    return true;
                }
            }
            _ => {}
        }

        false
    }
}

fn is_tracked(proto: u8) -> bool {
    matches!(proto, PROTO_TCP | PROTO_UDP | PROTO_ICMPV6)
}

fn advance_tcp(prev: Option<TcpState>, flags: u8) -> TcpState {
    if (flags & TCP_FLAG_RST) != 0 {
        return TcpState::Closed;
    }
    if (flags & TCP_FLAG_FIN) != 0 {
        return TcpState::FinSeen;
    }
    let syn = (flags & TCP_FLAG_SYN) != 0;
    let ack = (flags & TCP_FLAG_ACK) != 0;
    match prev {
        Some(TcpState::Closed) | Some(TcpState::FinSeen) => prev.unwrap(),
        Some(TcpState::Established) => TcpState::Established,
        Some(TcpState::SynSent) | None => {
            if ack && !syn {
                TcpState::Established
            } else if syn && ack {
                TcpState::Established
            } else {
                TcpState::SynSent
            }
        }
    }
}

/// Parse an IPv6 packet far enough to extract the transport-layer 5-tuple
/// (plus TCP flags / ICMP type as needed). Returns None for:
///   - non-IPv6 packets
///   - packets shorter than the IPv6 header
///   - non-first fragments (we can't see the transport header)
///   - unknown next-header chains
///   - protocols we don't filter on
fn parse(pkt: &[u8]) -> Option<Parsed> {
    if pkt.len() < 40 {
        return None;
    }
    if (pkt[0] >> 4) != 6 {
        return None;
    }

    let mut src_ip = [0u8; 16];
    let mut dst_ip = [0u8; 16];
    src_ip.copy_from_slice(&pkt[8..24]);
    dst_ip.copy_from_slice(&pkt[24..40]);

    let mut next = pkt[6];
    let mut off = 40usize;

    // Walk extension headers up to a small bound.
    for _ in 0..8 {
        match next {
            HOP_BY_HOP | ROUTING | DEST_OPTS => {
                if off + 2 > pkt.len() {
                    return None;
                }
                let nxt = pkt[off];
                let hdr_len = (pkt[off + 1] as usize + 1) * 8;
                if off + hdr_len > pkt.len() {
                    return None;
                }
                next = nxt;
                off += hdr_len;
            }
            FRAGMENT => {
                if off + 8 > pkt.len() {
                    return None;
                }
                // Bytes 2-3: frag_offset (high 13 bits) | res (2) | M (1)
                let frag_word = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
                let frag_offset = frag_word >> 3;
                if frag_offset != 0 {
                    return None; // non-first fragment
                }
                next = pkt[off];
                off += 8;
            }
            _ => break,
        }
    }

    let proto = next;
    if !is_tracked(proto) {
        return None;
    }

    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut tcp_flags = 0u8;
    let mut icmp_type = 0u8;

    match proto {
        PROTO_TCP => {
            if off + 14 > pkt.len() {
                return None;
            }
            src_port = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            dst_port = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
            tcp_flags = pkt[off + 13];
        }
        PROTO_UDP => {
            if off + 8 > pkt.len() {
                return None;
            }
            src_port = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            dst_port = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
        }
        PROTO_ICMPV6 => {
            if off + 8 > pkt.len() {
                return None;
            }
            icmp_type = pkt[off];
            // For Echo Request/Reply, identifier lives at off+4..off+6 and is
            // mirrored back unchanged in the reply, so we use it as a port-equivalent
            // on both sides of the flow key.
            if icmp_type == ICMP_ECHO_REQUEST || icmp_type == ICMP_ECHO_REPLY {
                let id = u16::from_be_bytes([pkt[off + 4], pkt[off + 5]]);
                src_port = id;
                dst_port = id;
            }
        }
        _ => return None,
    }

    Some(Parsed {
        proto,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        tcp_flags,
        icmp_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_v6(proto: u8, src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; 40 + payload.len()];
        pkt[0] = 0x60;
        let plen = payload.len() as u16;
        pkt[4..6].copy_from_slice(&plen.to_be_bytes());
        pkt[6] = proto;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&src);
        pkt[24..40].copy_from_slice(&dst);
        pkt[40..].copy_from_slice(payload);
        pkt
    }

    fn tcp(sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&sport.to_be_bytes());
        t[2..4].copy_from_slice(&dport.to_be_bytes());
        // data offset = 5 (20 bytes), upper nibble of byte 12
        t[12] = 5 << 4;
        t[13] = flags;
        t
    }

    fn udp(sport: u16, dport: u16) -> Vec<u8> {
        let mut u = vec![0u8; 8];
        u[0..2].copy_from_slice(&sport.to_be_bytes());
        u[2..4].copy_from_slice(&dport.to_be_bytes());
        u
    }

    fn icmp_echo(typ: u8, id: u16) -> Vec<u8> {
        let mut i = vec![0u8; 8];
        i[0] = typ;
        i[4..6].copy_from_slice(&id.to_be_bytes());
        i
    }

    fn local() -> [u8; 16] {
        let mut a = [0u8; 16];
        a[0] = 0x02;
        a[15] = 0x01;
        a
    }

    fn peer() -> [u8; 16] {
        let mut a = [0u8; 16];
        a[0] = 0x02;
        a[15] = 0x02;
        a
    }

    fn fw(cfg: FirewallConfig) -> Firewall {
        Firewall::new(&cfg).unwrap()
    }

    fn enabled_cfg() -> FirewallConfig {
        FirewallConfig {
            enable: true,
            open_tcp: vec![],
            open_udp: vec![],
            open_all_for: vec![],
            allow_icmp_echo: true,
        }
    }

    #[test]
    fn tcp_outbound_then_inbound_passes() {
        let fw = fw(enabled_cfg());

        let out = build_v6(PROTO_TCP, local(), peer(), &tcp(40000, 80, TCP_FLAG_SYN));
        fw.observe_outbound(&out);

        let reply = build_v6(
            PROTO_TCP,
            peer(),
            local(),
            &tcp(80, 40000, TCP_FLAG_SYN | TCP_FLAG_ACK),
        );
        assert!(fw.check_inbound(&reply));
    }

    #[test]
    fn tcp_unsolicited_inbound_dropped() {
        let fw = fw(enabled_cfg());
        let pkt = build_v6(PROTO_TCP, peer(), local(), &tcp(40000, 22, TCP_FLAG_SYN));
        assert!(!fw.check_inbound(&pkt));
    }

    #[test]
    fn open_tcp_allows_syn_and_subsequent_packets() {
        let mut cfg = enabled_cfg();
        cfg.open_tcp = vec![22];
        let fw = fw(cfg);

        let syn = build_v6(PROTO_TCP, peer(), local(), &tcp(40000, 22, TCP_FLAG_SYN));
        assert!(fw.check_inbound(&syn));

        // Subsequent ACK from peer must hit conntrack.
        let ack = build_v6(PROTO_TCP, peer(), local(), &tcp(40000, 22, TCP_FLAG_ACK));
        assert!(fw.check_inbound(&ack));

        // Different port still dropped.
        let other = build_v6(PROTO_TCP, peer(), local(), &tcp(40001, 23, TCP_FLAG_SYN));
        assert!(!fw.check_inbound(&other));
    }

    #[test]
    fn tcp_inbound_ack_without_flow_dropped() {
        let mut cfg = enabled_cfg();
        cfg.open_tcp = vec![22];
        let fw = fw(cfg);

        let ack = build_v6(PROTO_TCP, peer(), local(), &tcp(40000, 22, TCP_FLAG_ACK));
        assert!(!fw.check_inbound(&ack));
    }

    #[test]
    fn open_all_for_bypass() {
        let mut cfg = enabled_cfg();
        // Whitelist a /64 covering the peer.
        cfg.open_all_for = vec!["200::/8".to_string()];
        let fw = fw(cfg);

        let pkt = build_v6(PROTO_TCP, peer(), local(), &tcp(40000, 9999, TCP_FLAG_SYN));
        assert!(fw.check_inbound(&pkt));
    }

    #[test]
    fn udp_round_trip() {
        let fw = fw(enabled_cfg());

        let out = build_v6(PROTO_UDP, local(), peer(), &udp(40000, 53));
        fw.observe_outbound(&out);

        let reply = build_v6(PROTO_UDP, peer(), local(), &udp(53, 40000));
        assert!(fw.check_inbound(&reply));
    }

    #[test]
    fn open_udp_allows_inbound() {
        let mut cfg = enabled_cfg();
        cfg.open_udp = vec![5353];
        let fw = fw(cfg);

        let pkt = build_v6(PROTO_UDP, peer(), local(), &udp(40000, 5353));
        assert!(fw.check_inbound(&pkt));

        let other = build_v6(PROTO_UDP, peer(), local(), &udp(40000, 5354));
        assert!(!fw.check_inbound(&other));
    }

    #[test]
    fn icmp_echo_default_allowed() {
        let fw = fw(enabled_cfg());
        let req = build_v6(
            PROTO_ICMPV6,
            peer(),
            local(),
            &icmp_echo(ICMP_ECHO_REQUEST, 7),
        );
        assert!(fw.check_inbound(&req));
    }

    #[test]
    fn icmp_echo_disabled() {
        let mut cfg = enabled_cfg();
        cfg.allow_icmp_echo = false;
        let fw = fw(cfg);

        let req = build_v6(
            PROTO_ICMPV6,
            peer(),
            local(),
            &icmp_echo(ICMP_ECHO_REQUEST, 7),
        );
        assert!(!fw.check_inbound(&req));
    }

    #[test]
    fn icmp_echo_reply_matches_outbound_request() {
        let mut cfg = enabled_cfg();
        cfg.allow_icmp_echo = false;
        let fw = fw(cfg);

        let req_out = build_v6(
            PROTO_ICMPV6,
            local(),
            peer(),
            &icmp_echo(ICMP_ECHO_REQUEST, 42),
        );
        fw.observe_outbound(&req_out);

        let reply_in = build_v6(
            PROTO_ICMPV6,
            peer(),
            local(),
            &icmp_echo(ICMP_ECHO_REPLY, 42),
        );
        assert!(fw.check_inbound(&reply_in));

        // Unrelated reply id is still rejected.
        let stray = build_v6(
            PROTO_ICMPV6,
            peer(),
            local(),
            &icmp_echo(ICMP_ECHO_REPLY, 99),
        );
        assert!(!fw.check_inbound(&stray));
    }

    #[test]
    fn icmp_error_always_allowed() {
        let mut cfg = enabled_cfg();
        cfg.allow_icmp_echo = false;
        let fw = fw(cfg);

        // Type 1 = Destination Unreachable
        let mut payload = vec![0u8; 8];
        payload[0] = 1;
        let pkt = build_v6(PROTO_ICMPV6, peer(), local(), &payload);
        assert!(fw.check_inbound(&pkt));
    }

    #[test]
    fn non_first_fragment_dropped_on_inbound() {
        // Fragment header with frag_offset != 0
        let mut payload = vec![0u8; 8];
        payload[0] = PROTO_TCP; // next header
        payload[1] = 0;
        // frag_offset = 1 → high 13 bits of u16 = 0b0000000000001000
        payload[2] = 0;
        payload[3] = 0b00001000;
        let pkt = build_v6(FRAGMENT, peer(), local(), &payload);
        let fw = fw(enabled_cfg());
        assert!(!fw.check_inbound(&pkt));
    }

    #[test]
    fn malformed_packet_dropped() {
        let fw = fw(enabled_cfg());
        // Too short
        assert!(!fw.check_inbound(&[0x60u8; 10]));
        // Wrong version
        let mut bad = vec![0u8; 60];
        bad[0] = 0x40;
        assert!(!fw.check_inbound(&bad));
    }

    #[test]
    fn invalid_open_all_for_rejected() {
        let cfg = FirewallConfig {
            enable: true,
            open_tcp: vec![],
            open_udp: vec![],
            open_all_for: vec!["not a cidr".to_string()],
            allow_icmp_echo: true,
        };
        assert!(Firewall::new(&cfg).is_err());
    }

    #[test]
    fn ipv4_open_all_for_rejected() {
        let cfg = FirewallConfig {
            enable: true,
            open_tcp: vec![],
            open_udp: vec![],
            open_all_for: vec!["10.0.0.0/8".to_string()],
            allow_icmp_echo: true,
        };
        assert!(Firewall::new(&cfg).is_err());
    }

    #[test]
    fn gc_evicts_stale() {
        let fw = fw(enabled_cfg());
        let key = FlowKey {
            proto: PROTO_UDP,
            our_ip: local(),
            our_port: 40000,
            peer_ip: peer(),
            peer_port: 53,
        };
        {
            let mut t = fw.table.lock().unwrap();
            t.insert(
                key,
                FlowEntry {
                    last_seen: Instant::now() - Duration::from_secs(120),
                    tcp_state: None,
                },
            );
        }
        fw.gc();
        let t = fw.table.lock().unwrap();
        assert!(t.is_empty());
    }
}
