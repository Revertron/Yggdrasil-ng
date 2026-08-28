// TUN support is behind the "tun" feature (enabled by default).
// Disable it with --no-default-features for library/VpnService builds.
#![cfg(feature = "tun")]

#[cfg(feature = "ckr")]
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::sync::OnceLock;

use tun_rs::AsyncDevice;
#[cfg(target_os = "linux")]
use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

use crate::ipv6rwc::ReadWriteCloser;

/// Fixed GUID we register the wintun adapter with. Reused to target the same
/// interface when assigning DNS servers via `SetInterfaceDnsSettings`.
#[cfg(windows)]
const TUN_DEVICE_GUID: u128 = 0x8f59971a78724aa6b2eb061fc4e9d0a7;

#[cfg(windows)]
static SET_INTERFACE_DNS_PTR: OnceLock<
    Option<
        unsafe extern "system" fn(
            windows::core::GUID,
            *const windows::Win32::NetworkManagement::IpHelper::DNS_INTERFACE_SETTINGS,
        ) -> windows::core::HRESULT,
    >,
> = OnceLock::new();

/// TUN adapter: bridges a TUN network device with the IPv6 RWC.
pub struct TunAdapter {
    device: Arc<AsyncDevice>,
    /// Interface name assigned by the OS, which may differ from the requested one.
    name: String,
    /// MTU the interface ended up with, which the OS may have clamped.
    mtu: u16,
    /// Whether the kernel actually granted TSO/GSO on this device. Linux only;
    /// always false elsewhere.
    gso: bool,
    read_handle: tokio::task::JoinHandle<()>,
    write_handle: tokio::task::JoinHandle<()>,
}

impl TunAdapter {
    /// Create and start the TUN adapter.
    /// `name`: interface name ("auto" for automatic, "none" to disable)
    /// `rwc`: the IPv6 ReadWriteCloser bridge
    /// `addr`: the Yggdrasil IPv6 address string
    /// `subnet`: the /64 subnet string (for routing)
    /// `mtu`: the MTU for the TUN interface
    /// `gso`: enable TSO/GSO segmentation offload (Linux only)
    /// `dns_servers`: DNS server IPs to assign to the interface (Windows only)
    /// `ckr_config`: optional CKR tunnel routing config (for route installation)
    // Argument count is platform-dependent: the cfg'd knobs push it past the
    // clippy threshold on Linux.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        name: &str,
        rwc: Arc<ReadWriteCloser>,
        addr: &str,
        _subnet: &str,
        mtu: u16,
        #[cfg(target_os = "linux")] gso: bool,
        #[cfg(windows)] dns_servers: &[String],
        #[cfg(feature = "ckr")] ckr_config: Option<&crate::config::TunnelRoutingConfig>,
        #[cfg(feature = "ckr")] self_key: &[u8; 32],
    ) -> Result<Self, String> {
        if name == "none" {
            return Err("TUN disabled".to_string());
        }

        let tun_name = if name == "auto" {
            if cfg!(windows) {
                "Yggdrasil"
            } else {
                "ygg0"
            }
        } else {
            name
        };

        // Parse the address - strip any /prefix and get just the IP
        let ip_str = addr.split('/').next().unwrap_or(addr);
        let ip: Ipv6Addr = ip_str
            .parse()
            .map_err(|e| format!("invalid address '{}': {}", ip_str, e))?;

        // Create TUN device using tun-rs DeviceBuilder
        let mut builder = tun_rs::DeviceBuilder::new().ipv6(ip, 7u8).mtu(mtu);

        // macOS only accepts utunN names and assigns the index itself, so
        // "auto" cannot map to a fixed name there.
        if !(cfg!(target_os = "macos") && name == "auto") {
            builder = builder.name(tun_name);
        }

        // Assign IPv4 address to TUN if configured in CKR
        #[cfg(feature = "ckr")]
        if let Some(ckr_cfg) = ckr_config {
            if ckr_cfg.enable && !ckr_cfg.ipv4_address.is_empty() && ckr_cfg.ip_addresses.iter().all(|s| s.is_empty()) {
                let (v4_addr, v4_prefix) = parse_ipv4_cidr(&ckr_cfg.ipv4_address)?;
                builder = builder.ipv4(v4_addr, v4_prefix, None);
                tracing::info!("CKR: assigning IPv4 address {} to TUN", ckr_cfg.ipv4_address);
            }
        }

        #[cfg(feature = "ckr")]
        let mut ipv4_addrs: Vec<(Ipv4Addr, u8)> = Vec::new();

        // Assign IP addresses to TUN if configured in CKR
        #[cfg(feature = "ckr")]
        if let Some(ckr_cfg) = ckr_config {
            for cidr in &ckr_cfg.ip_addresses {
                if ckr_cfg.enable && !cidr.is_empty() {
                    if cidr.contains(':') {
                        // IPv6 path - reuse the same split/parse pattern already present 
                        // in parse_ipv4_cidr and the existing Yggdrasil IPv6 handling above
                        let parts: Vec<&str> = cidr.split('/').collect();
                        if parts.len() == 1 || parts.len() == 2 {
                            let ip_str = parts[0];
                            let prefix: u8 = if parts.len() == 1 {
                                128
                            } else {
                                parts[1].parse().map_err(|e| format!("invalid IPv6 prefix in ip_addresses '{}': {}", cidr, e))?
                            };
                            let ip: Ipv6Addr = ip_str.parse().map_err(|e| format!("invalid IPv6 in ip_addresses '{}': {}", cidr, e))?;
                            builder = builder.ipv6(ip, prefix);
                            tracing::info!("CKR: assigning IPv6 address {} to TUN", cidr);
                        } else {
                            return Err(format!("invalid IPv6 CIDR in ip_addresses '{}': expected addr or addr/prefix", cidr));
                        }
                    } else {
                        // IPv4 path - reuse the exact existing parse_ipv4_cidr function
                        let (v4_addr, v4_prefix) = parse_ipv4_cidr(cidr)?;
                        ipv4_addrs.push((v4_addr, v4_prefix));
                        tracing::info!("CKR: assigning IPv4 address {} to TUN", cidr);
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            // Only call device_guid on Windows
            builder = builder.device_guid(TUN_DEVICE_GUID);
        }

        // Offload asks the kernel for IFF_VNET_HDR, so segmented buffers cross
        // the device in one read/write instead of one syscall per MTU-sized
        // packet. The kernel may still refuse the offload mask (pre-2.6, or a
        // restricted container); tun-rs then falls back to plain packet mode,
        // which `tcp_gso()` below reports.
        #[cfg(target_os = "linux")]
        if gso {
            builder = builder.offload(true);
        }

        let device = builder
            .build_async()
            .map_err(|e| format!("failed to create TUN device: {}", e))?;

        #[cfg(target_os = "linux")]
        let gso_enabled = {
            let granted = device.tcp_gso();
            if gso && !granted {
                tracing::warn!("if_gso is set but the kernel refused TUN offload; continuing without GSO");
            }
            granted
        };
        #[cfg(not(target_os = "linux"))]
        let gso_enabled = false;

        let device = Arc::new(device);

        #[cfg(feature = "ckr")]
        for (v4_addr, v4_prefix) in ipv4_addrs {
            device
                .add_address_v4(v4_addr, v4_prefix)
                .map_err(|e| format!("failed to add IPv4 address to TUN: {}", e))?;
        }

        let actual_name = device.name().unwrap_or_else(|_| tun_name.to_string());
        let actual_mtu = device.mtu().unwrap_or(mtu);
        tracing::info!(
            "TUN device '{}' created with address {} and MTU {} (GSO {})",
            actual_name,
            addr,
            actual_mtu,
            if gso_enabled { "enabled" } else { "disabled" }
        );

        // Install CKR routes if configured
        #[cfg(feature = "ckr")]
        if let Some(ckr_cfg) = ckr_config {
            if ckr_cfg.install_system_routes {
                if let Err(e) = crate::ckr::install_routes(ckr_cfg, &actual_name, self_key) {
                    tracing::error!("Failed to install CKR routes: {}", e);
                }
            }
        }

        // Assign DNS servers to the interface (Windows only). Non-fatal on error.
        #[cfg(windows)]
        if !dns_servers.is_empty() {
            if is_set_interface_dns_settings_supported() {
                match set_interface_dns(dns_servers) {
                    Ok(()) => tracing::info!("Set DNS servers on TUN interface: {}", dns_servers.join(", ")),
                    Err(e) => tracing::error!("Failed to set DNS servers on TUN interface: {}", e),
                }
            } else {
                tracing::warn!(
                    "This Windows version does not support per-interface DNS settings \
                     (SetInterfaceDnsSettings not found in iphlpapi.dll), skipping"
                );
            }
        }

        // Task 1: TUN → network (read from TUN, write to RWC)
        // Task 2: network → TUN (read from RWC directly into TUN; no intermediate queue)
        // With offload granted the device speaks virtio headers and aggregated
        // buffers, so both directions take the recv_multiple/send_multiple path
        // instead.
        let device_read = device.clone();
        let rwc_read = rwc.clone();
        let device_write = device.clone();
        let rwc_write = rwc.clone();

        #[cfg(target_os = "linux")]
        let (read_handle, write_handle) = if gso_enabled {
            (
                tokio::spawn(async move { tun_read_loop_gso(device_read, rwc_read, actual_mtu).await }),
                tokio::spawn(async move { tun_write_loop_gso(device_write, rwc_write, actual_mtu).await }),
            )
        } else {
            (
                tokio::spawn(async move { tun_read_loop(device_read, rwc_read).await }),
                tokio::spawn(async move { tun_write_loop(device_write, rwc_write).await }),
            )
        };

        #[cfg(not(target_os = "linux"))]
        let (read_handle, write_handle) = (
            tokio::spawn(async move { tun_read_loop(device_read, rwc_read).await }),
            tokio::spawn(async move { tun_write_loop(device_write, rwc_write).await }),
        );

        Ok(Self {
            device,
            name: actual_name,
            mtu: actual_mtu,
            gso: gso_enabled,
            read_handle,
            write_handle,
        })
    }

    /// Interface name assigned by the OS.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// MTU the interface ended up with.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Whether TSO/GSO is active on this device.
    pub fn gso(&self) -> bool {
        self.gso
    }

    /// Tear down the TUN adapter explicitly: abort the I/O tasks, wait for
    /// them to drop their `Arc<AsyncDevice>` references, then drop the device
    /// so the OS-level interface is removed before this function returns.
    ///
    /// On Windows this is critical when running as a service: the SCM may
    /// terminate the process shortly after we report `ServiceState::Stopped`,
    /// before tokio's runtime drop has a chance to abort the I/O tasks. If
    /// the Wintun adapter isn't closed by then, it gets orphaned in the
    /// device tree and the next startup can't recreate it.
    pub async fn close(self) {
        let TunAdapter { device, read_handle, write_handle, .. } = self;
        read_handle.abort();
        write_handle.abort();
        let _ = read_handle.await;
        let _ = write_handle.await;
        // Tasks have released their Arc clones; drop the last one so
        // AsyncDevice::Drop runs WintunCloseAdapter (or platform equivalent).
        drop(device);
    }
}

/// Read packets from the TUN device and send them to the network via RWC.
async fn tun_read_loop(device: Arc<AsyncDevice>, rwc: Arc<ReadWriteCloser>) {
    let mut buf = vec![0u8; 65535];
    loop {
        match device.recv(&mut buf).await {
            Ok(n) if n > 0 => {
                if let Err(e) = rwc.write(&buf[..n]).await {
                    tracing::trace!("Unable to send packet to network: {}", e);
                }
            }
            Ok(_) => continue,
            Err(e) => {
                tracing::error!("TUN read error: {}", e);
                return;
            }
        }
    }
}

/// Batch buffers each direction is allowed to hold, in bytes. The batch is
/// sized from this and the MTU rather than always taking `IDEAL_BATCH_SIZE`
/// slots: with the default 65535-byte MTU that would reserve 8 MiB per
/// direction.
#[cfg(target_os = "linux")]
const GSO_BATCH_BUDGET: usize = 1 << 20;

/// Largest packet an offloaded write may coalesce into, plus the virtio header
/// in front of it and the same again in slack, which is what the GRO coalescer
/// requires of a buffer's capacity before it will merge into it.
#[cfg(target_os = "linux")]
const GSO_WRITE_BUF_CAP: usize = 2 * VIRTIO_NET_HDR_LEN + 65535;

/// Number of batch slots for `mtu`-sized packets under the budget above,
/// never fewer than the `65535 / mtu` segments a single aggregate can split
/// into and never more than the batch size the kernel is happy with.
#[cfg(target_os = "linux")]
fn gso_batch_size(mtu: u16, slot_bytes: usize) -> usize {
    let min_slots = 65535 / mtu.max(1) as usize + 2;
    (GSO_BATCH_BUDGET / slot_bytes).clamp(min_slots, IDEAL_BATCH_SIZE.max(min_slots))
}

/// Read from the TUN device with GRO enabled: a single read yields one virtio
/// header plus a possibly-aggregated buffer, which is split back into
/// individual IP packets before being handed to the RWC.
///
/// Linux-only; only spawned when the kernel granted the offload mask.
#[cfg(target_os = "linux")]
async fn tun_read_loop_gso(device: Arc<AsyncDevice>, rwc: Arc<ReadWriteCloser>, mtu: u16) {
    let slot = mtu.max(1) as usize;
    let batch = gso_batch_size(mtu, slot);
    // Holds the virtio header and the un-split aggregate the kernel hands over.
    let mut aggregate = vec![0u8; VIRTIO_NET_HDR_LEN + 65535];
    // Receives the individual packets the aggregate splits into.
    let mut bufs: Vec<Vec<u8>> = vec![vec![0u8; slot]; batch];
    let mut sizes = vec![0usize; batch];

    loop {
        match device
            .recv_multiple(&mut aggregate, &mut bufs, &mut sizes, 0)
            .await
        {
            Ok(count) => {
                for (buf, &len) in bufs.iter().zip(sizes.iter()).take(count) {
                    if len == 0 {
                        continue;
                    }
                    if let Err(e) = rwc.write(&buf[..len]).await {
                        tracing::trace!("Unable to send packet to network: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("TUN read error: {}", e);
                return;
            }
        }
    }
}

/// A batch slot for the offloaded write path.
///
/// The packet body sits at `VIRTIO_NET_HDR_LEN`, leaving the coalescer room to
/// write the virtio header in front of it, and `len` tracks how much of the
/// slot is live. The backing `Vec` keeps its full length between packets, so
/// reusing a slot costs an integer assignment instead of the memset that
/// growing a `Vec` back to MTU size would cost on every packet.
#[cfg(target_os = "linux")]
struct GsoWriteBuf {
    data: Vec<u8>,
    len: usize,
}

#[cfg(target_os = "linux")]
impl GsoWriteBuf {
    fn new() -> Self {
        Self {
            data: vec![0u8; GSO_WRITE_BUF_CAP],
            len: 0,
        }
    }
}

#[cfg(target_os = "linux")]
impl AsRef<[u8]> for GsoWriteBuf {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

#[cfg(target_os = "linux")]
impl AsMut<[u8]> for GsoWriteBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}

#[cfg(target_os = "linux")]
impl tun_rs::ExpandBuffer for GsoWriteBuf {
    fn buf_capacity(&self) -> usize {
        self.data.capacity()
    }

    fn buf_resize(&mut self, new_len: usize, value: u8) {
        if new_len > self.data.len() {
            self.data.resize(new_len, value);
        }
        self.len = new_len;
    }

    fn buf_extend_from_slice(&mut self, src: &[u8]) {
        let end = self.len + src.len();
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        self.data[self.len..end].copy_from_slice(src);
        self.len = end;
    }
}

/// Place a packet the RWC returned into `slot`, positioned so its body starts
/// at `VIRTIO_NET_HDR_LEN`.
///
/// The RWC returns the packet as a subslice of the buffer it was given —
/// currently one byte in, past the session type byte — which is why the buffer
/// is offered starting one byte early. Should it ever land somewhere else, the
/// packet is moved into place rather than the offset being guessed.
#[cfg(target_os = "linux")]
fn place_packet(slot_data: &mut [u8], start: usize, len: usize) -> usize {
    if start != VIRTIO_NET_HDR_LEN {
        slot_data.copy_within(start..start + len, VIRTIO_NET_HDR_LEN);
    }
    VIRTIO_NET_HDR_LEN + len
}

/// Read one packet from the RWC into `slot`, waiting for one to arrive.
#[cfg(target_os = "linux")]
async fn read_packet_into_slot(
    rwc: &ReadWriteCloser,
    slot: &mut GsoWriteBuf,
) -> Result<(), String> {
    let base = slot.data.as_ptr() as usize;
    let packet = rwc.read(&mut slot.data[VIRTIO_NET_HDR_LEN - 1..]).await?;
    let (start, len) = (packet.as_ptr() as usize - base, packet.len());
    slot.len = place_packet(&mut slot.data, start, len);
    Ok(())
}

/// Read a packet into `slot` only if the RWC already has one, reporting
/// whether it did. Never waits for the network.
#[cfg(target_os = "linux")]
async fn try_read_packet_into_slot(
    rwc: &ReadWriteCloser,
    slot: &mut GsoWriteBuf,
) -> Result<bool, String> {
    let base = slot.data.as_ptr() as usize;
    let Some(packet) = rwc.try_read(&mut slot.data[VIRTIO_NET_HDR_LEN - 1..]).await? else {
        return Ok(false);
    };
    let (start, len) = (packet.as_ptr() as usize - base, packet.len());
    slot.len = place_packet(&mut slot.data, start, len);
    Ok(true)
}

/// Write to the TUN device with GSO enabled: coalesce consecutive packets of
/// the same flow into one segmented buffer so the kernel does the splitting.
///
/// Linux-only; only spawned when the kernel granted the offload mask.
#[cfg(target_os = "linux")]
async fn tun_write_loop_gso(device: Arc<AsyncDevice>, rwc: Arc<ReadWriteCloser>, mtu: u16) {
    let batch = gso_batch_size(mtu, GSO_WRITE_BUF_CAP);
    let mut bufs: Vec<GsoWriteBuf> = (0..batch).map(|_| GsoWriteBuf::new()).collect();
    // Reused across batches; it only holds coalescing bookkeeping.
    let mut gro_table = GROTable::default();
    // Rate-limit overflow warnings so a sustained overload does not flood the log,
    // but count what happened in between so the warning says how bad it is.
    let mut last_overflow_log = Instant::now()
        .checked_sub(Duration::from_secs(60))
        .unwrap_or_else(Instant::now);
    let mut overflow_batches: u64 = 0;
    let mut at_risk_since_log: u64 = 0;
    const OVERFLOW_LOG_INTERVAL: Duration = Duration::from_secs(5);

    loop {
        // Wait for the first packet, then take only what is already queued
        // behind it: batching must never hold a packet back for a partner
        // that has not arrived yet.
        if let Err(e) = read_packet_into_slot(&rwc, &mut bufs[0]).await {
            tracing::error!("Exiting TUN write loop due to RWC read error: {}", e);
            return;
        }
        let mut count = 1;
        while count < bufs.len() {
            match try_read_packet_into_slot(&rwc, &mut bufs[count]).await {
                Ok(true) => count += 1,
                // Nothing else queued: send what we have rather than wait.
                Ok(false) => break,
                Err(e) => {
                    tracing::error!("Exiting TUN write loop due to RWC read error: {}", e);
                    return;
                }
            }
        }

        tracing::debug!("TUN write batch of {} packet(s)", count);
        match device
            .send_multiple(&mut gro_table, &mut bufs[..count], VIRTIO_NET_HDR_LEN)
            .await
        {
            Ok(_) => {}
            // `send_multiple` attempts every frame in the batch and reports
            // the last failure it saw, so an overflow means at least one of
            // these `count` packets was dropped — not that the batch was lost.
            // Report the batch as what it is, an upper bound, rather than
            // inflating the count by the packets that did get through.
            Err(e) if is_tun_write_overflow(&e) => {
                // Drop on overflow: better to lose some packets under load
                // than to stop delivering traffic entirely.
                overflow_batches += 1;
                at_risk_since_log += count as u64;
                let now = Instant::now();
                if now.duration_since(last_overflow_log) >= OVERFLOW_LOG_INTERVAL {
                    tracing::warn!(
                        "TUN write overflow in {} batch(es), up to {} packet(s) dropped \
                         since last report: {}",
                        overflow_batches,
                        at_risk_since_log,
                        e
                    );
                    last_overflow_log = now;
                    overflow_batches = 0;
                    at_risk_since_log = 0;
                }
                continue;
            }
            Err(e) => {
                tracing::error!("TUN write error: {}", e);
                return;
            }
        }
    }
}

/// Returns true for transient TUN write failures caused by kernel buffer exhaustion
/// (ENOBUFS / WouldBlock, and EQFULL on Apple). In these cases the packet should
/// be dropped instead of tearing down the write path.
#[cfg(unix)]
fn is_tun_write_overflow(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    match err.raw_os_error() {
        Some(code) if code == libc::ENOBUFS => true,
        // macOS-only: the interface output queue is full.
        #[cfg(target_vendor = "apple")]
        Some(code) if code == libc::EQFULL => true,
        _ => false,
    }
}

/// Windows counterpart: wintun reports a full ring buffer as ERROR_BUFFER_OVERFLOW,
/// which tun-rs translates into `ErrorKind::WouldBlock`. Its blocking send swallows
/// that internally and retries with backoff for 5 seconds before giving up with
/// `ErrorKind::TimedOut`, so in practice a full ring reaches us as the latter. A
/// disabled adapter surfaces as a different error, so it still tears down the loop.
#[cfg(not(unix))]
fn is_tun_write_overflow(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Read packets from the network (RWC) and write them straight into the TUN device.
async fn tun_write_loop(device: Arc<AsyncDevice>, rwc: Arc<ReadWriteCloser>) {
    // One byte larger than the largest payload: the session frame is read in
    // place, so it needs room for the leading session type byte too.
    let mut buf = vec![0u8; 65536];
    // Rate-limit overflow warnings so a sustained overload does not flood the log,
    // but count the drops in between so the warning says how bad it actually is.
    let mut last_overflow_log = Instant::now()
        .checked_sub(Duration::from_secs(60))
        .unwrap_or_else(Instant::now);
    let mut dropped_since_log: u64 = 0;
    const OVERFLOW_LOG_INTERVAL: Duration = Duration::from_secs(5);

    loop {
        match rwc.read(&mut buf).await {
            Ok(packet) => {
                tracing::debug!("TUN write {} bytes, version={:#x}", packet.len(), packet[0] >> 4);
                if let Err(e) = device.send(packet).await {
                    if is_tun_write_overflow(&e) {
                        // Drop on overflow: better to lose some packets under load
                        // than to stop delivering traffic entirely.
                        dropped_since_log += 1;
                        let now = Instant::now();
                        if now.duration_since(last_overflow_log) >= OVERFLOW_LOG_INTERVAL {
                            tracing::warn!(
                                "TUN write overflow, dropped {} packet(s) since last report: {}",
                                dropped_since_log,
                                e
                            );
                            last_overflow_log = now;
                            dropped_since_log = 0;
                        }
                        continue;
                    }
                    tracing::error!("TUN write error: {}", e);
                    return;
                }
            }
            Err(e) => {
                tracing::error!("Exiting TUN write loop due to RWC read error: {}", e);
                return;
            }
        }
    }
}

/// Parse an IPv4 CIDR string like "10.99.0.1/24" into (Ipv4Addr, prefix_len).
#[cfg(feature = "ckr")]
fn parse_ipv4_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    let (addr_str, prefix_str) = if parts.len() == 1 {
        (parts[0], "32")
    } else if parts.len() == 2 {
        (parts[0], parts[1])
    } else {
        return Err(format!("invalid IPv4 CIDR '{}': expected addr or addr/prefix", cidr));
    };
    let addr: Ipv4Addr = addr_str
        .parse()
        .map_err(|e| format!("invalid IPv4 address '{}': {}", addr_str, e))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|e| format!("invalid prefix length '{}': {}", prefix_str, e))?;
    if prefix > 32 {
        return Err(format!("prefix length {} exceeds 32", prefix));
    }
    Ok((addr, prefix))
}

#[cfg(windows)]
fn get_set_interface_dns_settings_ptr() -> Option<
    unsafe extern "system" fn(
        windows::core::GUID,
        *const windows::Win32::NetworkManagement::IpHelper::DNS_INTERFACE_SETTINGS,
    ) -> windows::core::HRESULT,
> {
    *SET_INTERFACE_DNS_PTR.get_or_init(|| {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

        let dll_name: Vec<u16> = OsStr::new("iphlpapi.dll")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let hmod_result = unsafe { GetModuleHandleW(windows::core::PCWSTR(dll_name.as_ptr())) };
        let hmod = match hmod_result {
            Ok(h) => h,
            Err(_) => return None,
        };
        if hmod.is_invalid() {
            return None;
        }

        let proc_name = b"SetInterfaceDnsSettings\0";
        let proc = unsafe { GetProcAddress(hmod, windows::core::PCSTR(proc_name.as_ptr())) };
        proc.map(|addr| unsafe { std::mem::transmute(addr) })
    })
}

#[cfg(windows)]
fn is_set_interface_dns_settings_supported() -> bool {
    get_set_interface_dns_settings_ptr().is_some()
}

#[cfg(windows)]
fn call_set_interface_dns_settings(
    guid: windows::core::GUID,
    settings: *const windows::Win32::NetworkManagement::IpHelper::DNS_INTERFACE_SETTINGS,
) -> windows::core::Result<()> {
    match get_set_interface_dns_settings_ptr() {
        Some(func) => {
            let hr = unsafe { func(guid, settings) };
            if hr.is_ok() {
                Ok(())
            } else {
                Err(windows::core::Error::from(hr))
            }
        }
        None => Err(windows::core::Error::from(
            windows::Win32::Foundation::ERROR_PROC_NOT_FOUND,
        )),
    }
}

/// Assign DNS servers to our TUN interface via `SetInterfaceDnsSettings`, and
/// disable dynamic DNS registration for it. Targets the adapter by the fixed
/// GUID we registered it with.
#[cfg(windows)]
fn set_interface_dns(servers: &[String]) -> Result<(), String> {
    use std::net::IpAddr;
    use std::str::FromStr;

    // Same GUID we registered the wintun adapter with. tun-rs converts the u128
    // via GUID::from_u128, so this matches the interface GUID exactly.
    let guid = windows::core::GUID::from_u128(TUN_DEVICE_GUID);

    // SetInterfaceDnsSettings configures one address family per call, and IPv6
    // nameservers require the DNS_SETTING_IPV6 flag — without it the addresses are
    // parsed as IPv4 and the call fails with ERROR_INVALID_PARAMETER. Split by family.
    let mut v4: Vec<&str> = Vec::new();
    let mut v6: Vec<&str> = Vec::new();
    for s in servers {
        match IpAddr::from_str(s) {
            Ok(IpAddr::V4(_)) => v4.push(s),
            Ok(IpAddr::V6(_)) => v6.push(s),
            Err(_) => tracing::warn!("Ignoring invalid DNS server address: {}", s),
        }
    }

    apply_interface_dns(guid, &v4, false)?;
    apply_interface_dns(guid, &v6, true)?;

    // Disable dynamic DNS registration for the mesh interface: registering this
    // interface's address with the mesh DNS servers is pointless and only produces
    // repeated failing DDNS attempts.
    set_interface_registration(guid, false)?;
    Ok(())
}

/// Enable or disable dynamic DNS (DDNS) registration of the interface's addresses.
#[cfg(windows)]
fn set_interface_registration(guid: windows::core::GUID, enabled: bool) -> Result<(), String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
        DNS_SETTING_REGISTRATION_ENABLED,
    };

    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: DNS_SETTING_REGISTRATION_ENABLED as u64,
        RegistrationEnabled: if enabled { 1 } else { 0 },
        ..Default::default()
    };

    call_set_interface_dns_settings(guid, &settings as *const _)
        .map_err(|e| format!("SetInterfaceDnsSettings (registration): {}", e))
}

/// Set the nameserver list for a single address family on the interface.
/// `ipv6` selects the DNS_SETTING_IPV6 flag. No-op for an empty list.
#[cfg(windows)]
fn apply_interface_dns(guid: windows::core::GUID, addrs: &[&str], ipv6: bool) -> Result<(), String> {
    use windows::core::PWSTR;
    use windows::Win32::NetworkManagement::IpHelper::{
        DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
        DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
    };

    if addrs.is_empty() {
        return Ok(());
    }

    // Comma-separated, null-terminated UTF-16 nameserver list.
    // Must stay alive for the duration of the call below.
    let mut ns: Vec<u16> = addrs
        .join(",")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut flags = DNS_SETTING_NAMESERVER as u64;
    if ipv6 {
        flags |= DNS_SETTING_IPV6 as u64;
    }

    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: flags,
        NameServer: PWSTR(ns.as_mut_ptr()),
        ..Default::default()
    };

    call_set_interface_dns_settings(guid, &settings as *const _)
        .map_err(|e| format!("SetInterfaceDnsSettings (ipv6={}): {}", ipv6, e))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use tun_rs::ExpandBuffer;

    #[test]
    fn batch_covers_the_segments_one_aggregate_can_split_into() {
        for mtu in [1280u16, 1420, 1500, 9000, 65535] {
            let slot = mtu as usize;
            let batch = gso_batch_size(mtu, slot);
            assert!(
                batch > 65535 / slot,
                "mtu {mtu}: batch {batch} cannot hold a full aggregate"
            );
            assert!(batch * slot <= GSO_BATCH_BUDGET.max(slot * (65535 / slot + 2)));
        }
    }

    #[test]
    fn write_buf_tracks_length_without_reallocating() {
        let mut buf = GsoWriteBuf::new();
        let cap = buf.buf_capacity();

        buf.buf_resize(VIRTIO_NET_HDR_LEN + 100, 0);
        assert_eq!(buf.as_ref().len(), VIRTIO_NET_HDR_LEN + 100);

        buf.buf_extend_from_slice(&[7u8; 50]);
        assert_eq!(buf.as_ref().len(), VIRTIO_NET_HDR_LEN + 150);
        assert_eq!(&buf.as_ref()[VIRTIO_NET_HDR_LEN + 100..], &[7u8; 50]);

        // Reusing the slot for a shorter packet must not shrink the allocation.
        buf.buf_resize(VIRTIO_NET_HDR_LEN + 20, 0);
        assert_eq!(buf.as_ref().len(), VIRTIO_NET_HDR_LEN + 20);
        assert_eq!(buf.buf_capacity(), cap);
    }

    #[test]
    fn write_buf_has_room_for_a_fully_coalesced_frame() {
        // The GRO coalescer refuses to merge into a buffer whose capacity is
        // below `2 * offset + coalesced_len`.
        let buf = GsoWriteBuf::new();
        assert!(buf.buf_capacity() >= 2 * VIRTIO_NET_HDR_LEN + 65535);
    }
}
