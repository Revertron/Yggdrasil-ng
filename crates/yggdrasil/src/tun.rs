// TUN support is behind the "tun" feature (enabled by default).
// Disable it with --no-default-features for library/VpnService builds.
#![cfg(feature = "tun")]

#[cfg(feature = "ckr")]
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;

use tun_rs::AsyncDevice;

use crate::ipv6rwc::ReadWriteCloser;

/// TUN adapter: bridges a TUN network device with the IPv6 RWC.
pub struct TunAdapter {
    device: Arc<AsyncDevice>,
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
    /// `ckr_config`: optional CKR tunnel routing config (for route installation)
    pub async fn new(
        name: &str,
        rwc: Arc<ReadWriteCloser>,
        addr: &str,
        _subnet: &str,
        mtu: u16,
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
        #[allow(unused_mut)]
        let mut builder = tun_rs::DeviceBuilder::new()
            .name(tun_name)
            .ipv6(ip, 7u8)
            .mtu(mtu);

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
            builder = builder.device_guid(0x8f59971a78724aa6b2eb061fc4e9d0a7);
        }

        let device = builder
            .build_async()
            .map_err(|e| format!("failed to create TUN device: {}", e))?;

        let device = Arc::new(device);

        #[cfg(feature = "ckr")]
        for (v4_addr, v4_prefix) in ipv4_addrs {
            device
                .add_address_v4(v4_addr, v4_prefix)
                .map_err(|e| format!("failed to add IPv4 address to TUN: {}", e))?;
        }

        tracing::info!("TUN device '{}' created with address {} and MTU {}", tun_name, addr, mtu);

        // Install CKR routes if configured
        #[cfg(feature = "ckr")]
        if let Some(ckr_cfg) = ckr_config {
            if ckr_cfg.install_system_routes {
                if let Err(e) = crate::ckr::install_routes(ckr_cfg, tun_name, self_key) {
                    tracing::error!("Failed to install CKR routes: {}", e);
                }
            }
        }

        // Task 1: TUN → network (read from TUN, write to RWC)
        let device_read = device.clone();
        let rwc_read = rwc.clone();
        let read_handle = tokio::spawn(async move {
            tun_read_loop(device_read, rwc_read).await;
        });

        // Task 2: network → TUN (read from RWC directly into TUN; no intermediate queue)
        let device_write = device.clone();
        let rwc_write = rwc.clone();
        let write_handle = tokio::spawn(async move {
            tun_write_loop(device_write, rwc_write).await;
        });

        Ok(Self {
            device,
            read_handle,
            write_handle,
        })
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
        let TunAdapter { device, read_handle, write_handle } = self;
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

/// Read packets from the network (RWC) and write them straight into the TUN device.
async fn tun_write_loop(device: Arc<AsyncDevice>, rwc: Arc<ReadWriteCloser>) {
    let mut buf = vec![0u8; 65535];
    loop {
        match rwc.read(&mut buf).await {
            Ok(n) => {
                tracing::debug!("TUN write {} bytes, version={:#x}", n, buf[0] >> 4);
                if let Err(e) = device.send(&buf[..n]).await {
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
