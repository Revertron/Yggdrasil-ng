// TUN is not supported on Android (handled at the OS/framework level).
// This module only compiles for non-Android targets.
#![cfg(not(target_os = "android"))]

use std::net::Ipv6Addr;
use std::sync::Arc;

use tokio::sync::mpsc;
use tun_rs::AsyncDevice;

use crate::ipv6rwc::ReadWriteCloser;

/// TUN adapter: bridges a TUN network device with the IPv6 RWC.
pub struct TunAdapter {
    _read_handle: tokio::task::JoinHandle<()>,
    _queue_handle: tokio::task::JoinHandle<()>,
    _write_handle: tokio::task::JoinHandle<()>,
}

impl TunAdapter {
    /// Create and start the TUN adapter.
    /// `name`: interface name ("auto" for automatic, "none" to disable)
    /// `rwc`: the IPv6 ReadWriteCloser bridge
    /// `addr`: the Yggdrasil IPv6 address string
    /// `subnet`: the /64 subnet string (for routing)
    /// `mtu`: the MTU for the TUN interface
    pub async fn new(
        name: &str,
        rwc: Arc<ReadWriteCloser>,
        addr: &str,
        _subnet: &str,
        mtu: u16,
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
        let mut builder = tun_rs::DeviceBuilder::new()
            .name(tun_name)
            .ipv6(ip, 7u8)
            .mtu(mtu);

        // Only call device_guid on Windows
        if cfg!(windows) {
            #[cfg(windows)]
            {
                builder = builder.device_guid(0x8f59971a78724aa6b2eb061fc4e9d0a7);
            }
        }

        let device = builder
            .build_async()
            .map_err(|e| format!("failed to create TUN device: {}", e))?;

        let device = Arc::new(device);

        tracing::info!("TUN device '{}' created with address {} and MTU {}", tun_name, addr, mtu);

        // Channel for packets from network → TUN
        let (tx, rx) = mpsc::channel::<Vec<u8>>(256);

        // Task 1: TUN → network (read from TUN, write to RWC)
        let device_read = device.clone();
        let rwc_read = rwc.clone();
        let read_handle = tokio::spawn(async move {
            tun_read_loop(device_read, rwc_read).await;
        });

        // Task 2: network → channel (read from RWC, send to channel)
        let rwc_queue = rwc.clone();
        let queue_handle = tokio::spawn(async move {
            tun_queue_loop(rwc_queue, tx).await;
        });

        // Task 3: channel → TUN (receive from channel, write to TUN)
        let device_write = device.clone();
        let write_handle = tokio::spawn(async move {
            tun_write_loop(device_write, rx).await;
        });

        Ok(Self {
            _read_handle: read_handle,
            _queue_handle: queue_handle,
            _write_handle: write_handle,
        })
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

/// Read packets from the network (RWC) and send them to the channel.
async fn tun_queue_loop(rwc: Arc<ReadWriteCloser>, tx: mpsc::Sender<Vec<u8>>) {
    loop {
        let mut buf = vec![0u8; 65535];
        match rwc.read(&mut buf).await {
            Ok(n) => {
                tracing::debug!("TUN read {} bytes, version={:#x}", n, buf[0] >> 4);
                buf.truncate(n);
                if tx.send(buf).await.is_err() {
                    tracing::error!("TUN queue channel closed");
                    return;
                }
            }
            Err(e) => {
                tracing::error!("Exiting TUN queue due to read error: {}", e);
                return;
            }
        }
    }
}

/// Receive packets from the channel and write them to the TUN device.
async fn tun_write_loop(
    device: Arc<AsyncDevice>,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    while let Some(packet) = rx.recv().await {
        tracing::debug!("TUN write {} bytes", packet.len());
        if let Err(e) = device.send(&packet).await {
            tracing::error!("TUN write error: {}", e);
            return;
        }
    }
}
