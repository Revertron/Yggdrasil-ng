//! smoltcp device backed by in-memory packet queues.
//!
//! The driver fills `rx` with IPv6 packets read from the node and drains `tx`
//! into the node after every interface poll.

use std::collections::VecDeque;

use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

/// Upper bound on packets queued for transmission between two drains. When
/// hit, smoltcp holds further egress until the driver has flushed the queue.
const TX_QUEUE_LIMIT: usize = 1024;

pub(crate) struct QueueDevice {
    pub(crate) rx: VecDeque<Vec<u8>>,
    pub(crate) tx: Vec<Vec<u8>>,
    mtu: usize,
}

impl QueueDevice {
    pub(crate) fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: Vec::new(),
            mtu,
        }
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((RxToken(packet), TxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.tx.len() >= TX_QUEUE_LIMIT {
            return None;
        }
        Some(TxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub(crate) struct RxToken(Vec<u8>);

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

pub(crate) struct TxToken<'a>(&'a mut Vec<Vec<u8>>);

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        self.0.push(packet);
        result
    }
}
