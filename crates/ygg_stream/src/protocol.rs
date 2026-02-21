use crate::error::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

/// Protocol flags
pub const FLAG_SYN: u8 = 0x01; // Open stream
pub const FLAG_ACK: u8 = 0x02; // Acknowledge
pub const FLAG_FIN: u8 = 0x04; // Close stream gracefully
pub const FLAG_RST: u8 = 0x08; // Reset stream (abort)

/// Default flow control window size (256 KB)
pub const DEFAULT_WINDOW_SIZE: usize = 256 * 1024;

/// Maximum packet size (64 KB - 1 byte)
pub const MAX_PACKET_SIZE: usize = 65535;

/// Maximum data payload per packet (accounting for 7-byte header)
pub const MAX_DATA_SIZE: usize = MAX_PACKET_SIZE - 7;

/// Packet header size (stream_id + flags + length)
pub const HEADER_SIZE: usize = 7;

/// Protocol packet
///
/// Wire format:
/// ```text
/// [stream_id: u32][flags: u8][length: u16][data: bytes]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Stream identifier
    pub stream_id: u32,

    /// Control flags (SYN, ACK, FIN, RST)
    pub flags: u8,

    /// Data payload
    pub data: Vec<u8>,

    /// Receiver's available window size (for flow control)
    /// Encoded in flags byte when ACK flag is set
    pub window: usize,
}

impl Packet {
    /// Create a new packet
    pub fn new(stream_id: u32, flags: u8, data: Vec<u8>) -> Self {
        Self {
            stream_id,
            flags,
            data,
            window: DEFAULT_WINDOW_SIZE,
        }
    }

    /// Create a SYN packet to open a stream
    pub fn syn(stream_id: u32) -> Self {
        Self::new(stream_id, FLAG_SYN, Vec::new())
    }

    /// Create a SYN-ACK packet
    pub fn syn_ack(stream_id: u32) -> Self {
        Self::new(stream_id, FLAG_SYN | FLAG_ACK, Vec::new())
    }

    /// Create a data packet
    pub fn data(stream_id: u32, data: Vec<u8>) -> Self {
        Self::new(stream_id, 0, data)
    }

    /// Create a data + ACK packet
    pub fn data_ack(stream_id: u32, data: Vec<u8>, window: usize) -> Self {
        Self {
            stream_id,
            flags: FLAG_ACK,
            data,
            window,
        }
    }

    /// Create a FIN packet to close a stream
    pub fn fin(stream_id: u32) -> Self {
        Self::new(stream_id, FLAG_FIN, Vec::new())
    }

    /// Create a RST packet to reset a stream
    pub fn rst(stream_id: u32) -> Self {
        Self::new(stream_id, FLAG_RST, Vec::new())
    }

    /// Create an ACK packet with window update
    pub fn ack(stream_id: u32, window: usize) -> Self {
        Self {
            stream_id,
            flags: FLAG_ACK,
            data: Vec::new(),
            window,
        }
    }

    /// Check if packet has SYN flag
    pub fn is_syn(&self) -> bool {
        self.flags & FLAG_SYN != 0
    }

    /// Check if packet has ACK flag
    pub fn is_ack(&self) -> bool {
        self.flags & FLAG_ACK != 0
    }

    /// Check if packet has FIN flag
    pub fn is_fin(&self) -> bool {
        self.flags & FLAG_FIN != 0
    }

    /// Check if packet has RST flag
    pub fn is_rst(&self) -> bool {
        self.flags & FLAG_RST != 0
    }

    /// Encode packet to bytes
    ///
    /// Format: [stream_id: u32][flags: u8][length: u16][data]
    pub fn encode(&self) -> Result<Vec<u8>> {
        let data_len = self.data.len();
        if data_len > MAX_DATA_SIZE {
            return Err(Error::PacketTooLarge(data_len, MAX_DATA_SIZE));
        }

        let mut buf = BytesMut::with_capacity(HEADER_SIZE + data_len);

        // Write stream ID (4 bytes, big-endian)
        buf.put_u32(self.stream_id);

        // Write flags (1 byte)
        buf.put_u8(self.flags);

        // Write length (2 bytes, big-endian)
        buf.put_u16(data_len as u16);

        // Write data payload
        buf.put_slice(&self.data);

        Ok(buf.to_vec())
    }

    /// Decode packet from bytes
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_SIZE {
            return Err(Error::Protocol(format!(
                "Packet too short: {} bytes (expected at least {})",
                buf.len(),
                HEADER_SIZE
            )));
        }

        let mut cursor = std::io::Cursor::new(buf);

        // Read stream ID (4 bytes, big-endian)
        let stream_id = cursor.get_u32();

        // Read flags (1 byte)
        let flags = cursor.get_u8();

        // Read length (2 bytes, big-endian)
        let length = cursor.get_u16() as usize;

        // Validate length matches remaining data
        let remaining = buf.len() - HEADER_SIZE;
        if length != remaining {
            return Err(Error::Protocol(format!(
                "Length mismatch: header says {} bytes, but {} bytes available",
                length, remaining
            )));
        }

        // Read data payload
        let data = buf[HEADER_SIZE..].to_vec();

        Ok(Self {
            stream_id,
            flags,
            data,
            window: DEFAULT_WINDOW_SIZE,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_encode_decode() {
        let packet = Packet::new(42, FLAG_SYN | FLAG_ACK, b"hello".to_vec());
        let encoded = packet.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();

        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.flags, FLAG_SYN | FLAG_ACK);
        assert_eq!(decoded.data, b"hello");
    }

    #[test]
    fn test_packet_syn() {
        let packet = Packet::syn(123);
        assert_eq!(packet.stream_id, 123);
        assert!(packet.is_syn());
        assert!(!packet.is_ack());
        assert!(!packet.is_fin());
        assert!(!packet.is_rst());
        assert!(packet.data.is_empty());
    }

    #[test]
    fn test_packet_syn_ack() {
        let packet = Packet::syn_ack(456);
        assert_eq!(packet.stream_id, 456);
        assert!(packet.is_syn());
        assert!(packet.is_ack());
        assert!(!packet.is_fin());
        assert!(!packet.is_rst());
    }

    #[test]
    fn test_packet_data() {
        let packet = Packet::data(789, b"test data".to_vec());
        assert_eq!(packet.stream_id, 789);
        assert!(!packet.is_syn());
        assert!(!packet.is_ack());
        assert!(!packet.is_fin());
        assert!(!packet.is_rst());
        assert_eq!(packet.data, b"test data");
    }

    #[test]
    fn test_packet_fin() {
        let packet = Packet::fin(111);
        assert_eq!(packet.stream_id, 111);
        assert!(packet.is_fin());
        assert!(!packet.is_syn());
        assert!(!packet.is_ack());
        assert!(!packet.is_rst());
    }

    #[test]
    fn test_packet_rst() {
        let packet = Packet::rst(222);
        assert_eq!(packet.stream_id, 222);
        assert!(packet.is_rst());
        assert!(!packet.is_syn());
        assert!(!packet.is_ack());
        assert!(!packet.is_fin());
    }

    #[test]
    fn test_packet_too_large() {
        let data = vec![0u8; MAX_DATA_SIZE + 1];
        let packet = Packet::new(1, 0, data);
        assert!(matches!(
            packet.encode(),
            Err(Error::PacketTooLarge(_, _))
        ));
    }

    #[test]
    fn test_decode_invalid_length() {
        // Create packet with mismatched length field
        let mut buf = BytesMut::new();
        buf.put_u32(1); // stream_id
        buf.put_u8(0); // flags
        buf.put_u16(100); // length says 100 bytes
        buf.put_slice(b"short"); // but only 5 bytes of data

        assert!(matches!(
            Packet::decode(&buf),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn test_decode_too_short() {
        let buf = vec![0u8; 3]; // Less than HEADER_SIZE
        assert!(matches!(
            Packet::decode(&buf),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn test_packet_with_large_data() {
        let data = vec![0xAB; 1000];
        let packet = Packet::data(999, data.clone());
        let encoded = packet.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();

        assert_eq!(decoded.stream_id, 999);
        assert_eq!(decoded.data.len(), 1000);
        assert_eq!(decoded.data, data);
    }

    #[test]
    fn test_packet_empty_data() {
        let packet = Packet::new(1, FLAG_ACK, Vec::new());
        let encoded = packet.encode().unwrap();
        assert_eq!(encoded.len(), HEADER_SIZE);

        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(decoded.stream_id, 1);
        assert!(decoded.is_ack());
        assert!(decoded.data.is_empty());
    }
}
