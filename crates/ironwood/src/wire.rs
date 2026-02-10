//! Wire protocol: message types, encoding, and decoding.
//!
//! Frame format: `length(uvarint) | type(u8) | payload`
//!
//! All variable-length integers use unsigned LEB128 (uvarint) encoding.
//! Paths are encoded as sequences of uvarint port numbers, terminated by 0.

use crate::crypto::{PublicKey, Sig, PUBLIC_KEY_SIZE, SIGNATURE_SIZE};
use crate::types::Error;

/// Port identifier for a peer link on the spanning tree.
pub(crate) type PeerPort = u64;

// ---------------------------------------------------------------------------
// Packet types
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PacketType {
    Dummy = 0,
    KeepAlive = 1,
    ProtoSigReq = 2,
    ProtoSigRes = 3,
    ProtoAnnounce = 4,
    ProtoBloomFilter = 5,
    ProtoPathLookup = 6,
    ProtoPathNotify = 7,
    ProtoPathBroken = 8,
    Traffic = 9,
}

impl TryFrom<u8> for PacketType {
    type Error = crate::types::Error;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Dummy),
            1 => Ok(Self::KeepAlive),
            2 => Ok(Self::ProtoSigReq),
            3 => Ok(Self::ProtoSigRes),
            4 => Ok(Self::ProtoAnnounce),
            5 => Ok(Self::ProtoBloomFilter),
            6 => Ok(Self::ProtoPathLookup),
            7 => Ok(Self::ProtoPathNotify),
            8 => Ok(Self::ProtoPathBroken),
            9 => Ok(Self::Traffic),
            _ => Err(crate::types::Error::UnrecognizedMessage),
        }
    }
}

// ---------------------------------------------------------------------------
// Uvarint helpers (unsigned LEB128, compatible with Go's encoding/binary)
// ---------------------------------------------------------------------------

/// Encode a u64 as uvarint, appending to `out`. Returns number of bytes written.
pub(crate) fn encode_uvarint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Decode a uvarint from the front of `data`. Returns (value, bytes_consumed).
/// Returns None if the data is insufficient or the varint is malformed.
pub(crate) fn decode_uvarint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if shift >= 63 && byte > 1 {
            return None; // overflow
        }
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
        if i >= 9 {
            return None; // too many bytes
        }
    }
    None // incomplete
}

/// Compute the encoded size of a uvarint.
pub(crate) fn uvarint_size(mut value: u64) -> usize {
    let mut size = 1;
    while value >= 0x80 {
        value >>= 7;
        size += 1;
    }
    size
}

// ---------------------------------------------------------------------------
// Path helpers (zero-terminated uvarint sequences)
// ---------------------------------------------------------------------------

/// Encode a path (slice of PeerPort) as zero-terminated uvarints.
pub(crate) fn encode_path(out: &mut Vec<u8>, path: &[PeerPort]) {
    for &port in path {
        encode_uvarint(out, port);
    }
    encode_uvarint(out, 0); // terminator
}

/// Compute the wire size of a path.
pub(crate) fn path_size(path: &[PeerPort]) -> usize {
    let mut size = 0;
    for &port in path {
        size += uvarint_size(port);
    }
    size += uvarint_size(0); // terminator
    size
}

/// Decode a zero-terminated path from `data`. Returns (path, bytes_consumed).
pub(crate) fn decode_path(data: &[u8]) -> Result<(Vec<PeerPort>, usize), Error> {
    let mut path = Vec::new();
    let mut offset = 0;
    loop {
        let (value, len) = decode_uvarint(&data[offset..]).ok_or(Error::Decode)?;
        offset += len;
        if value == 0 {
            break;
        }
        path.push(value);
    }
    Ok((path, offset))
}

// ---------------------------------------------------------------------------
// Decoder helper: reads from a &[u8] cursor
// ---------------------------------------------------------------------------

/// A cursor for decoding wire messages.
pub(crate) struct WireReader<'a> {
    data: &'a [u8],
}

impl<'a> WireReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn remaining(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Read the remaining bytes.
    pub fn rest(&self) -> &'a [u8] {
        self.data
    }

    pub fn read_uvarint(&mut self) -> Result<u64, Error> {
        let (value, len) = decode_uvarint(self.data).ok_or(Error::Decode)?;
        self.data = &self.data[len..];
        Ok(value)
    }

    pub fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        if self.data.len() < N {
            return Err(Error::Decode);
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.data[..N]);
        self.data = &self.data[N..];
        Ok(out)
    }

    pub fn read_public_key(&mut self) -> Result<PublicKey, Error> {
        self.read_fixed::<PUBLIC_KEY_SIZE>()
    }

    pub fn read_signature(&mut self) -> Result<Sig, Error> {
        self.read_fixed::<SIGNATURE_SIZE>()
    }

    pub fn read_path(&mut self) -> Result<Vec<PeerPort>, Error> {
        let (path, consumed) = decode_path(self.data)?;
        self.data = &self.data[consumed..];
        Ok(path)
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.data.len() < n {
            return Err(Error::Decode);
        }
        let out = &self.data[..n];
        self.data = &self.data[n..];
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Router signature request.
#[derive(Debug, Clone)]
pub(crate) struct SigReq {
    pub seq: u64,
    pub nonce: u64,
}

impl SigReq {
    pub fn size(&self) -> usize {
        uvarint_size(self.seq) + uvarint_size(self.nonce)
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_uvarint(out, self.seq);
        encode_uvarint(out, self.nonce);
    }

    pub fn decode(r: &mut WireReader) -> Result<Self, Error> {
        let seq = r.read_uvarint()?;
        let nonce = r.read_uvarint()?;
        Ok(Self { seq, nonce })
    }
}

/// Router signature response.
#[derive(Debug, Clone)]
pub(crate) struct SigRes {
    pub seq: u64,
    pub nonce: u64,
    pub port: PeerPort,
    pub psig: Sig,
}

impl SigRes {
    pub fn size(&self) -> usize {
        uvarint_size(self.seq) + uvarint_size(self.nonce) + uvarint_size(self.port) + SIGNATURE_SIZE
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_uvarint(out, self.seq);
        encode_uvarint(out, self.nonce);
        encode_uvarint(out, self.port);
        out.extend_from_slice(&self.psig);
    }

    pub fn decode(r: &mut WireReader) -> Result<Self, Error> {
        let seq = r.read_uvarint()?;
        let nonce = r.read_uvarint()?;
        let port = r.read_uvarint()?;
        let psig = r.read_signature()?;
        Ok(Self {
            seq,
            nonce,
            port,
            psig,
        })
    }
}

/// Router tree announcement.
#[derive(Debug, Clone)]
pub(crate) struct Announce {
    pub key: PublicKey,
    pub parent: PublicKey,
    pub sig_res: SigRes,
    pub sig: Sig,
}

impl Announce {
    pub fn size(&self) -> usize {
        PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE + self.sig_res.size() + SIGNATURE_SIZE
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.parent);
        self.sig_res.encode(out);
        out.extend_from_slice(&self.sig);
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut r = WireReader::new(data);
        let key = r.read_public_key()?;
        let parent = r.read_public_key()?;
        let sig_res = SigRes::decode(&mut r)?;
        let sig = r.read_signature()?;
        if !r.is_empty() {
            return Err(Error::Decode);
        }
        Ok(Self {
            key,
            parent,
            sig_res,
            sig,
        })
    }
}

/// Path lookup request.
#[derive(Debug, Clone)]
pub(crate) struct PathLookup {
    pub source: PublicKey,
    pub dest: PublicKey,
    pub from: Vec<PeerPort>,
}

impl PathLookup {
    pub fn size(&self) -> usize {
        PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE + path_size(&self.from)
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.dest);
        encode_path(out, &self.from);
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut r = WireReader::new(data);
        let source = r.read_public_key()?;
        let dest = r.read_public_key()?;
        let from = r.read_path()?;
        if !r.is_empty() {
            return Err(Error::Decode);
        }
        Ok(Self { source, dest, from })
    }
}

/// Signed path info (part of PathNotify).
#[derive(Debug, Clone)]
pub(crate) struct PathNotifyInfo {
    pub seq: u64,
    pub path: Vec<PeerPort>,
    pub sig: Sig,
}

impl PathNotifyInfo {
    pub fn size(&self) -> usize {
        uvarint_size(self.seq) + path_size(&self.path) + SIGNATURE_SIZE
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_uvarint(out, self.seq);
        encode_path(out, &self.path);
        out.extend_from_slice(&self.sig);
    }

    pub fn decode(r: &mut WireReader) -> Result<Self, Error> {
        let seq = r.read_uvarint()?;
        let path = r.read_path()?;
        let sig = r.read_signature()?;
        Ok(Self { seq, path, sig })
    }
}

/// Path notification (response to PathLookup).
#[derive(Debug, Clone)]
pub(crate) struct PathNotify {
    pub path: Vec<PeerPort>,
    pub watermark: u64,
    pub source: PublicKey,
    pub dest: PublicKey,
    pub info: PathNotifyInfo,
}

impl PathNotify {
    pub fn size(&self) -> usize {
        path_size(&self.path)
            + uvarint_size(self.watermark)
            + PUBLIC_KEY_SIZE
            + PUBLIC_KEY_SIZE
            + self.info.size()
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_path(out, &self.path);
        encode_uvarint(out, self.watermark);
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.dest);
        self.info.encode(out);
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut r = WireReader::new(data);
        let path = r.read_path()?;
        let watermark = r.read_uvarint()?;
        let source = r.read_public_key()?;
        let dest = r.read_public_key()?;
        let info = PathNotifyInfo::decode(&mut r)?;
        if !r.is_empty() {
            return Err(Error::Decode);
        }
        Ok(Self {
            path,
            watermark,
            source,
            dest,
            info,
        })
    }
}

/// Path broken notification.
#[derive(Debug, Clone)]
pub(crate) struct PathBroken {
    pub path: Vec<PeerPort>,
    pub watermark: u64,
    pub source: PublicKey,
    pub dest: PublicKey,
}

impl PathBroken {
    pub fn size(&self) -> usize {
        path_size(&self.path) + uvarint_size(self.watermark) + PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_path(out, &self.path);
        encode_uvarint(out, self.watermark);
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.dest);
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut r = WireReader::new(data);
        let path = r.read_path()?;
        let watermark = r.read_uvarint()?;
        let source = r.read_public_key()?;
        let dest = r.read_public_key()?;
        if !r.is_empty() {
            return Err(Error::Decode);
        }
        Ok(Self {
            path,
            watermark,
            source,
            dest,
        })
    }
}

/// User traffic packet.
#[derive(Debug, Clone)]
pub(crate) struct Traffic {
    pub path: Vec<PeerPort>,
    pub from: Vec<PeerPort>,
    pub source: PublicKey,
    pub dest: PublicKey,
    pub watermark: u64,
    pub payload: Vec<u8>,
}

impl Traffic {
    pub fn size(&self) -> usize {
        path_size(&self.path)
            + path_size(&self.from)
            + PUBLIC_KEY_SIZE
            + PUBLIC_KEY_SIZE
            + uvarint_size(self.watermark)
            + self.payload.len()
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_path(out, &self.path);
        encode_path(out, &self.from);
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.dest);
        encode_uvarint(out, self.watermark);
        out.extend_from_slice(&self.payload);
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut r = WireReader::new(data);
        let path = r.read_path()?;
        let from = r.read_path()?;
        let source = r.read_public_key()?;
        let dest = r.read_public_key()?;
        let watermark = r.read_uvarint()?;
        let payload = r.rest().to_vec();
        Ok(Self {
            path,
            from,
            source,
            dest,
            watermark,
            payload,
        })
    }
}

// ---------------------------------------------------------------------------
// Bloom filter wire encoding
// ---------------------------------------------------------------------------

/// Bloom filter constants matching the Go implementation.
pub(crate) const BLOOM_FILTER_FLAGS: usize = 16; // bytes for zero/one flags
pub(crate) const BLOOM_FILTER_U64S: usize = 128; // number of u64s in backing array
pub(crate) const BLOOM_FILTER_BYTES: usize = 1024; // total bytes
pub(crate) const BLOOM_FILTER_BITS: usize = 8192; // total bits
pub(crate) const BLOOM_FILTER_F: usize = 16; // BLOOM_FILTER_U64S / 8
pub(crate) const BLOOM_FILTER_K: usize = 8; // number of hash functions

/// Encode a bloom filter's backing u64 array with compression.
/// Format: [16 bytes: flags0 (all-zero chunks)][16 bytes: flags1 (all-one chunks)][remaining u64s in big-endian]
pub(crate) fn encode_bloom(out: &mut Vec<u8>, data: &[u64; BLOOM_FILTER_U64S]) {
    let mut flags0 = [0u8; BLOOM_FILTER_FLAGS];
    let mut flags1 = [0u8; BLOOM_FILTER_FLAGS];
    let mut keep = Vec::new();

    for (idx, &u) in data.iter().enumerate() {
        if u == 0 {
            flags0[idx / 8] |= 0x80 >> (idx % 8);
        } else if u == u64::MAX {
            flags1[idx / 8] |= 0x80 >> (idx % 8);
        } else {
            keep.push(u);
        }
    }

    out.extend_from_slice(&flags0);
    out.extend_from_slice(&flags1);
    for u in keep {
        out.extend_from_slice(&u.to_be_bytes());
    }
}

/// Decode a bloom filter from wire format.
pub(crate) fn decode_bloom(data: &[u8]) -> Result<[u64; BLOOM_FILTER_U64S], Error> {
    let mut r = WireReader::new(data);
    let flags0: [u8; BLOOM_FILTER_FLAGS] = r.read_fixed()?;
    let flags1: [u8; BLOOM_FILTER_FLAGS] = r.read_fixed()?;

    let mut result = [0u64; BLOOM_FILTER_U64S];
    for idx in 0..BLOOM_FILTER_U64S {
        let f0 = flags0[idx / 8] & (0x80 >> (idx % 8));
        let f1 = flags1[idx / 8] & (0x80 >> (idx % 8));

        if f0 != 0 && f1 != 0 {
            return Err(Error::Decode); // can't be both zero and all-ones
        } else if f0 != 0 {
            result[idx] = 0;
        } else if f1 != 0 {
            result[idx] = u64::MAX;
        } else {
            let bytes: [u8; 8] = r.read_fixed()?;
            result[idx] = u64::from_be_bytes(bytes);
        }
    }

    if !r.is_empty() {
        return Err(Error::Decode);
    }
    Ok(result)
}

/// Compute the wire size of a bloom filter.
pub(crate) fn bloom_wire_size(data: &[u64; BLOOM_FILTER_U64S]) -> usize {
    let mut size = BLOOM_FILTER_FLAGS * 2; // flags0 + flags1
    for &u in data.iter() {
        if u != 0 && u != u64::MAX {
            size += 8;
        }
    }
    size
}

// ---------------------------------------------------------------------------
// Frame-level encode/decode
// ---------------------------------------------------------------------------

/// Encode a complete wire frame: length(uvarint) | type(u8) | payload.
pub(crate) fn encode_frame(packet_type: PacketType, payload: &[u8]) -> Vec<u8> {
    let content_len = 1 + payload.len(); // type byte + payload
    let mut frame = Vec::with_capacity(uvarint_size(content_len as u64) + content_len);
    encode_uvarint(&mut frame, content_len as u64);
    frame.push(packet_type as u8);
    frame.extend_from_slice(payload);
    frame
}

/// Decode a frame header from the front of `data`.
/// Returns (packet_type, payload_slice, total_frame_bytes_consumed).
pub(crate) fn decode_frame(data: &[u8]) -> Result<(PacketType, &[u8], usize), Error> {
    let (length, len_bytes) = decode_uvarint(data).ok_or(Error::Decode)?;
    let length = length as usize;
    if data.len() < len_bytes + length {
        return Err(Error::Decode);
    }
    let content = &data[len_bytes..len_bytes + length];
    if content.is_empty() {
        return Err(Error::Decode);
    }
    let packet_type = PacketType::try_from(content[0])?;
    let payload = &content[1..];
    Ok((packet_type, payload, len_bytes + length))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uvarint_roundtrip() {
        for &val in &[0u64, 1, 127, 128, 255, 256, 16383, 16384, u64::MAX >> 1] {
            let mut buf = Vec::new();
            encode_uvarint(&mut buf, val);
            let (decoded, len) = decode_uvarint(&buf).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(len, buf.len());
            assert_eq!(len, uvarint_size(val));
        }
    }

    #[test]
    fn path_roundtrip() {
        let path = vec![1, 2, 300, 65535];
        let mut buf = Vec::new();
        encode_path(&mut buf, &path);
        assert_eq!(buf.len(), path_size(&path));
        let (decoded, consumed) = decode_path(&buf).unwrap();
        assert_eq!(decoded, path);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn empty_path_roundtrip() {
        let path: Vec<PeerPort> = vec![];
        let mut buf = Vec::new();
        encode_path(&mut buf, &path);
        let (decoded, _) = decode_path(&buf).unwrap();
        assert_eq!(decoded, path);
    }

    #[test]
    fn sig_req_roundtrip() {
        let req = SigReq {
            seq: 42,
            nonce: 123456789,
        };
        let mut buf = Vec::new();
        req.encode(&mut buf);
        assert_eq!(buf.len(), req.size());
        let mut r = WireReader::new(&buf);
        let decoded = SigReq::decode(&mut r).unwrap();
        assert_eq!(decoded.seq, 42);
        assert_eq!(decoded.nonce, 123456789);
        assert!(r.is_empty());
    }

    #[test]
    fn sig_res_roundtrip() {
        let res = SigRes {
            seq: 1,
            nonce: 2,
            port: 5,
            psig: [0xAB; 64],
        };
        let mut buf = Vec::new();
        res.encode(&mut buf);
        assert_eq!(buf.len(), res.size());
        let mut r = WireReader::new(&buf);
        let decoded = SigRes::decode(&mut r).unwrap();
        assert_eq!(decoded.seq, 1);
        assert_eq!(decoded.nonce, 2);
        assert_eq!(decoded.port, 5);
        assert_eq!(decoded.psig, [0xAB; 64]);
        assert!(r.is_empty());
    }

    #[test]
    fn announce_roundtrip() {
        let ann = Announce {
            key: [1u8; 32],
            parent: [2u8; 32],
            sig_res: SigRes {
                seq: 10,
                nonce: 20,
                port: 3,
                psig: [0xCC; 64],
            },
            sig: [0xDD; 64],
        };
        let mut buf = Vec::new();
        ann.encode(&mut buf);
        assert_eq!(buf.len(), ann.size());
        let decoded = Announce::decode(&buf).unwrap();
        assert_eq!(decoded.key, [1u8; 32]);
        assert_eq!(decoded.parent, [2u8; 32]);
        assert_eq!(decoded.sig_res.seq, 10);
        assert_eq!(decoded.sig, [0xDD; 64]);
    }

    #[test]
    fn traffic_roundtrip() {
        let tr = Traffic {
            path: vec![1, 2, 3],
            from: vec![4, 5],
            source: [0x11; 32],
            dest: [0x22; 32],
            watermark: 99,
            payload: b"hello world".to_vec(),
        };
        let mut buf = Vec::new();
        tr.encode(&mut buf);
        assert_eq!(buf.len(), tr.size());
        let decoded = Traffic::decode(&buf).unwrap();
        assert_eq!(decoded.path, vec![1, 2, 3]);
        assert_eq!(decoded.from, vec![4, 5]);
        assert_eq!(decoded.source, [0x11; 32]);
        assert_eq!(decoded.dest, [0x22; 32]);
        assert_eq!(decoded.watermark, 99);
        assert_eq!(decoded.payload, b"hello world");
    }

    #[test]
    fn path_lookup_roundtrip() {
        let lookup = PathLookup {
            source: [0xAA; 32],
            dest: [0xBB; 32],
            from: vec![10, 20, 30],
        };
        let mut buf = Vec::new();
        lookup.encode(&mut buf);
        assert_eq!(buf.len(), lookup.size());
        let decoded = PathLookup::decode(&buf).unwrap();
        assert_eq!(decoded.source, [0xAA; 32]);
        assert_eq!(decoded.dest, [0xBB; 32]);
        assert_eq!(decoded.from, vec![10, 20, 30]);
    }

    #[test]
    fn path_notify_roundtrip() {
        let notify = PathNotify {
            path: vec![1, 2],
            watermark: 7,
            source: [0x11; 32],
            dest: [0x22; 32],
            info: PathNotifyInfo {
                seq: 42,
                path: vec![3, 4, 5],
                sig: [0xFF; 64],
            },
        };
        let mut buf = Vec::new();
        notify.encode(&mut buf);
        assert_eq!(buf.len(), notify.size());
        let decoded = PathNotify::decode(&buf).unwrap();
        assert_eq!(decoded.path, vec![1, 2]);
        assert_eq!(decoded.watermark, 7);
        assert_eq!(decoded.info.seq, 42);
        assert_eq!(decoded.info.path, vec![3, 4, 5]);
    }

    #[test]
    fn path_broken_roundtrip() {
        let broken = PathBroken {
            path: vec![1],
            watermark: 0,
            source: [0x33; 32],
            dest: [0x44; 32],
        };
        let mut buf = Vec::new();
        broken.encode(&mut buf);
        assert_eq!(buf.len(), broken.size());
        let decoded = PathBroken::decode(&buf).unwrap();
        assert_eq!(decoded.path, vec![1]);
        assert_eq!(decoded.source, [0x33; 32]);
    }

    #[test]
    fn bloom_roundtrip() {
        let mut data = [0u64; BLOOM_FILTER_U64S];
        data[0] = 0;
        data[1] = u64::MAX;
        data[2] = 0xDEADBEEFCAFEBABE;
        data[127] = 42;

        let mut buf = Vec::new();
        encode_bloom(&mut buf, &data);
        assert_eq!(buf.len(), bloom_wire_size(&data));
        let decoded = decode_bloom(&buf).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn frame_roundtrip() {
        let payload = b"test payload";
        let frame = encode_frame(PacketType::Traffic, payload);
        let (ptype, decoded_payload, consumed) = decode_frame(&frame).unwrap();
        assert_eq!(ptype, PacketType::Traffic);
        assert_eq!(decoded_payload, payload);
        assert_eq!(consumed, frame.len());
    }
}
