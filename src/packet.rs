//! MeshCore wire format: `[header][transport codes 2x u16 LE, route 0/3][path_len][path][payload]`.

use crate::crypto::sha256;
use anyhow::{Result, bail};

pub const MAX_PATH_SIZE: usize = 64;
pub const MAX_PAYLOAD: usize = 184;

pub const ROUTE_TRANSPORT_FLOOD: u8 = 0;
pub const ROUTE_FLOOD: u8 = 1;
pub const ROUTE_DIRECT: u8 = 2;
pub const ROUTE_TRANSPORT_DIRECT: u8 = 3;

pub mod ptype {
    pub const REQ: u8 = 0x00;
    pub const RESPONSE: u8 = 0x01;
    pub const TXT_MSG: u8 = 0x02;
    pub const ACK: u8 = 0x03;
    pub const ADVERT: u8 = 0x04;
    pub const GRP_TXT: u8 = 0x05;
    pub const GRP_DATA: u8 = 0x06;
    pub const ANON_REQ: u8 = 0x07;
    pub const PATH: u8 = 0x08;
    pub const TRACE: u8 = 0x09;
    pub const MULTIPART: u8 = 0x0A;
    pub const CONTROL: u8 = 0x0B;
}

pub fn ptype_name(t: u8) -> String {
    match t {
        0x00 => "REQ".into(),
        0x01 => "RESPONSE".into(),
        0x02 => "TXT_MSG".into(),
        0x03 => "ACK".into(),
        0x04 => "ADVERT".into(),
        0x05 => "GRP_TXT".into(),
        0x06 => "GRP_DATA".into(),
        0x07 => "ANON_REQ".into(),
        0x08 => "PATH".into(),
        0x09 => "TRACE".into(),
        0x0A => "MULTIPART".into(),
        0x0B => "CONTROL".into(),
        0x0F => "RAW_CUSTOM".into(),
        n => format!("TYPE_{n:X}"),
    }
}

pub fn ptype_from_name(s: &str) -> Option<u8> {
    (0u8..16).find(|t| ptype_name(*t).eq_ignore_ascii_case(s))
}

pub fn route_name(r: u8) -> &'static str {
    match r {
        ROUTE_TRANSPORT_FLOOD => "transport_flood",
        ROUTE_FLOOD => "flood",
        ROUTE_DIRECT => "direct",
        _ => "transport_direct",
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub header: u8,
    pub transport_codes: Option<[u16; 2]>,
    /// Raw path_len byte: bits 0-5 hop count, bits 6-7 hash size - 1.
    pub path_len: u8,
    pub path: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn route(&self) -> u8 {
        self.header & 0x03
    }
    pub fn ptype(&self) -> u8 {
        (self.header >> 2) & 0x0F
    }
    pub fn version(&self) -> u8 {
        self.header >> 6
    }
    pub fn is_flood(&self) -> bool {
        matches!(self.route(), ROUTE_FLOOD | ROUTE_TRANSPORT_FLOOD)
    }
    pub fn path_hash_size(&self) -> usize {
        (self.path_len >> 6) as usize + 1
    }
    pub fn path_count(&self) -> usize {
        (self.path_len & 63) as usize
    }
    /// Path entries as hex strings (repeater hash prefixes).
    pub fn path_hashes(&self) -> Vec<String> {
        self.path.chunks(self.path_hash_size()).map(hex::encode).collect()
    }

    /// Packet hash used for duplicate suppression (firmware Packet::calculatePacketHash, 8 bytes).
    pub fn hash(&self) -> [u8; 8] {
        let t = [self.ptype()];
        let pl = [self.path_len];
        let h = if self.ptype() == ptype::TRACE { sha256(&[&t, &pl, &self.payload]) } else { sha256(&[&t, &self.payload]) };
        let mut o = [0u8; 8];
        o.copy_from_slice(&h[..8]);
        o
    }

    pub fn parse(raw: &[u8]) -> Result<Packet> {
        if raw.len() < 2 {
            bail!("frame too short");
        }
        let header = raw[0];
        let mut i = 1;
        let transport_codes = if matches!(header & 3, ROUTE_TRANSPORT_FLOOD | ROUTE_TRANSPORT_DIRECT) {
            if raw.len() < i + 5 {
                bail!("frame too short for transport codes");
            }
            let a = u16::from_le_bytes([raw[i], raw[i + 1]]);
            let b = u16::from_le_bytes([raw[i + 2], raw[i + 3]]);
            i += 4;
            Some([a, b])
        } else {
            None
        };
        let path_len = raw[i];
        i += 1;
        let size = (path_len >> 6) as usize + 1;
        if size == 4 {
            bail!("reserved path hash size");
        }
        let bl = (path_len & 63) as usize * size;
        if bl > MAX_PATH_SIZE {
            bail!("path too long ({bl} bytes)");
        }
        if raw.len() < i + bl + 1 {
            bail!("frame truncated (path {bl} bytes, no payload)");
        }
        let path = raw[i..i + bl].to_vec();
        i += bl;
        let payload = raw[i..].to_vec();
        if payload.len() > MAX_PAYLOAD {
            bail!("payload too long ({} bytes)", payload.len());
        }
        Ok(Packet { header, transport_codes, path_len, path, payload })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut o = vec![self.header];
        if let Some([a, b]) = self.transport_codes {
            o.extend(a.to_le_bytes());
            o.extend(b.to_le_bytes());
        }
        o.push(self.path_len);
        o.extend(&self.path);
        o.extend(&self.payload);
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        // flood ADVERT, 2 hops with 1-byte hashes
        let raw = [0x11, 0x02, 0xaa, 0xbb, 1, 2, 3];
        let p = Packet::parse(&raw).unwrap();
        assert_eq!(p.route(), ROUTE_FLOOD);
        assert_eq!(p.ptype(), ptype::ADVERT);
        assert_eq!(p.path_hashes(), vec!["aa", "bb"]);
        assert_eq!(p.payload, vec![1, 2, 3]);
        assert_eq!(p.encode(), raw);
        // transport flood, 1 hop with 2-byte hashes
        let raw = [0x14, 0x34, 0x12, 0x00, 0x00, 0x41, 0xaa, 0xbb, 9];
        let p = Packet::parse(&raw).unwrap();
        assert_eq!(p.transport_codes, Some([0x1234, 0]));
        assert_eq!(p.path_hashes(), vec!["aabb"]);
        assert_eq!(p.encode(), raw);
    }
}
