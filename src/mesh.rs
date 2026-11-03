//! Packet builders for transmission (firmware Mesh.cpp / BaseChatMesh.cpp equivalents).

use crate::crypto::{self, Identity, sha256};
use crate::packet::{Packet, ROUTE_DIRECT, ROUTE_FLOOD, ptype};
use anyhow::{Result, bail};

/// Max DM / channel text length (firmware MAX_TEXT_LEN = 10 cipher blocks).
pub const MAX_TEXT_LEN: usize = 160;

/// Route for an outgoing packet.
#[derive(Debug, Clone)]
pub enum Route {
    /// Flood with empty path; `hash_size` = path hash bytes repeaters append (1-3).
    Flood { hash_size: u8 },
    /// Direct along a path (raw path_len byte and path bytes). path_len 0 = zero hop.
    Direct { path_len: u8, path: Vec<u8> },
}

impl Route {
    pub fn zero_hop() -> Route {
        Route::Direct { path_len: 0, path: vec![] }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Route::Flood { .. } => "flood",
            Route::Direct { path_len, .. } if path_len & 63 == 0 => "zero_hop",
            Route::Direct { .. } => "direct",
        }
    }
}

pub fn finish(t: u8, payload: Vec<u8>, route: &Route) -> Packet {
    let (r, path_len, path) = match route {
        Route::Flood { hash_size } => (ROUTE_FLOOD, (hash_size.clamp(&1, &3) - 1) << 6, vec![]),
        Route::Direct { path_len, path } => (ROUTE_DIRECT, *path_len, path.clone()),
    };
    Packet { header: (t << 2) | r, transport_codes: None, path_len, path, payload }
}

/// Advert app data: flags (type | 0x80 name | 0x10 location), [lat, lon i32 x1e6], name.
pub fn app_data(adv_type: u8, name: &str, loc: Option<(f64, f64)>) -> Vec<u8> {
    let mut flags = adv_type & 0x0F;
    if loc.is_some() {
        flags |= 0x10;
    }
    if !name.is_empty() {
        flags |= 0x80;
    }
    let mut a = vec![flags];
    if let Some((lat, lon)) = loc {
        a.extend(((lat * 1e6) as i32).to_le_bytes());
        a.extend(((lon * 1e6) as i32).to_le_bytes());
    }
    let room = 32 - a.len();
    let mut n = name.as_bytes().to_vec();
    n.truncate(room);
    a.extend(n);
    a
}

/// Signed advert: pubkey, timestamp, signature over (pubkey || timestamp || app_data), app_data.
pub fn advert(me: &Identity, timestamp: u32, app: &[u8], route: &Route) -> Packet {
    let mut msg = me.public.to_vec();
    msg.extend(timestamp.to_le_bytes());
    msg.extend(app);
    let sig = me.sign(&msg);
    let mut pl = me.public.to_vec();
    pl.extend(timestamp.to_le_bytes());
    pl.extend(sig);
    pl.extend(app);
    finish(ptype::ADVERT, pl, route)
}

/// Peer datagram (TXT_MSG / REQ / RESPONSE): dest hash, src hash, MAC + ciphertext.
pub fn datagram(t: u8, me: &Identity, peer: &[u8; 32], plain: &[u8], route: &Route) -> Result<Packet> {
    if plain.len() + crypto::MAC_SIZE + crypto::BLOCK - 1 > crate::packet::MAX_PAYLOAD {
        bail!("payload too long");
    }
    let secret = me.shared_secret(peer)?;
    let mut pl = vec![peer[0], me.public[0]];
    pl.extend(crypto::encrypt_then_mac(&secret, plain));
    Ok(finish(t, pl, route))
}

/// Plain text DM plaintext and the ACK code the recipient will return:
/// sha256(timestamp || flags || text, sender public key)[0..4] as LE u32 (firmware composeMsgPacket).
pub fn text_plain(me: &Identity, timestamp: u32, attempt: u8, text: &str) -> Result<(Vec<u8>, u32)> {
    if text.len() > MAX_TEXT_LEN {
        bail!("text longer than {MAX_TEXT_LEN} bytes");
    }
    let mut p = timestamp.to_le_bytes().to_vec();
    p.push(attempt & 3);
    p.extend(text.as_bytes());
    let h = sha256(&[&p, &me.public]);
    let ack = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
    if attempt > 3 {
        p.push(0);
        p.push(attempt);
    }
    Ok((p, ack))
}

/// ACK code for a received plain text message (sender = peer): sha256(data[0..5+text_len], peer key)[0..4].
pub fn ack_for_plain(plain: &[u8], peer: &[u8; 32]) -> u32 {
    let tl = plain[5..].iter().position(|&b| b == 0).unwrap_or(plain.len() - 5);
    let h = sha256(&[&plain[..5 + tl], peer]);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// ACK code for a received signed text message: sha256(data[0..9+text_len], our key)[0..4].
pub fn ack_for_signed(plain: &[u8], me: &Identity) -> u32 {
    let tl = plain[9..].iter().position(|&b| b == 0).unwrap_or(plain.len() - 9);
    let h = sha256(&[&plain[..9 + tl], &me.public]);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// 6-byte ACK body as firmware v1.18: crc (4), extended attempt byte, random byte.
pub fn ack_body(crc: u32, ext_attempt: u8) -> Vec<u8> {
    let mut b = crc.to_le_bytes().to_vec();
    b.push(ext_attempt);
    b.push(rand::random());
    b
}

pub fn ack(body: &[u8], route: &Route) -> Packet {
    finish(ptype::ACK, body.to_vec(), route)
}

/// PATH return to a peer: carries `path` (the route from the peer to us, as received) and optional
/// extra (type, data); without extra, 0xFF + 4 random bytes keep the packet hash unique.
pub fn path_return(me: &Identity, peer: &[u8; 32], path_len: u8, path: &[u8], extra: Option<(u8, &[u8])>, route: &Route) -> Result<Packet> {
    let mut d = vec![path_len];
    d.extend(path);
    match extra {
        Some((t, x)) => {
            d.push(t);
            d.extend(x);
        }
        None => {
            d.push(0xFF);
            d.extend(rand::random::<[u8; 4]>());
        }
    }
    datagram(ptype::PATH, me, peer, &d, route)
}

/// Channel text: timestamp, flags 0, "name: text".
pub fn group_text(secret: &[u8; 32], hash: u8, timestamp: u32, sender: &str, text: &str, route: &Route) -> Result<Packet> {
    let mut body = format!("{sender}: ").into_bytes();
    if body.len() + text.len() > MAX_TEXT_LEN {
        bail!("text longer than {} bytes (with sender prefix)", MAX_TEXT_LEN - body.len());
    }
    body.extend(text.as_bytes());
    let mut p = timestamp.to_le_bytes().to_vec();
    p.push(0);
    p.extend(body);
    let mut pl = vec![hash];
    pl.extend(crypto::encrypt_then_mac(secret, &p));
    Ok(finish(ptype::GRP_TXT, pl, route))
}

/// Firmware ACK wait: flood 500 + 16 x airtime; direct 500 + (6 x airtime + 250) x (hops + 1).
pub fn ack_timeout_ms(route: &Route, airtime_ms: f64) -> f64 {
    match route {
        Route::Flood { .. } => 500.0 + 16.0 * airtime_ms,
        Route::Direct { path_len, .. } => 500.0 + (airtime_ms * 6.0 + 250.0) * ((path_len & 63) as f64 + 1.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{Keys, Status, decode_frame};

    #[test]
    fn dm_roundtrip_and_ack() {
        let a = Identity::generate();
        let b = Identity::generate();
        let (plain, ack) = text_plain(&a, 100, 0, "hi").unwrap();
        let p = datagram(ptype::TXT_MSG, &a, &b.public, &plain, &Route::Flood { hash_size: 2 }).unwrap();
        let raw = p.encode();
        let mut keys = Keys { me: Some(b.clone()), ..Default::default() };
        keys.add_peer(a.public);
        let d = decode_frame(&raw, false, &keys);
        assert_eq!(d.status, Status::Ok);
        assert_eq!(d.data.as_ref().unwrap()["plain"]["text"], "hi");
        // recipient computes the same ACK code
        let s = b.shared_secret(&a.public).unwrap();
        let dec = crypto::mac_then_decrypt(&s, &raw[4..]).unwrap();
        assert_eq!(ack_for_plain(&dec, &a.public), ack);
        assert_eq!(raw[1], 0x40); // flood, 2-byte hashes, 0 hops
    }

    #[test]
    fn advert_verifies() {
        let a = Identity::generate();
        let p = advert(&a, 1_800_000_000, &app_data(1, "zerg admin", None), &Route::zero_hop());
        let d = decode_frame(&p.encode(), false, &Keys::default());
        assert_eq!(d.status, Status::Ok);
        assert_eq!(d.data.unwrap()["name"], "zerg admin");
    }
}
