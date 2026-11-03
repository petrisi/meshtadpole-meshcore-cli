//! Payload decoding. Produces a JSON description of every frame, decrypting what our keys allow.

use crate::crypto::{self, Identity, mac_then_decrypt};
use crate::packet::{Packet, ptype, ptype_name, route_name};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Parsed; decrypted where applicable.
    Ok,
    CrcError,
    /// Wire format invalid.
    Malformed,
    /// Payload version not supported (only v1 exists).
    UnsupportedVersion,
    /// Advert signature invalid.
    BadSignature,
    /// Group message: no configured channel with matching hash and MAC.
    NoChannel,
    /// Peer-encrypted payload not decryptable by us (not to/from us, or peer key unknown).
    Encrypted,
    /// Decrypted but content invalid.
    DecodeError,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::CrcError => "crc_error",
            Status::Malformed => "malformed",
            Status::UnsupportedVersion => "unsupported_version",
            Status::BadSignature => "bad_signature",
            Status::NoChannel => "no_channel",
            Status::Encrypted => "encrypted",
            Status::DecodeError => "decode_error",
        }
    }
}

/// Configured group channel.
#[derive(Debug, Clone)]
pub struct Channel {
    pub name: String,
    pub secret: [u8; 32],
    pub hash: u8,
}

/// Keys available to the decoder.
#[derive(Default)]
pub struct Keys {
    pub me: Option<Identity>,
    pub channels: Vec<Channel>,
    /// Known peer public keys (from adverts), indexed by first byte.
    pub peers: HashMap<u8, Vec<[u8; 32]>>,
}

impl Keys {
    pub fn add_peer(&mut self, k: [u8; 32]) {
        let v = self.peers.entry(k[0]).or_default();
        if !v.contains(&k) {
            v.push(k);
        }
    }
}

#[derive(Debug, Clone)]
pub struct Decoded {
    pub status: Status,
    pub packet: Option<Packet>,
    pub pkt_hash: Option<String>,
    /// Full sender public key when the payload carries it (ADVERT, ANON_REQ) or a decrypt identified it.
    pub src_key: Option<String>,
    pub src_hash: Option<String>,
    pub dest_hash: Option<String>,
    pub channel: Option<String>,
    pub data: Option<Value>,
    pub error: Option<String>,
    /// Decrypted peer payload (daemon-internal, never stored raw): peer key, direction in/out, plaintext.
    pub peer_plain: Option<([u8; 32], &'static str, Vec<u8>)>,
}

impl Decoded {
    fn new(status: Status) -> Decoded {
        Decoded { status, packet: None, pkt_hash: None, src_key: None, src_hash: None, dest_hash: None, channel: None, data: None, error: None, peer_plain: None }
    }
}

pub fn adv_type_name(t: u8) -> &'static str {
    match t {
        0 => "none",
        1 => "chat",
        2 => "repeater",
        3 => "room",
        4 => "sensor",
        _ => "unknown",
    }
}

pub fn txt_type_name(t: u8) -> String {
    match t {
        0 => "plain".into(),
        1 => "cli_data".into(),
        2 => "signed_plain".into(),
        3 => "cli_command".into(),
        n => format!("type_{n}"),
    }
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Text up to the first NUL (plaintext is zero-padded to the AES block size).
fn c_str(b: &[u8]) -> String {
    let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// Advert app data: flags, [lat, lon i32 1e6], [feat1 u16], [feat2 u16], [name].
pub fn parse_app_data(a: &[u8]) -> Value {
    if a.is_empty() {
        return json!({});
    }
    let flags = a[0];
    let mut i = 1;
    let mut v = json!({"flags": flags, "adv_type": flags & 0x0F, "adv_type_name": adv_type_name(flags & 0x0F)});
    if flags & 0x10 != 0 && a.len() >= i + 8 {
        v["latitude"] = json!(i32::from_le_bytes(a[i..i + 4].try_into().unwrap()) as f64 / 1e6);
        v["longitude"] = json!(i32::from_le_bytes(a[i + 4..i + 8].try_into().unwrap()) as f64 / 1e6);
        i += 8;
    }
    if flags & 0x20 != 0 && a.len() >= i + 2 {
        v["feat1"] = json!(u16::from_le_bytes([a[i], a[i + 1]]));
        i += 2;
    }
    if flags & 0x40 != 0 && a.len() >= i + 2 {
        v["feat2"] = json!(u16::from_le_bytes([a[i], a[i + 1]]));
        i += 2;
    }
    if flags & 0x80 != 0 && a.len() > i {
        v["name"] = json!(c_str(&a[i..]));
    }
    v
}

/// Decode a received frame.
pub fn decode_frame(raw: &[u8], crc_error: bool, keys: &Keys) -> Decoded {
    let p = match Packet::parse(raw) {
        Ok(p) => p,
        Err(e) => {
            let mut d = Decoded::new(if crc_error { Status::CrcError } else { Status::Malformed });
            d.error = Some(e.to_string());
            return d;
        }
    };
    let mut d = Decoded::new(Status::Ok);
    d.pkt_hash = Some(hex::encode(p.hash()));
    if crc_error {
        d.status = Status::CrcError;
        d.packet = Some(p);
        return d;
    }
    if p.version() != 0 {
        d.status = Status::UnsupportedVersion;
        d.packet = Some(p);
        return d;
    }
    decode_payload(&p, keys, &mut d);
    d.packet = Some(p);
    d
}

fn short(d: &mut Decoded, what: &str) {
    d.status = Status::Malformed;
    d.error = Some(format!("{what}: payload too short"));
}

fn decode_payload(p: &Packet, keys: &Keys, d: &mut Decoded) {
    let pl = &p.payload;
    let t = p.ptype();
    match t {
        ptype::ADVERT => {
            if pl.len() < 32 + 4 + 64 {
                return short(d, "advert");
            }
            let pubk: [u8; 32] = pl[..32].try_into().unwrap();
            let ts = le32(&pl[32..36]);
            let sig = &pl[36..100];
            let app = &pl[100..pl.len().min(100 + 32)];
            let mut msg = pubk.to_vec();
            msg.extend(&pl[32..36]);
            msg.extend(app);
            let ok = crypto::verify(&pubk, &msg, sig);
            d.src_key = Some(hex::encode(pubk));
            d.src_hash = Some(hex::encode(&pubk[..1]));
            let mut v = json!({"public_key": hex::encode(pubk), "timestamp": ts, "signature_valid": ok});
            if let Value::Object(m) = parse_app_data(app) {
                for (k, x) in m {
                    v[k] = x;
                }
            }
            d.data = Some(v);
            if !ok {
                d.status = Status::BadSignature;
            }
        }
        ptype::ACK => {
            if pl.len() < 4 {
                return short(d, "ack");
            }
            d.data = Some(json!({"ack_crc": format!("{:08x}", le32(pl)), "extra": hex::encode(&pl[4..])}));
        }
        ptype::REQ | ptype::RESPONSE | ptype::TXT_MSG | ptype::PATH => {
            if pl.len() < 2 + crypto::MAC_SIZE + crypto::BLOCK {
                return short(d, &ptype_name(t));
            }
            d.dest_hash = Some(hex::encode(&pl[..1]));
            d.src_hash = Some(hex::encode(&pl[1..2]));
            let mut v = json!({"ciphertext_len": pl.len() - 4});
            match peer_decrypt(keys, pl[0], pl[1], &pl[2..]) {
                Some((peer, dir, plain)) => {
                    d.src_key = Some(hex::encode(if dir == "in" { peer } else { keys.me.as_ref().unwrap().public }));
                    v["peer"] = json!(hex::encode(peer));
                    v["direction"] = json!(dir);
                    match peer_plain(t, &plain) {
                        Ok(x) => v["plain"] = x,
                        Err(e) => {
                            d.status = Status::DecodeError;
                            d.error = Some(e);
                        }
                    }
                    d.peer_plain = Some((peer, dir, plain));
                }
                None => d.status = Status::Encrypted,
            }
            d.data = Some(v);
        }
        ptype::ANON_REQ => {
            if pl.len() < 1 + 32 + crypto::MAC_SIZE + crypto::BLOCK {
                return short(d, "anon_req");
            }
            let sender: [u8; 32] = pl[1..33].try_into().unwrap();
            d.dest_hash = Some(hex::encode(&pl[..1]));
            d.src_key = Some(hex::encode(sender));
            d.src_hash = Some(hex::encode(&sender[..1]));
            let mut v = json!({"sender_public_key": hex::encode(sender), "ciphertext_len": pl.len() - 35});
            let plain = keys
                .me
                .as_ref()
                .filter(|me| me.public[0] == pl[0])
                .and_then(|me| me.shared_secret(&sender).ok())
                .and_then(|s| mac_then_decrypt(&s, &pl[33..]));
            match plain {
                Some(b) if b.len() >= 4 => {
                    v["plain"] = json!({"timestamp": le32(&b), "data_hex": hex::encode(&b[4..])});
                }
                _ => d.status = Status::Encrypted,
            }
            d.data = Some(v);
        }
        ptype::GRP_TXT | ptype::GRP_DATA => {
            if pl.len() < 1 + crypto::MAC_SIZE + crypto::BLOCK {
                return short(d, &ptype_name(t));
            }
            let mut v = json!({"channel_hash": format!("{:02x}", pl[0])});
            let hit = keys
                .channels
                .iter()
                .filter(|c| c.hash == pl[0])
                .find_map(|c| mac_then_decrypt(&c.secret, &pl[1..]).map(|b| (c, b)));
            match hit {
                Some((c, b)) => {
                    d.channel = Some(c.name.clone());
                    match group_plain(t, &b) {
                        Ok(x) => v["plain"] = x,
                        Err(e) => {
                            d.status = Status::DecodeError;
                            d.error = Some(e);
                        }
                    }
                }
                None => d.status = Status::NoChannel,
            }
            d.data = Some(v);
        }
        ptype::TRACE => {
            if pl.len() < 9 {
                return short(d, "trace");
            }
            let flags = pl[8];
            let hs = 1usize << (flags & 3);
            let hashes: Vec<String> = pl[9..].chunks(hs).map(hex::encode).collect();
            // In TRACE the packet path holds per-hop SNR x4 (i8), not hashes.
            let snrs: Vec<f64> = p.path.iter().map(|&x| (x as i8) as f64 / 4.0).collect();
            d.data = Some(json!({
                "tag": format!("{:08x}", le32(pl)), "auth_code": format!("{:08x}", le32(&pl[4..])),
                "flags": flags, "hash_size": hs, "route": hashes, "snrs": snrs,
            }));
        }
        ptype::CONTROL => {
            if pl.is_empty() {
                return short(d, "control");
            }
            let sub = pl[0] >> 4;
            let mut v = json!({"sub_type": sub, "flags": pl[0] & 0x0F});
            match sub {
                0x8 if pl.len() >= 6 => {
                    v["sub_type_name"] = json!("DISCOVER_REQ");
                    v["prefix_only"] = json!(pl[0] & 1 != 0);
                    v["type_filter"] = json!(pl[1]);
                    v["tag"] = json!(format!("{:08x}", le32(&pl[2..])));
                    if pl.len() >= 10 {
                        v["since"] = json!(le32(&pl[6..]));
                    }
                }
                0x9 if pl.len() >= 6 => {
                    v["sub_type_name"] = json!("DISCOVER_RESP");
                    v["node_type"] = json!(adv_type_name(pl[0] & 0x0F));
                    v["snr"] = json!((pl[1] as i8) as f64 / 4.0);
                    v["tag"] = json!(format!("{:08x}", le32(&pl[2..])));
                    v["public_key"] = json!(hex::encode(&pl[6..]));
                    if pl.len() >= 7 {
                        d.src_hash = Some(hex::encode(&pl[6..7]));
                    }
                    if pl.len() == 6 + 32 {
                        d.src_key = Some(hex::encode(&pl[6..]));
                    }
                }
                _ => v["data_hex"] = json!(hex::encode(&pl[1..])),
            }
            d.data = Some(v);
        }
        ptype::MULTIPART => {
            if pl.len() < 2 {
                return short(d, "multipart");
            }
            let inner = pl[0] & 0x0F;
            let mut v = json!({"remaining": pl[0] >> 4, "inner_type": ptype_name(inner)});
            if inner == ptype::ACK && pl.len() >= 5 {
                v["ack_crc"] = json!(format!("{:08x}", le32(&pl[1..])));
            } else {
                v["data_hex"] = json!(hex::encode(&pl[1..]));
            }
            d.data = Some(v);
        }
        _ => d.data = Some(json!({"data_hex": hex::encode(pl)})),
    }
}

/// Try to decrypt a peer payload addressed to us (from a known peer) or sent by us (to a known peer).
/// Returns (peer key, "in"/"out", plaintext).
fn peer_decrypt(keys: &Keys, dest: u8, src: u8, mac_ct: &[u8]) -> Option<([u8; 32], &'static str, Vec<u8>)> {
    let me = keys.me.as_ref()?;
    let mine = me.public[0];
    let mut tries: Vec<(u8, &'static str)> = Vec::new();
    if dest == mine {
        tries.push((src, "in"));
    }
    if src == mine {
        tries.push((dest, "out"));
    }
    for (h, dir) in tries {
        for k in keys.peers.get(&h).into_iter().flatten() {
            let Ok(s) = me.shared_secret(k) else { continue };
            if let Some(b) = mac_then_decrypt(&s, mac_ct) {
                return Some((*k, dir, b));
            }
        }
    }
    None
}

fn peer_plain(t: u8, b: &[u8]) -> Result<Value, String> {
    if b.len() < 5 {
        return Err("plaintext too short".into());
    }
    let ts = le32(b);
    Ok(match t {
        ptype::TXT_MSG => {
            let tt = b[4] >> 2;
            let mut v = json!({"timestamp": ts, "txt_type": txt_type_name(tt), "attempt": b[4] & 3});
            if tt == 2 && b.len() >= 9 {
                v["sender_prefix"] = json!(hex::encode(&b[5..9]));
                v["text"] = json!(c_str(&b[9..]));
            } else {
                v["text"] = json!(c_str(&b[5..]));
            }
            v
        }
        ptype::PATH => {
            let pl = b[0];
            let hs = (pl >> 6) as usize + 1;
            let n = (pl & 63) as usize * hs;
            if hs == 4 || b.len() < 1 + n + 1 {
                return Err("bad path encoding".into());
            }
            let path: Vec<String> = b[1..1 + n].chunks(hs).map(hex::encode).collect();
            json!({"path": path, "path_len_raw": pl, "hash_size": hs, "extra_type": ptype_name(b[1 + n] & 0x0F), "extra_hex": hex::encode(&b[2 + n..])})
        }
        _ => json!({"timestamp": ts, "data_hex": hex::encode(&b[4..])}),
    })
}

fn group_plain(t: u8, b: &[u8]) -> Result<Value, String> {
    if t == ptype::GRP_TXT {
        if b.len() < 5 {
            return Err("plaintext too short".into());
        }
        let text = c_str(&b[5..]);
        let mut v = json!({"timestamp": le32(b), "txt_type": txt_type_name(b[4] >> 2), "attempt": b[4] & 3});
        match text.split_once(": ") {
            Some((name, msg)) => {
                v["sender"] = json!(name);
                v["text"] = json!(msg);
            }
            None => v["text"] = json!(text),
        }
        Ok(v)
    } else {
        if b.len() < 3 {
            return Err("plaintext too short".into());
        }
        let n = (b[2] as usize).min(b.len() - 3);
        Ok(json!({"data_type": u16::from_le_bytes([b[0], b[1]]), "data_len": b[2], "data_hex": hex::encode(&b[3..3 + n])}))
    }
}

/// Frame event JSON (shared by daemon broadcast and offline decode).
pub fn to_json(d: &Decoded) -> Value {
    let mut v = json!({"status": d.status.as_str()});
    if let Some(p) = &d.packet {
        v["route"] = json!(route_name(p.route()));
        v["payload_type"] = json!(ptype_name(p.ptype()));
        v["payload_ver"] = json!(p.version());
        if let Some(tc) = p.transport_codes {
            v["transport_codes"] = json!([format!("{:04x}", tc[0]), format!("{:04x}", tc[1])]);
        }
        v["path_hash_size"] = json!(p.path_hash_size());
        v["path_hops"] = json!(p.path_count());
        if p.ptype() != ptype::TRACE {
            v["path"] = json!(p.path_hashes());
        }
    }
    for (k, x) in [("pkt_hash", &d.pkt_hash), ("src_key", &d.src_key), ("src_hash", &d.src_hash), ("dest_hash", &d.dest_hash), ("channel", &d.channel), ("error", &d.error)] {
        if let Some(x) = x {
            v[k] = json!(x);
        }
    }
    if let Some(x) = &d.data {
        v["data"] = x.clone();
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advert_roundtrip() {
        let id = Identity::generate();
        let ts: u32 = 1_700_000_000;
        let app = [&[0x81u8][..], b"node"].concat();
        let mut msg = id.public.to_vec();
        msg.extend(ts.to_le_bytes());
        msg.extend(&app);
        let sig = id.sign(&msg);
        let mut pl = id.public.to_vec();
        pl.extend(ts.to_le_bytes());
        pl.extend(sig);
        pl.extend(&app);
        let raw = [&[0x11u8, 0x00][..], &pl].concat();
        let d = decode_frame(&raw, false, &Keys::default());
        assert_eq!(d.status, Status::Ok, "{:?}", d.error);
        let v = d.data.unwrap();
        assert_eq!(v["name"], "node");
        assert_eq!(v["adv_type_name"], "chat");
        let mut bad = raw.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(decode_frame(&bad, false, &Keys::default()).status, Status::BadSignature);
    }

    #[test]
    fn group_text() {
        let (secret, hash) = crypto::channel_secret(&crypto::hashtag_key("#test")).unwrap();
        let mut plain = 1_700_000_000u32.to_le_bytes().to_vec();
        plain.push(0);
        plain.extend(b"alice: hi");
        let mut pl = vec![hash];
        pl.extend(crypto::encrypt_then_mac(&secret, &plain));
        let raw = [&[0x15u8, 0x00][..], &pl].concat();
        let keys = Keys { channels: vec![Channel { name: "#test".into(), secret, hash }], ..Default::default() };
        let d = decode_frame(&raw, false, &keys);
        assert_eq!(d.status, Status::Ok);
        assert_eq!(d.channel.as_deref(), Some("#test"));
        assert_eq!(d.data.as_ref().unwrap()["plain"]["sender"], "alice");
        assert_eq!(d.data.as_ref().unwrap()["plain"]["text"], "hi");
        assert_eq!(decode_frame(&raw, false, &Keys::default()).status, Status::NoChannel);
    }

    #[test]
    fn peer_text_to_us() {
        let me = Identity::generate();
        let peer = Identity::generate();
        let s = peer.shared_secret(&me.public).unwrap();
        let mut plain = 5u32.to_le_bytes().to_vec();
        plain.push(0);
        plain.extend(b"hello");
        let mut pl = vec![me.public[0], peer.public[0]];
        pl.extend(crypto::encrypt_then_mac(&s, &plain));
        let raw = [&[0x0Au8, 0x00][..], &pl].concat(); // direct TXT_MSG
        let mut keys = Keys { me: Some(me), ..Default::default() };
        assert_eq!(decode_frame(&raw, false, &keys).status, Status::Encrypted);
        keys.add_peer(peer.public);
        let d = decode_frame(&raw, false, &keys);
        assert_eq!(d.status, Status::Ok);
        assert_eq!(d.data.unwrap()["plain"]["text"], "hello");
    }
}
