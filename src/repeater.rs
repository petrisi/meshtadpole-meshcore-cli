//! Repeater / room server management: login, binary requests and their responses, DISCOVER.
//! Formats from firmware examples/simple_repeater (MyMesh.cpp/.h) and helpers/BaseChatMesh.cpp.

use serde_json::{Value, json};

pub const REQ_STATUS: u8 = 0x01;
pub const REQ_TELEMETRY: u8 = 0x03;
pub const REQ_ACL: u8 = 0x05;
pub const REQ_NEIGHBOURS: u8 = 0x06;
pub const REQ_OWNER: u8 = 0x07;

pub const CTL_DISCOVER_REQ: u8 = 0x80;
/// Neighbour entries per response page with 6-byte key prefixes (130-byte firmware result buffer / 11).
pub const NEIGHBOURS_PAGE: u8 = 11;

/// Request kind name -> type byte.
pub fn kind(name: &str) -> Option<u8> {
    Some(match name {
        "status" => REQ_STATUS,
        "telemetry" => REQ_TELEMETRY,
        "acl" => REQ_ACL,
        "neighbours" | "neighbors" => REQ_NEIGHBOURS,
        "owner" => REQ_OWNER,
        _ => return None,
    })
}

/// Login plaintext: timestamp, password (max 15 bytes, firmware limit). Room servers also get sync_since.
pub fn login_plain(timestamp: u32, password: &str, room_sync_since: Option<u32>) -> Vec<u8> {
    let mut p = timestamp.to_le_bytes().to_vec();
    if let Some(s) = room_sync_since {
        p.extend(s.to_le_bytes());
    }
    let pw = password.as_bytes();
    p.extend(&pw[..pw.len().min(15)]);
    p
}

/// Request plaintext: timestamp (= tag reflected in the response), type, type-specific bytes, random blob.
pub fn request_plain(timestamp: u32, req_type: u8, neighbours_offset: u16) -> Vec<u8> {
    let mut p = timestamp.to_le_bytes().to_vec();
    p.push(req_type);
    match req_type {
        // version 0, count, offset u16, order_by 2 (strongest first), key prefix length 6
        REQ_NEIGHBOURS => {
            p.extend([0, NEIGHBOURS_PAGE]);
            p.extend(neighbours_offset.to_le_bytes());
            p.extend([2, 6]);
        }
        // TELEMETRY: byte 1 = inverse permission mask (0 = all sensors); others reserved
        _ => p.extend([0u8; 4]),
    }
    p.extend(rand::random::<[u8; 4]>());
    p
}

/// DISCOVER_REQ control payload (zero hop): flags, type filter (bit per advert type), tag, since.
pub fn discover_payload(type_filter: u8, tag: u32) -> Vec<u8> {
    let mut p = vec![CTL_DISCOVER_REQ, type_filter];
    p.extend(tag.to_le_bytes());
    p.extend(0u32.to_le_bytes());
    p
}

/// ACL role from permission bits 0-1.
pub fn role(perms: u8) -> &'static str {
    ["guest", "read_only", "read_write", "admin"][(perms & 3) as usize]
}

fn u16le(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}
fn i16le(b: &[u8], i: usize) -> i16 {
    i16::from_le_bytes([b[i], b[i + 1]])
}
fn u32le(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// Login response (after the 4-byte server timestamp): RESP_SERVER_LOGIN_OK=0, keep-alive, is_admin,
/// permissions, random (4), firmware version level.
pub fn parse_login(b: &[u8]) -> Value {
    if b.len() >= 6 && &b[4..6] == b"OK" {
        return json!({"ok": true, "legacy": true, "server_time": u32le(b, 0)});
    }
    if b.len() < 8 || b[4] != 0 {
        return json!({"ok": false, "code": b.get(4)});
    }
    let perms = b[7];
    json!({
        "ok": true, "server_time": u32le(b, 0), "is_admin": b[6] == 1,
        "permissions": perms, "role": role(perms),
        "firmware_ver_level": b.get(12),
    })
}

/// RepeaterStats (56 bytes after the tag).
pub fn parse_status(b: &[u8]) -> Result<Value, String> {
    let s = &b[4..];
    if s.len() < 56 {
        return Err(format!("status: {} bytes, expected 56", s.len()));
    }
    Ok(json!({
        "batt_mv": u16le(s, 0), "tx_queue_len": u16le(s, 2), "noise_floor_dbm": i16le(s, 4), "last_rssi_dbm": i16le(s, 6),
        "packets_recv": u32le(s, 8), "packets_sent": u32le(s, 12), "tx_airtime_s": u32le(s, 16), "uptime_s": u32le(s, 20),
        "sent_flood": u32le(s, 24), "sent_direct": u32le(s, 28), "recv_flood": u32le(s, 32), "recv_direct": u32le(s, 36),
        "err_events": u16le(s, 40), "last_snr_db": i16le(s, 42) as f64 / 4.0,
        "direct_dups": u16le(s, 44), "flood_dups": u16le(s, 46), "rx_airtime_s": u32le(s, 48), "recv_errors": u32le(s, 52),
    }))
}

/// Cayenne LPP (electroniccats/CayenneLPP as used by MeshCore): [channel][type][data]...
pub fn parse_lpp(b: &[u8]) -> Value {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= b.len() {
        let (ch, t) = (b[i], b[i + 1]);
        // Decrypted payloads are zero-padded to the AES block size; MeshCore channels start at 1.
        if ch == 0 && t == 0 && b[i..].iter().all(|&x| x == 0) {
            break;
        }
        let d = &b[i + 2..];
        let (name, size, val): (&str, usize, Box<dyn Fn(&[u8]) -> Value>) = match t {
            0 => ("digital_input", 1, Box::new(|d| json!(d[0]))),
            1 => ("digital_output", 1, Box::new(|d| json!(d[0]))),
            2 => ("analog_input", 2, Box::new(|d| json!(i16::from_be_bytes([d[0], d[1]]) as f64 / 100.0))),
            3 => ("analog_output", 2, Box::new(|d| json!(i16::from_be_bytes([d[0], d[1]]) as f64 / 100.0))),
            100 => ("generic", 4, Box::new(|d| json!(u32::from_be_bytes([d[0], d[1], d[2], d[3]])))),
            101 => ("illuminance_lux", 2, Box::new(|d| json!(u16::from_be_bytes([d[0], d[1]])))),
            102 => ("presence", 1, Box::new(|d| json!(d[0]))),
            103 => ("temperature_c", 2, Box::new(|d| json!(i16::from_be_bytes([d[0], d[1]]) as f64 / 10.0))),
            104 => ("humidity_pct", 1, Box::new(|d| json!(d[0] as f64 / 2.0))),
            113 => ("accelerometer_g", 6, Box::new(|d| json!([0, 2, 4].map(|k| i16::from_be_bytes([d[k], d[k + 1]]) as f64 / 1000.0)))),
            115 => ("pressure_hpa", 2, Box::new(|d| json!(u16::from_be_bytes([d[0], d[1]]) as f64 / 10.0))),
            116 => ("voltage_v", 2, Box::new(|d| json!(u16::from_be_bytes([d[0], d[1]]) as f64 / 100.0))),
            117 => ("current_a", 2, Box::new(|d| json!(u16::from_be_bytes([d[0], d[1]]) as f64 / 1000.0))),
            118 => ("frequency_hz", 4, Box::new(|d| json!(u32::from_be_bytes([d[0], d[1], d[2], d[3]])))),
            120 => ("percentage", 1, Box::new(|d| json!(d[0]))),
            121 => ("altitude_m", 2, Box::new(|d| json!(i16::from_be_bytes([d[0], d[1]])))),
            125 => ("concentration_ppm", 2, Box::new(|d| json!(u16::from_be_bytes([d[0], d[1]])))),
            128 => ("power_w", 2, Box::new(|d| json!(u16::from_be_bytes([d[0], d[1]])))),
            130 => ("distance_m", 4, Box::new(|d| json!(u32::from_be_bytes([d[0], d[1], d[2], d[3]]) as f64 / 1000.0))),
            131 => ("energy_kwh", 4, Box::new(|d| json!(u32::from_be_bytes([d[0], d[1], d[2], d[3]]) as f64 / 1000.0))),
            132 => ("direction_deg", 2, Box::new(|d| json!(u16::from_be_bytes([d[0], d[1]])))),
            133 => ("unixtime", 4, Box::new(|d| json!(u32::from_be_bytes([d[0], d[1], d[2], d[3]])))),
            134 => ("gyrometer_dps", 6, Box::new(|d| json!([0, 2, 4].map(|k| i16::from_be_bytes([d[k], d[k + 1]]) as f64 / 100.0)))),
            135 => ("colour_rgb", 3, Box::new(|d| json!([d[0], d[1], d[2]]))),
            136 => ("gps", 9, Box::new(|d| {
                let s24 = |k: usize| (((d[k] as i32) << 24 | (d[k + 1] as i32) << 16 | (d[k + 2] as i32) << 8) >> 8) as f64;
                json!({"latitude": s24(0) / 1e4, "longitude": s24(3) / 1e4, "altitude_m": s24(6) / 100.0})
            })),
            142 => ("switch", 1, Box::new(|d| json!(d[0]))),
            _ => {
                out.push(json!({"channel": ch, "type": t, "error": "unknown LPP type; rest not parsed", "rest_hex": hex::encode(&b[i..])}));
                break;
            }
        };
        if d.len() < size {
            out.push(json!({"channel": ch, "type": t, "error": "truncated"}));
            break;
        }
        out.push(json!({"channel": ch, "type": name, "value": val(&d[..size])}));
        i += 2 + size;
    }
    json!(out)
}

/// Neighbours page: total (u16), count (u16), entries [key prefix (6), heard secs ago (u32), snr x4 (i8)].
pub fn parse_neighbours(b: &[u8]) -> Result<(u16, Vec<Value>), String> {
    let s = &b[4..];
    if s.len() < 4 {
        return Err("neighbours: short".into());
    }
    let total = u16le(s, 0);
    let n = u16le(s, 2) as usize;
    let mut v = Vec::new();
    for k in 0..n {
        let o = 4 + k * 11;
        if s.len() < o + 11 {
            return Err("neighbours: truncated".into());
        }
        v.push(json!({"key_prefix": hex::encode(&s[o..o + 6]), "heard_s_ago": u32le(s, o + 6), "snr_db": (s[o + 10] as i8) as f64 / 4.0}));
    }
    Ok((total, v))
}

/// ACL: entries [key prefix (6), permissions].
pub fn parse_acl(b: &[u8]) -> Value {
    json!(b[4..]
        .chunks_exact(7)
        .filter(|c| c.iter().any(|&x| x != 0)) // zero padding; firmware skips permission-0 entries
        .map(|c| json!({"key_prefix": hex::encode(&c[..6]), "permissions": c[6], "role": role(c[6])}))
        .collect::<Vec<_>>())
}

/// Owner info: "firmware version\nnode name\nowner info".
pub fn parse_owner(b: &[u8]) -> Value {
    let t = String::from_utf8_lossy(&b[4..]);
    let t = t.trim_end_matches('\0');
    let mut it = t.splitn(3, '\n');
    json!({"firmware": it.next(), "name": it.next(), "owner_info": it.next()})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lpp_voltage_temperature() {
        // ch1 voltage 4.12 V, ch1 temperature 21.5 C
        let b = [1, 116, 0x01, 0x9C, 1, 103, 0x00, 0xD7];
        let v = parse_lpp(&b);
        assert_eq!(v[0]["type"], "voltage_v");
        assert_eq!(v[0]["value"], 4.12);
        assert_eq!(v[1]["value"], 21.5);
    }

    #[test]
    fn lpp_ignores_padding() {
        let b = [1, 116, 0x01, 0x9C, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_lpp(&b).as_array().unwrap().len(), 1);
    }

    #[test]
    fn status_layout() {
        let mut b = vec![0u8; 4 + 56];
        b[4..6].copy_from_slice(&4100u16.to_le_bytes());
        b[8..10].copy_from_slice(&(-110i16).to_le_bytes());
        b[46..48].copy_from_slice(&(-20i16).to_le_bytes());
        let v = parse_status(&b).unwrap();
        assert_eq!(v["batt_mv"], 4100);
        assert_eq!(v["noise_floor_dbm"], -110);
        assert_eq!(v["last_snr_db"], -5.0);
    }
}
