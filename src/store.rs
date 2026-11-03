//! SQLite store. Schema is part of the public interface (see docs/schema.md).

use crate::decode::{Decoded, Status};
use crate::packet::ptype;
use anyhow::{Result, anyhow};
use meshtadpole_radio::store::Session;
use meshtadpole_radio::store::rusqlite::{self, Connection, params};
use meshtadpole_radio::sx1262::RxFrame;
use serde_json::Value;
use std::path::Path;

pub use meshtadpole_radio::store::{COMMON_SCHEMA, now};

pub const SCHEMA_VERSION: i64 = 1;

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS rx_frames(
  id INTEGER PRIMARY KEY,
  session_id INTEGER,
  rx_time REAL NOT NULL,
  raw BLOB,
  len INTEGER,
  airtime_ms REAL,
  rssi REAL, snr REAL, signal_rssi REAL, freq_error_hz REAL,
  status TEXT NOT NULL,
  route TEXT, payload_type TEXT, payload_ver INTEGER,
  transport_code1 INTEGER, transport_code2 INTEGER,
  path_hash_size INTEGER, path_hops INTEGER, path TEXT, last_hop TEXT,
  pkt_hash TEXT,
  src_key TEXT, src_hash TEXT, dest_hash TEXT,
  channel TEXT,
  data_json TEXT,
  error TEXT,
  dup_of INTEGER
);
CREATE INDEX IF NOT EXISTS rx_frames_time ON rx_frames(rx_time);
CREATE INDEX IF NOT EXISTS rx_frames_hash ON rx_frames(pkt_hash, rx_time);
CREATE INDEX IF NOT EXISTS rx_frames_type_time ON rx_frames(payload_type, rx_time);
CREATE INDEX IF NOT EXISTS rx_frames_src_key ON rx_frames(src_key, rx_time);
CREATE INDEX IF NOT EXISTS rx_frames_last_hop ON rx_frames(last_hop, rx_time);

CREATE TABLE IF NOT EXISTS nodes(
  public_key TEXT PRIMARY KEY,
  hash TEXT NOT NULL,
  name TEXT, adv_type TEXT, flags INTEGER,
  latitude REAL, longitude REAL, feat1 INTEGER, feat2 INTEGER,
  advert_timestamp INTEGER, app_data_json TEXT,
  first_heard REAL, last_heard REAL, last_frame_id INTEGER,
  adverts_heard INTEGER NOT NULL DEFAULT 0, receptions INTEGER NOT NULL DEFAULT 0,
  last_rssi REAL, last_snr REAL, last_route TEXT, last_path_hops INTEGER, last_path TEXT,
  last_direct_heard REAL, last_direct_rssi REAL, last_direct_snr REAL
);
CREATE INDEX IF NOT EXISTS nodes_hash ON nodes(hash);

CREATE TABLE IF NOT EXISTS tx_frames(
  id INTEGER PRIMARY KEY,
  session_id INTEGER,
  tx_time REAL NOT NULL,
  raw BLOB, len INTEGER, airtime_ms REAL,
  route TEXT, payload_type TEXT, pkt_hash TEXT,
  dest TEXT, data_json TEXT,
  attempt INTEGER, error TEXT
);
CREATE INDEX IF NOT EXISTS tx_frames_time ON tx_frames(tx_time);

CREATE VIEW IF NOT EXISTS v_packets AS
SELECT f.id, f.rx_time, datetime(f.rx_time,'unixepoch') AS rx_utc, f.status, f.route, f.payload_type,
  f.path_hops, f.path, f.last_hop, f.src_hash, f.dest_hash, f.src_key, n.name AS src_name, f.channel,
  f.rssi, f.snr, f.len, f.airtime_ms, f.pkt_hash, f.data_json, f.dup_of
FROM rx_frames f LEFT JOIN nodes n ON n.public_key = f.src_key;

CREATE VIEW IF NOT EXISTS v_adverts AS
SELECT id AS frame_id, rx_time, src_key AS public_key, json_extract(data_json,'$.name') AS name,
  json_extract(data_json,'$.adv_type_name') AS adv_type, json_extract(data_json,'$.timestamp') AS advert_timestamp,
  json_extract(data_json,'$.latitude') AS latitude, json_extract(data_json,'$.longitude') AS longitude,
  route, path_hops, path, last_hop, rssi, snr, dup_of
FROM rx_frames WHERE payload_type='ADVERT' AND status='ok';

CREATE VIEW IF NOT EXISTS v_channel_text AS
SELECT id AS frame_id, rx_time, datetime(rx_time,'unixepoch') AS rx_utc, channel,
  json_extract(data_json,'$.plain.sender') AS sender, json_extract(data_json,'$.plain.text') AS text,
  json_extract(data_json,'$.plain.timestamp') AS sender_timestamp, path_hops, path, rssi, snr
FROM rx_frames WHERE payload_type='GRP_TXT' AND status='ok' AND dup_of IS NULL;

CREATE VIEW IF NOT EXISTS v_heard_repeaters AS
SELECT last_hop AS hash, count(*) AS frames, avg(rssi) AS avg_rssi, avg(snr) AS avg_snr,
  min(snr) AS min_snr, max(snr) AS max_snr, min(rx_time) AS first_heard, max(rx_time) AS last_heard
FROM rx_frames WHERE last_hop IS NOT NULL AND status NOT IN ('crc_error','header_error','malformed')
GROUP BY last_hop;
"#;

/// Full DDL (common tables from meshtadpole-radio + tool tables).
pub fn full_schema() -> String {
    format!("{}\n{}", COMMON_SCHEMA.trim(), SCHEMA.trim())
}

pub fn open_rw(path: &Path) -> Result<Connection> {
    meshtadpole_radio::store::open_rw(path, SCHEMA, SCHEMA_VERSION).map_err(|e| anyhow!(e))
}

pub fn open_ro(path: &Path) -> Result<Connection> {
    meshtadpole_radio::store::open_ro(path).map_err(|e| anyhow!(e))
}

pub fn query_json(c: &Connection, sql: &str, args: &[&dyn rusqlite::ToSql]) -> Result<Vec<Value>> {
    Ok(meshtadpole_radio::store::query_json(c, sql, args)?)
}

pub struct Writer {
    pub s: Session,
}

impl Writer {
    pub fn insert_header_error(&self, t: f64, rssi_inst: f32) -> Result<i64> {
        self.s.c.execute(
            "INSERT INTO rx_frames(session_id,rx_time,rssi,status) VALUES(?1,?2,?3,'header_error')",
            params![self.s.id, t, rssi_inst],
        )?;
        Ok(self.s.c.last_insert_rowid())
    }

    /// Insert a frame and update the node table. Returns (frame id, dup_of).
    pub fn insert_frame(&self, t: f64, f: &RxFrame, airtime_ms: f64, d: &Decoded) -> Result<(i64, Option<i64>)> {
        let trusted = !matches!(d.status, Status::CrcError | Status::Malformed);
        let dup_of: Option<i64> = match (&d.pkt_hash, trusted) {
            (Some(h), true) => self
                .s
                .c
                .query_row(
                    "SELECT id FROM rx_frames WHERE pkt_hash=?1 AND dup_of IS NULL AND status NOT IN ('crc_error','malformed') AND rx_time>?2 ORDER BY id LIMIT 1",
                    params![h, t - 3600.0],
                    |r| r.get(0),
                )
                .ok(),
            _ => None,
        };
        let p = d.packet.as_ref();
        let path = p.filter(|p| p.ptype() != ptype::TRACE).map(|p| p.path_hashes().join(","));
        // Flood path: the last entry is the repeater we received this copy from.
        let last_hop = p.filter(|p| p.is_flood() && p.path_count() > 0).and_then(|p| p.path_hashes().pop());
        self.s.c.execute(
            "INSERT INTO rx_frames(session_id,rx_time,raw,len,airtime_ms,rssi,snr,signal_rssi,freq_error_hz,status,
               route,payload_type,payload_ver,transport_code1,transport_code2,path_hash_size,path_hops,path,last_hop,
               pkt_hash,src_key,src_hash,dest_hash,channel,data_json,error,dup_of)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27)",
            params![
                self.s.id, t, f.data, f.data.len(), airtime_ms, f.rssi_dbm, f.snr_db, f.signal_rssi_dbm, f.freq_error_hz,
                d.status.as_str(),
                p.map(|p| crate::packet::route_name(p.route())), p.map(|p| crate::packet::ptype_name(p.ptype())), p.map(|p| p.version()),
                p.and_then(|p| p.transport_codes).map(|c| c[0]), p.and_then(|p| p.transport_codes).map(|c| c[1]),
                p.map(|p| p.path_hash_size()), p.map(|p| p.path_count()), path, last_hop,
                d.pkt_hash, d.src_key, d.src_hash, d.dest_hash, d.channel, d.data.as_ref().map(|v| v.to_string()), d.error, dup_of
            ],
        )?;
        let id = self.s.c.last_insert_rowid();
        if d.status == Status::Ok && p.is_some_and(|p| p.ptype() == ptype::ADVERT) {
            self.update_node(t, id, f, d, dup_of.is_none(), path.as_deref())?;
        }
        Ok((id, dup_of))
    }

    fn update_node(&self, t: f64, frame_id: i64, f: &RxFrame, d: &Decoded, first: bool, path: Option<&str>) -> Result<()> {
        let (Some(key), Some(v), Some(p)) = (&d.src_key, &d.data, &d.packet) else { return Ok(()) };
        let route = crate::packet::route_name(p.route());
        self.s.c.execute(
            "INSERT INTO nodes(public_key,hash,first_heard,last_heard,last_frame_id,adverts_heard,receptions,last_rssi,last_snr,last_route,last_path_hops,last_path)
             VALUES(?1,substr(?1,1,2),?2,?2,?3,?4,1,?5,?6,?7,?8,?9)
             ON CONFLICT(public_key) DO UPDATE SET last_heard=excluded.last_heard,last_frame_id=excluded.last_frame_id,
               adverts_heard=adverts_heard+excluded.adverts_heard,receptions=receptions+1,last_rssi=excluded.last_rssi,last_snr=excluded.last_snr,
               last_route=excluded.last_route,last_path_hops=excluded.last_path_hops,last_path=excluded.last_path",
            params![key, t, frame_id, first as i64, f.rssi_dbm, f.snr_db, route, p.path_count(), path],
        )?;
        if p.path_count() == 0 {
            self.s.c.execute(
                "UPDATE nodes SET last_direct_heard=?2,last_direct_rssi=?3,last_direct_snr=?4 WHERE public_key=?1",
                params![key, t, f.rssi_dbm, f.snr_db],
            )?;
        }
        // Advertised data: only from adverts not older than the stored one (replays keep old content out).
        self.s.c.execute(
            "UPDATE nodes SET name=?2,adv_type=?3,flags=?4,latitude=?5,longitude=?6,feat1=?7,feat2=?8,advert_timestamp=?9,app_data_json=?10
             WHERE public_key=?1 AND (advert_timestamp IS NULL OR advert_timestamp<=?9)",
            params![
                key, v["name"].as_str(), v["adv_type_name"].as_str(), v["flags"].as_i64(), v["latitude"].as_f64(), v["longitude"].as_f64(),
                v["feat1"].as_i64(), v["feat2"].as_i64(), v["timestamp"].as_i64(), v.to_string()
            ],
        )?;
        Ok(())
    }
}

/// Known peer public keys (for decrypting messages to us).
pub fn load_peer_keys(c: &Connection) -> Result<Vec<[u8; 32]>> {
    let mut st = c.prepare("SELECT public_key FROM nodes")?;
    let rows = st.query_map([], |r| r.get::<_, String>(0))?;
    Ok(rows.flatten().filter_map(|h| hex::decode(h).ok()).filter_map(|b| <[u8; 32]>::try_from(b.as_slice()).ok()).collect())
}

/// Re-export for dynamic query arguments.
pub use rusqlite::ToSql as rusqlite_ToSql;
