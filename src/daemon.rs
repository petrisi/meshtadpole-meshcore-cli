//! Daemon: owns the radio and identity, decodes and stores every frame, transmits on request,
//! answers messages addressed to us (ACK, PATH return), serves a local NDJSON API.
//!
//! API (TCP, one JSON object per line):
//! - `{"cmd":"status"}` -> status object.
//! - `{"cmd":"subscribe"}` -> stream of frame events until disconnect.
//! - `{"cmd":"advert","flood":bool,"wait_s":f}` -> transmission and echoes heard.
//! - `{"cmd":"send_text","to":"<64 hex key>","text":"..","retries":n,"flood":bool}` -> ACK result.
//! - `{"cmd":"send_channel","channel":"<name>","text":"..","wait_s":f}` -> transmission and echoes heard.
//! - `{"cmd":"discover","wait_s":f,"type_filter":n}` -> nodes answering a zero-hop DISCOVER_REQ.
//! - `{"cmd":"login","to":"<key>","password":"..","room":bool}` -> login result (password redacted in logs).
//! - `{"cmd":"request","to":"<key>","kind":"status|telemetry|neighbours|acl|owner","password":".."}` -> parsed response.
//! - `{"cmd":"cli","to":"<key>","command":"..","password":".."}` -> command reply text.

use crate::config::Config;
use crate::decode::{Decoded, Keys, Status, decode_frame, to_json};
use crate::mesh::{self, Route};
use crate::packet::{Packet, ptype, ptype_name};
use crate::repeater;
use crate::store::{self, Writer};
use anyhow::{Context, Result, anyhow, bail};
use meshtadpole_radio::link::{self, Airtime, TxJob, TxReport};
use meshtadpole_radio::store::Session;
use meshtadpole_radio::{api, sx1262};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Per-transmission data handed through the radio link, stored in tx_frames.
pub struct TxMeta {
    route: &'static str,
    dest: Option<String>,
    data: Value,
    attempt: u32,
    pkt_hash: String,
}

type Job = TxJob<TxMeta>;

/// What an API call waits for.
#[derive(Clone)]
enum Match {
    /// ACK code (ACK packet, multipart ACK, or ACK inside a PATH return).
    Ack(u32),
    /// Our own packet repeated by a repeater (same packet hash).
    Echo(String),
    /// RESPONSE (or PATH with RESPONSE extra) from a peer; tag = reflected request timestamp (None: any).
    Response { peer: [u8; 32], tag: Option<u32> },
    /// CLI reply (TXT_MSG of type CLI data) from a peer.
    Cli { peer: [u8; 32] },
    /// DISCOVER_RESP carrying our tag.
    Discover(u32),
}

/// What a received frame offers to waiters.
enum Sig {
    Response { peer: [u8; 32], plain: Vec<u8> },
    Cli { peer: [u8; 32], text: String },
    Discover(u32),
}

struct Waiter {
    id: u64,
    m: Match,
    tx: Sender<Value>,
}

struct Shared {
    cfg: Config,
    db: PathBuf,
    keys: RwLock<Keys>,
    /// Learned routes to peers: raw path_len byte and path bytes.
    out_paths: Mutex<HashMap<[u8; 32], (u8, Vec<u8>)>>,
    subscribers: api::Subscribers,
    waiters: Mutex<Vec<Waiter>>,
    next_waiter: AtomicU64,
    tx_queue: Mutex<Sender<Job>>,
    airtime: Arc<Airtime>,
    last_ts: Mutex<u32>,
    /// Successful logins this daemon session: peer -> login result.
    logins: Mutex<HashMap<[u8; 32], Value>>,
    status: Mutex<Value>,
    frames: AtomicU64,
    stop: AtomicBool,
}

impl Shared {
    fn me(&self) -> Result<crate::crypto::Identity> {
        self.keys.read().unwrap().me.clone().ok_or_else(|| anyhow!("no identity; run `tadpole-mc identity --generate`"))
    }

    /// Sender timestamp, strictly increasing (firmware getCurrentTimeUnique).
    fn timestamp(&self) -> u32 {
        let mut last = self.last_ts.lock().unwrap();
        let t = store::now() as u32;
        *last = if t <= *last { *last + 1 } else { t };
        *last
    }

    fn flood(&self) -> Route {
        Route::Flood { hash_size: self.cfg.node.path_hash_size }
    }

    fn wait_for(&self, m: Match) -> (u64, std::sync::mpsc::Receiver<Value>) {
        let (tx, rx) = channel();
        let id = self.next_waiter.fetch_add(1, Ordering::Relaxed);
        self.waiters.lock().unwrap().push(Waiter { id, m, tx });
        (id, rx)
    }

    fn unwait(&self, ids: &[u64]) {
        self.waiters.lock().unwrap().retain(|w| !ids.contains(&w.id));
    }

    fn notify(&self, acks: &[u32], pkt_hash: Option<&str>, sigs: &[Sig], ev: &Value) {
        self.waiters.lock().unwrap().retain(|w| {
            let mut out = None;
            match &w.m {
                Match::Ack(a) if acks.contains(a) => out = Some(ev.clone()),
                Match::Echo(h) if Some(h.as_str()) == pkt_hash => out = Some(ev.clone()),
                m => {
                    for s in sigs {
                        match (m, s) {
                            (Match::Response { peer, tag }, Sig::Response { peer: p, plain })
                                if peer == p && plain.len() >= 4 && tag.is_none_or(|t| plain[..4] == t.to_le_bytes()) =>
                            {
                                let mut e = ev.clone();
                                e["response_hex"] = json!(hex::encode(plain));
                                out = Some(e);
                            }
                            (Match::Cli { peer }, Sig::Cli { peer: p, text }) if peer == p => {
                                let mut e = ev.clone();
                                e["cli_reply"] = json!(text);
                                out = Some(e);
                            }
                            (Match::Discover(t), Sig::Discover(tt)) if t == tt => out = Some(ev.clone()),
                            _ => {}
                        }
                    }
                }
            }
            match out {
                Some(e) => w.tx.send(e).is_ok(),
                None => true,
            }
        });
    }

    /// Learned direct route to a peer, else flood.
    fn route_to(&self, peer: &[u8; 32]) -> Route {
        match self.out_paths.lock().unwrap().get(peer) {
            Some((l, p)) => Route::Direct { path_len: *l, path: p.clone() },
            None => self.flood(),
        }
    }

    /// Queue a packet and wait for the radio to send it.
    fn transmit(&self, p: &Packet, meta: TxMeta, delay: Duration) -> Result<TxReport> {
        let (dtx, drx) = channel();
        self.tx_queue.lock().unwrap().send(TxJob { frame: p.encode(), meta, delay, done: Some(dtx) })?;
        drx.recv_timeout(Duration::from_secs(60)).map_err(|_| anyhow!("tx queue timeout"))?.map_err(|e| anyhow!(e))
    }
}

fn meta(p: &Packet, route: &Route, dest: Option<String>, data: Value, attempt: u32) -> TxMeta {
    TxMeta { route: route.name(), dest, data, attempt, pkt_hash: hex::encode(p.hash()) }
}

fn report_json(r: &TxReport, attempt: u32, route: &Route) -> Value {
    json!({"tx_frame_id": r.id, "tx_time": r.tx_time, "len": r.len, "airtime_ms": r.airtime_ms, "attempt": attempt, "route": route.name()})
}

/// Collect echoes (our packet repeated) for `wait_s`.
fn echoes(rx: &std::sync::mpsc::Receiver<Value>, wait_s: f64) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs_f64(wait_s.max(0.0));
    let mut out = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        let Ok(ev) = rx.recv_timeout(left) else { break };
        out.push(echo_json(&ev));
    }
    out
}

fn echo_json(ev: &Value) -> Value {
    json!({"frame_id": ev["frame_id"], "rx_time": ev["rx_time"], "path": ev["path"], "last_hop": ev["path"].as_array().and_then(|a| a.last()).cloned(), "rssi": ev["rssi"], "snr": ev["snr"]})
}

fn advert(sh: &Shared, req: &Value) -> Result<Value> {
    let me = sh.me()?;
    let flood = req["flood"].as_bool().unwrap_or(false);
    let route = if flood { sh.flood() } else { Route::zero_hop() };
    let n = &sh.cfg.node;
    let loc = n.latitude.zip(n.longitude);
    let app = mesh::app_data(crate::config::adv_type_code(&n.adv_type)?, &n.name, loc);
    let ts = sh.timestamp();
    let p = mesh::advert(&me, ts, &app, &route);
    let h = hex::encode(p.hash());
    let (wid, rx) = sh.wait_for(Match::Echo(h.clone()));
    let data = json!({"timestamp": ts, "name": n.name, "adv_type": n.adv_type, "latitude": n.latitude, "longitude": n.longitude});
    let r = sh.transmit(&p, meta(&p, &route, None, data, 0), Duration::from_millis(rand::random::<u64>() % 400));
    let r = match r {
        Ok(r) => r,
        Err(e) => {
            sh.unwait(&[wid]);
            return Err(e);
        }
    };
    let heard = echoes(&rx, req["wait_s"].as_f64().unwrap_or(if flood { 15.0 } else { 5.0 }));
    sh.unwait(&[wid]);
    Ok(json!({"pkt_hash": h, "route": route.name(), "timestamp": ts, "transmission": report_json(&r, 0, &route), "echoes": heard}))
}

fn send_channel(sh: &Shared, req: &Value) -> Result<Value> {
    let name = req["channel"].as_str().ok_or_else(|| anyhow!("channel required"))?;
    let text = req["text"].as_str().ok_or_else(|| anyhow!("text required"))?;
    let ch = sh.keys.read().unwrap().channels.iter().find(|c| c.name == name).cloned().ok_or_else(|| anyhow!("unknown channel {name}"))?;
    let route = sh.flood();
    let ts = sh.timestamp();
    let p = mesh::group_text(&ch.secret, ch.hash, ts, &sh.cfg.node.name, text, &route)?;
    let h = hex::encode(p.hash());
    let (wid, rx) = sh.wait_for(Match::Echo(h.clone()));
    let data = json!({"channel": name, "timestamp": ts, "text": text});
    let r = sh.transmit(&p, meta(&p, &route, Some(name.to_string()), data, 0), Duration::from_millis(rand::random::<u64>() % 400));
    let r = match r {
        Ok(r) => r,
        Err(e) => {
            sh.unwait(&[wid]);
            return Err(e);
        }
    };
    let heard = echoes(&rx, req["wait_s"].as_f64().unwrap_or(10.0));
    sh.unwait(&[wid]);
    Ok(json!({"pkt_hash": h, "channel": name, "timestamp": ts, "transmission": report_json(&r, 0, &route), "echoes": heard}))
}

/// DM with ACK wait and retries. Direct when a path is known (last attempt floods), else flood.
fn send_text(sh: &Shared, req: &Value) -> Result<Value> {
    let me = sh.me()?;
    let to = req["to"].as_str().ok_or_else(|| anyhow!("to required (64 hex public key)"))?;
    let peer: [u8; 32] = hex::decode(to).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("to must be a 64-hex public key"))?;
    let text = req["text"].as_str().ok_or_else(|| anyhow!("text required"))?;
    let retries = req["retries"].as_u64().unwrap_or(2) as u32;
    let force_flood = req["flood"].as_bool().unwrap_or(false);
    let extra_wait = req["extra_wait_s"].as_f64().unwrap_or(3.0);
    let ts = sh.timestamp();
    let mut txs = Vec::new();
    let mut echoes_heard = Vec::new();
    let mut waiters = Vec::new();
    let mut ack_rx = Vec::new();
    let mut result = None;
    'attempts: for attempt in 0..=retries {
        let path = sh.out_paths.lock().unwrap().get(&peer).cloned();
        let route = match path {
            Some((path_len, path)) if !force_flood && attempt < retries => Route::Direct { path_len, path },
            _ => sh.flood(),
        };
        let (plain, ack) = mesh::text_plain(&me, ts, attempt as u8, text)?;
        let p = mesh::datagram(ptype::TXT_MSG, &me, &peer, &plain, &route)?;
        let (wa, ra) = sh.wait_for(Match::Ack(ack));
        let (we, re) = sh.wait_for(Match::Echo(hex::encode(p.hash())));
        waiters.extend([wa, we]);
        ack_rx.push((attempt, ack, route.name(), ra));
        let data = json!({"to": to, "timestamp": ts, "text": text, "expected_ack": format!("{ack:08x}")});
        let r = match sh.transmit(&p, meta(&p, &route, Some(to.to_string()), data, attempt), Duration::from_millis(rand::random::<u64>() % 400)) {
            Ok(r) => r,
            Err(e) => {
                sh.unwait(&waiters);
                return Err(e);
            }
        };
        let t_sent = Instant::now();
        txs.push(report_json(&r, attempt, &route));
        let deadline = t_sent + Duration::from_secs_f64(mesh::ack_timeout_ms(&route, r.airtime_ms) / 1000.0 + extra_wait);
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            let step = left.min(Duration::from_millis(100));
            while let Ok(ev) = re.try_recv() {
                echoes_heard.push(echo_json(&ev));
            }
            // An ACK for any attempt so far confirms delivery.
            for (a, code, rname, ra) in &ack_rx {
                if let Ok(ev) = ra.try_recv() {
                    result = Some(json!({"acked": true, "ack_attempt": a, "ack_code": format!("{code:08x}"), "ack_route_sent": rname,
                        "rtt_ms": (t_sent.elapsed().as_secs_f64() * 1000.0).round(), "ack_frame_id": ev["frame_id"],
                        "ack_via": ev["payload_type"], "ack_path": ev["path"], "ack_rssi": ev["rssi"], "ack_snr": ev["snr"]}));
                    break 'attempts;
                }
            }
            std::thread::sleep(step);
        }
    }
    sh.unwait(&waiters);
    let mut out = result.unwrap_or_else(|| json!({"acked": false}));
    out["to"] = json!(to);
    out["timestamp"] = json!(ts);
    out["transmissions"] = json!(txs);
    out["echoes"] = json!(echoes_heard);
    out["out_path"] = json!(sh.out_paths.lock().unwrap().get(&peer).map(|(l, p)| json!({"path_len": l, "path": hex::encode(p)})));
    Ok(out)
}

fn peer_key(req: &Value) -> Result<[u8; 32]> {
    let to = req["to"].as_str().ok_or_else(|| anyhow!("to required (64 hex public key)"))?;
    hex::decode(to).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("to must be a 64-hex public key"))
}

/// Send `p` and wait for the first event on `rx`: firmware timeout for the route plus `extra_s`.
fn exchange(sh: &Shared, p: &Packet, route: &Route, m: TxMeta, rx: &std::sync::mpsc::Receiver<Value>, extra_s: f64) -> Result<(Value, Option<Value>, f64)> {
    let r = sh.transmit(p, m, Duration::from_millis(rand::random::<u64>() % 300))?;
    let t0 = Instant::now();
    let timeout = Duration::from_secs_f64(mesh::ack_timeout_ms(route, r.airtime_ms) / 1000.0 + extra_s);
    let ev = rx.recv_timeout(timeout).ok();
    Ok((report_json(&r, 0, route), ev, (t0.elapsed().as_secs_f64() * 1000.0).round()))
}

fn rf(ev: &Value) -> Value {
    json!({"frame_id": ev["frame_id"], "payload_type": ev["payload_type"], "route": ev["route"], "path": ev["path"], "rssi": ev["rssi"], "snr": ev["snr"]})
}

fn discover(sh: &Shared, req: &Value) -> Result<Value> {
    let tag: u32 = rand::random();
    let filter = req["type_filter"].as_u64().unwrap_or(1 << 2) as u8; // default: repeaters
    let route = Route::zero_hop();
    let p = mesh::control(repeater::discover_payload(filter, tag), &route);
    let (wid, rx) = sh.wait_for(Match::Discover(tag));
    let r = sh.transmit(&p, meta(&p, &route, None, json!({"discover_tag": format!("{tag:08x}"), "type_filter": filter}), 0), Duration::ZERO);
    let mut found = Vec::new();
    if r.is_ok() {
        let deadline = Instant::now() + Duration::from_secs_f64(req["wait_s"].as_f64().unwrap_or(8.0));
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            let Ok(ev) = rx.recv_timeout(left) else { break };
            // Name from the node table when known (adverts / owner info).
            let key = ev["data"]["public_key"].as_str().unwrap_or_default().to_string();
            let name = store::open_ro(&sh.db).ok().and_then(|c| {
                store::query_json(&c, "SELECT name FROM nodes WHERE public_key=?1", &[&key]).ok()?.into_iter().next()
            });
            found.push(json!({"public_key": key, "name": name.map(|n| n["name"].clone()), "node_type": ev["data"]["node_type"],
                "snr_at_node_db": ev["data"]["snr"], "rssi": ev["rssi"], "snr": ev["snr"], "frame_id": ev["frame_id"]}));
        }
    }
    sh.unwait(&[wid]);
    let r = r?;
    Ok(json!({"tag": format!("{tag:08x}"), "transmission": report_json(&r, 0, &route), "responses": found}))
}

/// Login (ANON_REQ with password). Retries with a fresh timestamp (firmware replay protection).
fn login(sh: &Shared, peer: [u8; 32], password: &str, room: bool, retries: u32) -> Result<Value> {
    let me = sh.me()?;
    let mut txs = Vec::new();
    for attempt in 0..=retries {
        let route = if attempt == retries && attempt > 0 { sh.flood() } else { sh.route_to(&peer) };
        let ts = sh.timestamp();
        let plain = repeater::login_plain(ts, password, room.then_some(ts));
        let p = mesh::anon_req(&me, &peer, &plain, &route)?;
        let (wid, rx) = sh.wait_for(Match::Response { peer, tag: None });
        let m = meta(&p, &route, Some(hex::encode(peer)), json!({"login": true, "attempt": attempt}), attempt);
        let res = exchange(sh, &p, &route, m, &rx, 4.0);
        sh.unwait(&[wid]);
        let (tx, ev, ms) = res?;
        txs.push(tx);
        if let Some(ev) = ev {
            let b = hex::decode(ev["response_hex"].as_str().unwrap_or_default())?;
            let mut v = repeater::parse_login(&b);
            v["rtt_ms"] = json!(ms);
            v["rf"] = rf(&ev);
            v["transmissions"] = json!(txs);
            if v["ok"] == true {
                sh.logins.lock().unwrap().insert(peer, v.clone());
            }
            if let Ok(c) = store::open_rw(&sh.db) {
                let _ = store::insert_report(&c, &hex::encode(peer), "login", &v);
            }
            return Ok(v);
        }
    }
    Ok(json!({"ok": false, "error": "no response (wrong password gets no reply)", "transmissions": txs}))
}

/// Log in first when not logged in this daemon session and a password is given.
fn ensure_login(sh: &Shared, peer: [u8; 32], req: &Value) -> Result<Option<Value>> {
    if sh.logins.lock().unwrap().contains_key(&peer) {
        return Ok(None);
    }
    let Some(pw) = req["password"].as_str() else { return Ok(None) };
    let v = login(sh, peer, pw, req["room"].as_bool().unwrap_or(false), 1)?;
    if v["ok"] != true {
        bail!("login failed: {v}");
    }
    Ok(Some(v))
}

/// Response plaintext, RF of the response frame, round trip ms.
type Reply = (Vec<u8>, Value, f64);

/// One REQ round trip; retries with fresh timestamps.
fn req_once(sh: &Shared, peer: [u8; 32], req_type: u8, offset: u16, retries: u32) -> Result<(Option<Reply>, Vec<Value>)> {
    let me = sh.me()?;
    let mut txs = Vec::new();
    for attempt in 0..=retries {
        let route = if attempt == retries && attempt > 0 { sh.flood() } else { sh.route_to(&peer) };
        let ts = sh.timestamp();
        let p = mesh::datagram(ptype::REQ, &me, &peer, &repeater::request_plain(ts, req_type, offset), &route)?;
        let (wid, rx) = sh.wait_for(Match::Response { peer, tag: Some(ts) });
        let m = meta(&p, &route, Some(hex::encode(peer)), json!({"request": req_type, "offset": offset, "tag": ts}), attempt);
        let res = exchange(sh, &p, &route, m, &rx, 4.0);
        sh.unwait(&[wid]);
        let (tx, ev, ms) = res?;
        txs.push(tx);
        if let Some(ev) = ev {
            let b = hex::decode(ev["response_hex"].as_str().unwrap_or_default())?;
            return Ok((Some((b, rf(&ev), ms)), txs));
        }
    }
    Ok((None, txs))
}

fn request(sh: &Shared, req: &Value) -> Result<Value> {
    let peer = peer_key(req)?;
    let kind = req["kind"].as_str().ok_or_else(|| anyhow!("kind required"))?;
    let rt = repeater::kind(kind).ok_or_else(|| anyhow!("unknown kind {kind} (status, telemetry, neighbours, acl, owner)"))?;
    let retries = req["retries"].as_u64().unwrap_or(1) as u32;
    let login = ensure_login(sh, peer, req)?;
    let mut txs = Vec::new();
    let mut out = json!({"to": hex::encode(peer), "kind": kind});
    if let Some(l) = login {
        out["login"] = l;
    }
    let data = if rt == repeater::REQ_NEIGHBOURS {
        let mut all = Vec::new();
        let mut total = 0;
        loop {
            let (r, t) = req_once(sh, peer, rt, all.len() as u16, retries)?;
            txs.extend(t);
            let Some((b, rfv, ms)) = r else { break };
            let (tot, page) = repeater::parse_neighbours(&b).map_err(|e| anyhow!(e))?;
            total = tot;
            out["rf"] = rfv;
            out["rtt_ms"] = json!(ms);
            let n = page.len();
            all.extend(page);
            if n == 0 || all.len() >= total as usize {
                break;
            }
        }
        if out.get("rf").is_none() { None } else { Some(json!({"total": total, "neighbours": all})) }
    } else {
        let (r, t) = req_once(sh, peer, rt, 0, retries)?;
        txs = t;
        match r {
            Some((b, rfv, ms)) => {
                out["rf"] = rfv;
                out["rtt_ms"] = json!(ms);
                Some(match rt {
                    repeater::REQ_STATUS => repeater::parse_status(&b).map_err(|e| anyhow!(e))?,
                    repeater::REQ_TELEMETRY => json!({"sensors": repeater::parse_lpp(&b[4..])}),
                    repeater::REQ_ACL => json!({"entries": repeater::parse_acl(&b)}),
                    _ => repeater::parse_owner(&b),
                })
            }
            None => None,
        }
    };
    out["transmissions"] = json!(txs);
    match data {
        Some(d) => {
            if let Ok(c) = store::open_rw(&sh.db) {
                let _ = store::insert_report(&c, &hex::encode(peer), kind, &d);
            }
            out["ok"] = json!(true);
            out["data"] = d;
        }
        None => {
            out["ok"] = json!(false);
            out["error"] = json!("no response (not logged in, no permission, or out of range)");
        }
    }
    Ok(out)
}

/// Remote CLI command. Not retried by default: a retry with a new timestamp executes the command again.
fn cli(sh: &Shared, req: &Value) -> Result<Value> {
    let peer = peer_key(req)?;
    let command = req["command"].as_str().ok_or_else(|| anyhow!("command required"))?;
    let me = sh.me()?;
    let login = ensure_login(sh, peer, req)?;
    let retries = req["retries"].as_u64().unwrap_or(0) as u32;
    let mut txs = Vec::new();
    let mut out = json!({"to": hex::encode(peer), "command": command});
    if let Some(l) = login {
        out["login"] = l;
    }
    for attempt in 0..=retries {
        let route = sh.route_to(&peer);
        let ts = sh.timestamp();
        let p = mesh::datagram(ptype::TXT_MSG, &me, &peer, &mesh::cli_plain(ts, command)?, &route)?;
        let (wid, rx) = sh.wait_for(Match::Cli { peer });
        let m = meta(&p, &route, Some(hex::encode(peer)), json!({"cli": command}), attempt);
        let res = exchange(sh, &p, &route, m, &rx, req["wait_s"].as_f64().unwrap_or(5.0));
        sh.unwait(&[wid]);
        let (tx, ev, ms) = res?;
        txs.push(tx);
        if let Some(ev) = ev {
            out["ok"] = json!(true);
            out["reply"] = ev["cli_reply"].clone();
            out["rtt_ms"] = json!(ms);
            out["rf"] = rf(&ev);
            if let Ok(c) = store::open_rw(&sh.db) {
                let _ = store::insert_report(&c, &hex::encode(peer), "cli", &json!({"command": command, "reply": ev["cli_reply"]}));
            }
            out["transmissions"] = json!(txs);
            return Ok(out);
        }
    }
    out["ok"] = json!(false);
    out["error"] = json!("no reply (not logged in as admin, unknown command, or out of range)");
    out["transmissions"] = json!(txs);
    Ok(out)
}

fn handle_line(line: &str, w: &mut TcpStream, sh: &Shared) -> std::io::Result<()> {
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return writeln!(w, "{}", json!({"error": format!("bad request: {e}")})),
    };
    let cmd = req["cmd"].as_str().unwrap_or_default();
    let res = match cmd {
        "status" => {
            let mut s = sh.status.lock().unwrap().clone();
            s["frames"] = json!(sh.frames.load(Ordering::Relaxed));
            s["known_peer_keys"] = json!(sh.keys.read().unwrap().peers.values().map(Vec::len).sum::<usize>());
            s["known_out_paths"] = json!(sh.out_paths.lock().unwrap().len());
            s["tx_airtime_last_hour_ms"] = json!(sh.airtime.last_hour_ms());
            s["duty_cycle_limit"] = json!(sh.cfg.node.duty_cycle_limit);
            s["duty_cycle_enforce"] = json!(sh.cfg.node.duty_cycle_enforce);
            return writeln!(w, "{s}");
        }
        "subscribe" => {
            writeln!(w, "{}", json!({"subscribed": true}))?;
            sh.subscribers.add(w.try_clone()?);
            return Ok(());
        }
        "advert" => advert(sh, &req),
        "send_text" => send_text(sh, &req),
        "send_channel" => send_channel(sh, &req),
        "discover" => discover(sh, &req),
        "login" => peer_key(&req).and_then(|p| {
            let pw = req["password"].as_str().ok_or_else(|| anyhow!("password required"))?;
            login(sh, p, pw, req["room"].as_bool().unwrap_or(false), req["retries"].as_u64().unwrap_or(1) as u32)
        }),
        "request" => request(sh, &req),
        "cli" => cli(sh, &req),
        other => Err(anyhow!("unknown cmd {other:?}")),
    };
    let out = res.unwrap_or_else(|e| json!({"error": format!("{e:#}")}));
    let mut logged = req.clone();
    if logged.get("password").is_some() {
        logged["password"] = json!(crate::config::REDACTED);
    }
    if let Ok(c) = store::open_rw(&sh.db) {
        let _ = meshtadpole_radio::store::log_request(&c, &logged, &out);
    }
    writeln!(w, "{out}")
}

struct Mc {
    sh: Arc<Shared>,
    w: Writer,
}

/// ACK codes carried by a frame (ACK, multipart ACK, PATH with ACK extra).
fn ack_codes(d: &Decoded) -> Vec<u32> {
    let Some(p) = &d.packet else { return vec![] };
    let pl = &p.payload;
    let le = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    match p.ptype() {
        ptype::ACK if pl.len() >= 4 => vec![le(pl)],
        ptype::MULTIPART if pl.len() >= 5 && pl[0] & 0x0F == ptype::ACK => vec![le(&pl[1..])],
        ptype::PATH => match &d.peer_plain {
            Some((_, "in", b)) => {
                let n = (b[0] & 63) as usize * ((b[0] >> 6) as usize + 1);
                if b.len() >= 1 + n + 5 && b[1 + n] & 0x0F == ptype::ACK { vec![le(&b[2 + n..])] } else { vec![] }
            }
            _ => vec![],
        },
        _ => vec![],
    }
}

/// Waiter signals in a decoded frame: responses (RESPONSE or PATH+RESPONSE), CLI replies, DISCOVER_RESP tags.
fn signals(d: &Decoded) -> Vec<Sig> {
    let mut v = Vec::new();
    let Some(p) = &d.packet else { return v };
    match (p.ptype(), &d.peer_plain) {
        (ptype::RESPONSE, Some((peer, "in", b))) => v.push(Sig::Response { peer: *peer, plain: b.clone() }),
        (ptype::PATH, Some((peer, "in", b))) if !b.is_empty() => {
            let n = (b[0] & 63) as usize * ((b[0] >> 6) as usize + 1);
            if b.len() > 1 + n && b[1 + n] & 0x0F == ptype::RESPONSE {
                v.push(Sig::Response { peer: *peer, plain: b[2 + n..].to_vec() });
            }
        }
        (ptype::TXT_MSG, Some((peer, "in", b))) if b.len() > 5 && b[4] >> 2 == 1 => {
            let end = b[5..].iter().position(|&x| x == 0).map(|i| 5 + i).unwrap_or(b.len());
            v.push(Sig::Cli { peer: *peer, text: String::from_utf8_lossy(&b[5..end]).into_owned() });
        }
        (ptype::CONTROL, _) if p.payload.len() >= 6 && p.payload[0] >> 4 == 0x9 => {
            v.push(Sig::Discover(u32::from_le_bytes([p.payload[2], p.payload[3], p.payload[4], p.payload[5]])));
        }
        _ => {}
    }
    v
}

impl Mc {
    fn job(
&self, p: Packet, route: &Route, dest: &[u8; 32], data: Value, delay_ms: u64) -> Job {
        let m = meta(&p, route, Some(hex::encode(dest)), data, 0);
        TxJob { frame: p.encode(), meta: m, delay: Duration::from_millis(delay_ms + rand::random::<u64>() % 300), done: None }
    }

    /// Replies to a first reception addressed to us: ACK for text messages (inside a PATH return when the
    /// message came by flood, as firmware), store learned paths, reciprocal PATH return for flooded PATHs.
    fn respond(&mut self, d: &Decoded) -> Result<Vec<Job>> {
        let (Some(p), Some((peer, "in", b))) = (&d.packet, &d.peer_plain) else { return Ok(vec![]) };
        let me = self.sh.me()?;
        let peer = *peer;
        let flood = self.sh.flood();
        let direct_or_flood = |sh: &Shared| match sh.out_paths.lock().unwrap().get(&peer) {
            Some((l, path)) => Route::Direct { path_len: *l, path: path.clone() },
            None => sh.flood(),
        };
        let mut out = Vec::new();
        match p.ptype() {
            ptype::TXT_MSG if b.len() >= 5 => {
                let tt = b[4] >> 2;
                let body = match tt {
                    0 => {
                        let tl = b[5..].iter().position(|&x| x == 0).unwrap_or(b.len() - 5);
                        mesh::ack_body(mesh::ack_for_plain(b, &peer), b.get(5 + tl + 1).copied().unwrap_or(0))
                    }
                    2 if b.len() >= 9 => mesh::ack_for_signed(b, &me).to_le_bytes().to_vec(),
                    _ => return Ok(vec![]), // CLI data/commands: no ACK
                };
                let data = json!({"reply": "ack", "ack": hex::encode(&body)});
                if p.is_flood() {
                    let pk = mesh::path_return(&me, &peer, p.path_len, &p.path, Some((ptype::ACK, &body)), &flood)?;
                    out.push(self.job(pk, &flood, &peer, data, 200));
                } else {
                    let r = direct_or_flood(&self.sh);
                    out.push(self.job(mesh::ack(&body, &r), &r, &peer, data, 200));
                }
            }
            ptype::PATH if !b.is_empty() => {
                let l = b[0];
                let n = (l & 63) as usize * ((l >> 6) as usize + 1);
                if (l >> 6) < 3 && b.len() > n {
                    let path = b[1..1 + n].to_vec();
                    self.w.set_out_path(&hex::encode(peer), l, &path)?;
                    self.sh.out_paths.lock().unwrap().insert(peer, (l, path.clone()));
                    if p.is_flood() {
                        // Let the peer learn the route to us too, sent along the route we just learned.
                        let r = Route::Direct { path_len: l, path };
                        let pk = mesh::path_return(&me, &peer, p.path_len, &p.path, None, &r)?;
                        out.push(self.job(pk, &r, &peer, json!({"reply": "reciprocal_path"}), 500));
                    }
                }
            }
            _ => {}
        }
        Ok(out)
    }
}

impl link::Handler for Mc {
    type Meta = TxMeta;

    fn event(&mut self, ev: &link::Event) -> Result<(), link::BoxError> {
        self.w.s.radio_event(ev.name(), ev.detail())?;
        let mut st = self.sh.status.lock().unwrap();
        match ev {
            link::Event::Connected { usb_serial } => {
                st["radio"] = json!("connected");
                st["usb_serial"] = json!(usb_serial);
            }
            link::Event::Disconnected { .. } => st["radio"] = json!("disconnected"),
            _ => {}
        }
        eprintln!("{}", json!({"event": ev.name(), "detail": ev.detail()}));
        Ok(())
    }

    fn frame(&mut self, t: f64, f: &sx1262::RxFrame, airtime: f64) -> Result<Vec<Job>, link::BoxError> {
        let sh = self.sh.clone();
        let d = decode_frame(&f.data, f.crc_error, &sh.keys.read().unwrap());
        if d.status == Status::Ok && d.packet.as_ref().is_some_and(|p| p.ptype() == ptype::ADVERT) {
            if let Some(k) = d.src_key.as_deref().and_then(|h| hex::decode(h).ok()).and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()) {
                sh.keys.write().unwrap().add_peer(k);
            }
        }
        let (id, dup_of) = self.w.insert_frame(t, f, airtime, &d)?;
        sh.frames.fetch_add(1, Ordering::Relaxed);
        let mut ev = to_json(&d);
        ev["frame_id"] = json!(id);
        ev["rx_time"] = json!(t);
        ev["rssi"] = json!(f.rssi_dbm);
        ev["snr"] = json!(f.snr_db);
        ev["freq_error_hz"] = json!(f.freq_error_hz.round());
        ev["len"] = json!(f.data.len());
        ev["airtime_ms"] = json!((airtime * 10.0).round() / 10.0);
        ev["dup_of"] = json!(dup_of);
        sh.subscribers.broadcast(&ev.to_string());
        if d.status == Status::CrcError {
            return Ok(vec![]);
        }
        let sigs = signals(&d);
        if let Some(p) = d.packet.as_ref().filter(|p| p.ptype() == ptype::CONTROL && d.status == Status::Ok) {
            // DISCOVER_RESP with a full key: known node, direct neighbour.
            if p.payload.first().is_some_and(|b| b >> 4 == 0x9) {
                if let Some(k) = d.src_key.as_deref() {
                    let kt = d.data.as_ref().and_then(|v| v["node_type"].as_str()).unwrap_or("unknown").to_string();
                    self.w.upsert_discovered(t, k, &kt, id, f.rssi_dbm, f.snr_db)?;
                    if let Some(kb) = hex::decode(k).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()) {
                        sh.keys.write().unwrap().add_peer(kb);
                    }
                }
            }
        }
        sh.notify(&ack_codes(&d), d.pkt_hash.as_deref(), &sigs, &ev);
        if dup_of.is_some() || d.status != Status::Ok {
            return Ok(vec![]);
        }
        Ok(self.respond(&d)?)
    }

    fn header_error(&mut self, t: f64, rssi: f32) -> Result<(), link::BoxError> {
        let id = self.w.insert_header_error(t, rssi)?;
        self.sh.subscribers.broadcast(&json!({"frame_id": id, "rx_time": t, "status": "header_error", "rssi": rssi}).to_string());
        Ok(())
    }

    fn transmitted(&mut self, job: &Job, t: f64, airtime: f64, error: Option<&str>) -> Result<i64, link::BoxError> {
        let m = &job.meta;
        let pt = ptype_name((job.frame[0] >> 2) & 0x0F);
        Ok(self.w.insert_tx(t, &job.frame, airtime, m.route, &pt, &m.pkt_hash, m.dest.as_deref(), &m.data, m.attempt, error)?)
    }

    fn stats(&mut self, s: &link::Stats) -> Result<(), link::BoxError> {
        Ok(self.w.s.radio_stats(s)?)
    }

    fn heartbeat(&mut self) -> Result<(), link::BoxError> {
        Ok(self.w.s.heartbeat()?)
    }
}

pub fn run(cfg: &Config, db: &Path) -> Result<()> {
    let listener = TcpListener::bind(&cfg.api).with_context(|| format!("bind API {} (daemon already running?)", cfg.api))?;
    let lora = cfg.lora()?;
    let me = cfg.identity()?;
    let c = store::open_rw(db)?;
    let mut keys = Keys { me: me.clone(), channels: cfg.channels()?, ..Default::default() };
    for k in store::load_peer_keys(&c)? {
        keys.add_peer(k);
    }
    let out_paths: HashMap<[u8; 32], (u8, Vec<u8>)> = store::load_out_paths(&c)?.into_iter().map(|(k, l, p)| (k, (l, p))).collect();
    let w = Writer { me: me.as_ref().map(|m| m.public_hex()), s: Session::start(c, env!("CARGO_PKG_VERSION"), "", &lora, &serde_json::to_string(&cfg.redacted())?)? };
    let (qtx, qrx) = channel::<Job>();
    let airtime = Arc::new(Airtime::default());
    let sh = Arc::new(Shared {
        cfg: cfg.clone(),
        db: db.to_path_buf(),
        keys: RwLock::new(keys),
        out_paths: Mutex::new(out_paths),
        subscribers: api::Subscribers::default(),
        waiters: Mutex::new(Vec::new()),
        next_waiter: AtomicU64::new(1),
        tx_queue: Mutex::new(qtx),
        airtime: airtime.clone(),
        last_ts: Mutex::new(0),
        logins: Mutex::new(HashMap::new()),
        status: Mutex::new(Value::Null),
        frames: AtomicU64::new(0),
        stop: AtomicBool::new(false),
    });
    *sh.status.lock().unwrap() = json!({
        "pid": std::process::id(),
        "session_id": w.s.id,
        "started": store::now(),
        "radio": "disconnected",
        "usb_serial": null,
        "db": db.display().to_string(),
        "name": cfg.node.name,
        "public_key": me.as_ref().map(|m| m.public_hex()),
        "path_hash_size": cfg.node.path_hash_size,
        "freq_hz": lora.freq_hz, "bw_hz": lora.bw_hz, "sf": lora.sf, "cr": lora.cr,
        "sync_word": format!("0x{:02x}", lora.sync_word), "preamble_len": lora.preamble_len, "tx_power_dbm": lora.tx_power_dbm,
        "channels": cfg.channels.iter().map(|c| &c.name).collect::<Vec<_>>(),
    });
    {
        let sh = sh.clone();
        std::thread::spawn(move || api::serve(listener, move |line: &str, w: &mut TcpStream| handle_line(line, w, &sh)));
    }
    {
        let sh = sh.clone();
        ctrlc::set_handler(move || sh.stop.store(true, Ordering::SeqCst)).ok();
    }
    eprintln!("{}", json!({"event": "started", "status": *sh.status.lock().unwrap()}));
    let lc = link::LinkConfig {
        lora,
        usb_serial: cfg.usb_serial.clone(),
        duty_cycle_limit: cfg.node.duty_cycle_limit,
        duty_cycle_enforce: cfg.node.duty_cycle_enforce,
        stats_interval: Duration::from_secs(60),
        agc_reset_interval: cfg.radio.agc_reset_interval_s.filter(|&s| s > 0).map(Duration::from_secs),
    };
    let mut h = Mc { sh: sh.clone(), w };
    let res = link::run(&lc, &mut h, &qrx, &airtime, &sh.stop).map_err(|e| anyhow!(e));
    h.w.s.end()?;
    eprintln!("{}", json!({"event": "stopped", "error": res.as_ref().err().map(|e| format!("{e:#}"))}));
    res
}

/// Connect to a running daemon.
pub fn connect(api: &str) -> Result<TcpStream> {
    meshtadpole_radio::api::connect(api).with_context(|| format!("daemon not reachable at {api}"))
}

/// One request/response round trip with the daemon.
pub fn call(api: &str, req: &Value) -> Result<Value> {
    let line = meshtadpole_radio::api::call(api, &req.to_string()).with_context(|| format!("daemon not reachable at {api}"))?;
    let v: Value = serde_json::from_str(&line)?;
    if let Some(e) = v.get("error") {
        bail!("{}", e.as_str().unwrap_or(&e.to_string()));
    }
    Ok(v)
}
