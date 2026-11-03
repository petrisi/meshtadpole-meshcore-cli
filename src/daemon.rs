//! Daemon: owns the radio and identity, decodes and stores every frame, transmits on request,
//! answers messages addressed to us (ACK, PATH return), serves a local NDJSON API.
//!
//! API (TCP, one JSON object per line):
//! - `{"cmd":"status"}` -> status object.
//! - `{"cmd":"subscribe"}` -> stream of frame events until disconnect.
//! - `{"cmd":"advert","flood":bool,"wait_s":f}` -> transmission and echoes heard.
//! - `{"cmd":"send_text","to":"<64 hex key>","text":"..","retries":n,"flood":bool}` -> ACK result.
//! - `{"cmd":"send_channel","channel":"<name>","text":"..","wait_s":f}` -> transmission and echoes heard.

use crate::config::Config;
use crate::decode::{Decoded, Keys, Status, decode_frame, to_json};
use crate::mesh::{self, Route};
use crate::packet::{Packet, ptype, ptype_name};
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

    fn notify(&self, acks: &[u32], pkt_hash: Option<&str>, ev: &Value) {
        self.waiters.lock().unwrap().retain(|w| {
            let hit = match &w.m {
                Match::Ack(a) => acks.contains(a),
                Match::Echo(h) => Some(h.as_str()) == pkt_hash,
            };
            !hit || w.tx.send(ev.clone()).is_ok()
        });
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
        other => Err(anyhow!("unknown cmd {other:?}")),
    };
    let out = res.unwrap_or_else(|e| json!({"error": format!("{e:#}")}));
    if let Ok(c) = store::open_rw(&sh.db) {
        let _ = meshtadpole_radio::store::log_request(&c, &req, &out);
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

impl Mc {
    fn job(&self, p: Packet, route: &Route, dest: &[u8; 32], data: Value, delay_ms: u64) -> Job {
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
        sh.notify(&ack_codes(&d), d.pkt_hash.as_deref(), &ev);
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
