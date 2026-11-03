//! Daemon: owns the radio, decodes and stores every frame, serves a local NDJSON API.
//!
//! API (TCP, one JSON object per line):
//! - `{"cmd":"status"}` -> status object.
//! - `{"cmd":"subscribe"}` -> stream of frame events until disconnect.

use crate::config::Config;
use crate::decode::{Keys, decode_frame, to_json};
use crate::packet::ptype;
use crate::store::{self, Writer};
use anyhow::{Context, Result, anyhow, bail};
use meshtadpole_radio::link::{self, Airtime, TxJob};
use meshtadpole_radio::store::Session;
use meshtadpole_radio::{api, sx1262};
use serde_json::{Value, json};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// Per-transmission data handed through the radio link (TX arrives in phase 2).
pub struct TxMeta;

type Job = TxJob<TxMeta>;

struct Shared {
    cfg: Config,
    keys: RwLock<Keys>,
    subscribers: api::Subscribers,
    airtime: Arc<Airtime>,
    status: Mutex<Value>,
    frames: AtomicU64,
    stop: AtomicBool,
}

fn handle_line(line: &str, w: &mut TcpStream, sh: &Shared) -> std::io::Result<()> {
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return writeln!(w, "{}", json!({"error": format!("bad request: {e}")})),
    };
    match req["cmd"].as_str() {
        Some("status") => {
            let mut s = sh.status.lock().unwrap().clone();
            s["frames"] = json!(sh.frames.load(Ordering::Relaxed));
            s["known_peer_keys"] = json!(sh.keys.read().unwrap().peers.values().map(Vec::len).sum::<usize>());
            s["tx_airtime_last_hour_ms"] = json!(sh.airtime.last_hour_ms());
            s["duty_cycle_limit"] = json!(sh.cfg.node.duty_cycle_limit);
            s["duty_cycle_enforce"] = json!(sh.cfg.node.duty_cycle_enforce);
            writeln!(w, "{s}")
        }
        Some("subscribe") => {
            writeln!(w, "{}", json!({"subscribed": true}))?;
            sh.subscribers.add(w.try_clone()?);
            Ok(())
        }
        other => writeln!(w, "{}", json!({"error": format!("unknown cmd {other:?}")})),
    }
}

struct Mc {
    sh: Arc<Shared>,
    w: Writer,
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
        let sh = &self.sh;
        let d = decode_frame(&f.data, f.crc_error, &sh.keys.read().unwrap());
        if d.status == crate::decode::Status::Ok && d.packet.as_ref().is_some_and(|p| p.ptype() == ptype::ADVERT) {
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
        Ok(vec![])
    }

    fn header_error(&mut self, t: f64, rssi: f32) -> Result<(), link::BoxError> {
        let id = self.w.insert_header_error(t, rssi)?;
        self.sh.subscribers.broadcast(&json!({"frame_id": id, "rx_time": t, "status": "header_error", "rssi": rssi}).to_string());
        Ok(())
    }

    fn transmitted(&mut self, _job: &Job, _t: f64, _airtime: f64, _error: Option<&str>) -> Result<i64, link::BoxError> {
        Err("transmit not implemented".into())
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
    let w = Writer { s: Session::start(c, env!("CARGO_PKG_VERSION"), "", &lora, &serde_json::to_string(&cfg.redacted())?)? };
    let (_qtx, qrx) = channel::<Job>();
    let airtime = Arc::new(Airtime::default());
    let sh = Arc::new(Shared {
        cfg: cfg.clone(),
        keys: RwLock::new(keys),
        subscribers: api::Subscribers::default(),
        airtime: airtime.clone(),
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
        agc_reset_interval: None,
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
