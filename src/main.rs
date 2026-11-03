mod config;
mod crypto;
mod daemon;
mod decode;
mod mesh;
mod packet;
mod repeater;
mod store;
mod topology;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use config::Config;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

/// Exit codes.
mod exit {
    pub const ERROR: i32 = 1;
    pub const NO_DEVICE: i32 = 3;
    pub const NO_DAEMON: i32 = 4;
}

#[derive(Parser)]
#[command(name = "tadpole-mc", version, about = "MeshCore node for the MeshTadpole SX1262 USB stick. JSON output.")]
struct Cli {
    /// Config file [default: <data dir>/meshtadpole/meshcore.json; env TADPOLE_MC_CONFIG]
    #[arg(long, global = true, env = "TADPOLE_MC_CONFIG")]
    config: Option<PathBuf>,
    /// SQLite database [default: <data dir>/meshtadpole/meshcore.db; env TADPOLE_MC_DB]
    #[arg(long, global = true, env = "TADPOLE_MC_DB")]
    db: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List attached MeshTadpole/CH341 sticks.
    Devices,
    /// Show effective config, derived LoRa parameters, channel hashes and paths. Private key is redacted.
    Config {
        /// Write the effective config to the config file.
        #[arg(long)]
        write: bool,
        /// Set a value by dotted path and write the file, e.g. `--set radio.tx_power_dbm=20`.
        /// Value is parsed as JSON, else taken as string. `channels` takes a JSON array. Restart the daemon to apply.
        #[arg(long, value_name = "PATH=VALUE")]
        set: Vec<String>,
    },
    /// Our identity: name, type, public key and hash derived from node.private_key.
    Identity {
        /// Generate a new key pair and write it to the config file (refused if one exists).
        #[arg(long)]
        generate: bool,
        /// With --generate: replace an existing key. The old identity is lost.
        #[arg(long)]
        force: bool,
    },
    /// Run the daemon in the foreground (owns the radio, writes the DB, serves the API).
    Daemon,
    /// Transmit our signed advert. Default zero hop (direct neighbours only); --flood to propagate.
    Advert {
        #[arg(long)]
        flood: bool,
        /// Seconds to collect echoes (repeaters relaying our advert) [default: 5 zero hop, 15 flood].
        #[arg(long)]
        wait: Option<f64>,
    },
    /// Send a text. TO: `#name` or a configured channel name prefixed `ch:` (channel message, no ACK),
    /// else a node name, public key or key prefix (DM with ACK; direct when a path is known, else flood).
    Send {
        to: String,
        text: String,
        /// DM: always flood (ignore learned path).
        #[arg(long)]
        flood: bool,
        /// DM: retransmissions without ACK (last attempt floods).
        #[arg(long, default_value_t = 2)]
        retries: u32,
        /// Channel: seconds to collect echoes. DM: extra seconds added to the firmware ACK timeout.
        #[arg(long)]
        wait: Option<f64>,
    },
    /// Daemon status.
    Status,
    /// Stream received frames from the daemon as NDJSON.
    Listen {
        /// Only frames with status=ok.
        #[arg(long)]
        ok_only: bool,
        /// Exit after N seconds.
        #[arg(long)]
        seconds: Option<u64>,
    },
    /// Query stored packets (v_packets), newest first.
    Packets {
        /// Only frames newer than N seconds ago.
        #[arg(long)]
        since: Option<f64>,
        /// Payload type name (ADVERT, GRP_TXT, TXT_MSG, ACK, PATH, REQ, RESPONSE, ANON_REQ, TRACE, CONTROL, ...).
        #[arg(long = "type")]
        ptype: Option<String>,
        /// Sender public key or hex prefix (matches src_key, or src_hash when 1 byte).
        #[arg(long)]
        from: Option<String>,
        /// Frames whose flood path contains this repeater hash (hex).
        #[arg(long)]
        via: Option<String>,
        /// Filter by status (ok, crc_error, header_error, malformed, bad_signature, no_channel, encrypted, decode_error).
        #[arg(long)]
        status: Option<String>,
        /// Channel name.
        #[arg(long)]
        channel: Option<String>,
        /// Include duplicate receptions (other copies of the same packet).
        #[arg(long)]
        dups: bool,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Nodes known from adverts, most recently heard first.
    Nodes {
        /// Only nodes heard within N seconds.
        #[arg(long)]
        since: Option<f64>,
        /// Filter by advert type (chat, repeater, room, sensor).
        #[arg(long = "type")]
        adv_type: Option<String>,
    },
    /// One node by name, public key or key prefix: summary plus recent adverts.
    Node { id: String },
    /// Zero-hop DISCOVER request: direct neighbours of the given types answer with key and the SNR they hear us at.
    /// Answering nodes are added to the node table.
    Discover {
        /// Comma list of types: repeater (default), room, chat, sensor.
        #[arg(long, default_value = "repeater")]
        types: String,
        #[arg(long, default_value_t = 8.0)]
        wait: f64,
    },
    /// Log in to a repeater / room server with the password from config `passwords` (or --password).
    Login {
        node: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Management request to repeaters/room servers: status, telemetry, neighbours, acl, owner.
    /// Logs in first when needed and a password is configured. NODE: name, key prefix, comma list or @group.
    /// Results are stored in node_reports.
    Request {
        node: String,
        kind: String,
        /// Retransmissions without response (last attempt floods).
        #[arg(long, default_value_t = 1)]
        retries: u32,
    },
    /// Remote CLI command (admin login required), e.g. `cmd 'Vuores North' 'get radio'`. Reply text returned.
    /// Not retried by default: a retry executes the command again.
    #[command(name = "cmd")]
    Remote {
        node: String,
        command: String,
        #[arg(long, default_value_t = 0)]
        retries: u32,
        /// Extra seconds to wait for the reply beyond the firmware timeout.
        #[arg(long, default_value_t = 5.0)]
        wait: f64,
    },
    /// TRACE along repeaters, returning the SNR each hop received at. PATH: comma list of names / key
    /// prefixes. Round trip by default (A,B -> A,B,A) so the result returns to us; the first hop must
    /// hear us and we must hear the last.
    Trace {
        path: String,
        /// Send PATH exactly as given (asymmetric routes, loops), e.g. `A,B,C`: out via A and B, back via C.
        /// The result reaches us only if we hear the last hop.
        #[arg(long)]
        no_return: bool,
        /// Hash bytes per hop: 1, 2, 4 or 8.
        #[arg(long, default_value_t = 2)]
        hash_size: usize,
        #[arg(long)]
        wait: Option<f64>,
    },
    /// Directed link graph from stored flood paths, neighbour reports, traces and discover replies.
    /// Edge from->to: `to` received `from`. Offline (database only).
    Topology {
        /// Evidence newer than N seconds [default: 86400].
        #[arg(long, default_value_t = 86400.0)]
        since: f64,
        /// Only edges from these sources (comma list: path, neighbours, trace, discover).
        #[arg(long)]
        sources: Option<String>,
    },
    /// Learned route to a node (from its PATH return). --reset forgets it: the next send floods and
    /// the node's PATH return teaches a fresh route.
    Path {
        node: String,
        #[arg(long)]
        reset: bool,
    },
    /// Read-only SQL against the database. Rows as JSON array.
    Sql { query: String },
    /// Print the database schema (DDL).
    Schema,
    /// Decode a raw over-the-air frame given as hex (offline; uses configured channels and identity).
    Decode { hex: String },
}

fn set_path(v: &mut Value, path: &str, val: Value) -> Result<()> {
    let mut cur = v;
    let parts: Vec<&str> = path.split('.').collect();
    for p in &parts[..parts.len() - 1] {
        cur = cur.get_mut(*p).ok_or_else(|| anyhow!("no such key {p} in {path}"))?;
    }
    let last = parts[parts.len() - 1];
    let obj = cur.as_object_mut().ok_or_else(|| anyhow!("{path}: parent is not an object"))?;
    // Optional keys and `groups.<name>` may be created; other keys must exist.
    let creatable = (parts.len() == 2 && (parts[0] == "groups" || parts[0] == "passwords")) || matches!(path, "node.latitude" | "node.longitude" | "usb_serial");
    if !obj.contains_key(last) && !creatable {
        bail!("no such key {last} in {path}");
    }
    obj.insert(last.into(), val);
    Ok(())
}

fn paths(cli: &Cli) -> (PathBuf, PathBuf) {
    let d = config::default_dir();
    (cli.config.clone().unwrap_or_else(|| d.join("meshcore.json")), cli.db.clone().unwrap_or_else(|| d.join("meshcore.db")))
}

fn print(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap());
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(&cli) {
        let msg = format!("{e:#}");
        eprintln!("{}", json!({"error": msg}));
        let code = if msg.contains("daemon not reachable") {
            exit::NO_DAEMON
        } else if msg.contains("device not found") {
            exit::NO_DEVICE
        } else {
            exit::ERROR
        };
        std::process::exit(code);
    }
}

fn identity_json(cfg: &Config) -> Result<Value> {
    let id = cfg.identity()?;
    Ok(json!({
        "name": cfg.node.name, "adv_type": cfg.node.adv_type,
        "public_key": id.as_ref().map(|i| i.public_hex()),
        "hash": id.as_ref().map(|i| format!("{:02x}", i.public[0])),
        "latitude": cfg.node.latitude, "longitude": cfg.node.longitude,
    }))
}

/// Target node: public key (hex), name, advert type.
type Target = (String, Option<String>, Option<String>);

/// Targets: node name / key prefix, comma list, or @group. Returns (key, name, adv_type), duplicates removed.
fn resolve_targets(cfg: &Config, db: &std::path::Path, spec: &str) -> Result<Vec<Target>> {
    let mut out: Vec<Target> = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let ids = match part.strip_prefix('@') {
            Some(g) => cfg.groups.get(g).cloned().ok_or_else(|| anyhow!("unknown group @{g}"))?,
            None => vec![part.to_string()],
        };
        for id in ids {
            let key = resolve_node(db, &id)?;
            if out.iter().any(|(k, _, _)| *k == key) {
                continue;
            }
            let row = store::open_ro(db)
                .ok()
                .and_then(|c| store::query_json(&c, "SELECT name, adv_type FROM nodes WHERE public_key=?1", &[&key]).ok())
                .and_then(|r| r.into_iter().next());
            let name = row.as_ref().and_then(|r| r["name"].as_str().map(String::from));
            let t = row.as_ref().and_then(|r| r["adv_type"].as_str().map(String::from));
            out.push((key, name, t));
        }
    }
    if out.is_empty() {
        bail!("no targets");
    }
    Ok(out)
}

/// Run `f` for each target; one target -> its result, several -> {"targets":[{node, ok, result|error}]}.
fn for_targets(targets: &[Target], f: impl Fn(&Target) -> Result<Value>) -> Value {
    if targets.len() == 1 {
        return match f(&targets[0]) {
            Ok(v) => v,
            Err(e) => json!({"error": format!("{e:#}")}),
        };
    }
    let mut out = Vec::new();
    for t in targets {
        eprintln!("{}", json!({"target": t.0, "name": t.1}));
        out.push(match f(t) {
            Ok(v) => json!({"node": t.0, "name": t.1, "ok": v["ok"] != false, "result": v}),
            Err(e) => json!({"node": t.0, "name": t.1, "ok": false, "error": format!("{e:#}")}),
        });
    }
    json!({"targets": out})
}

/// Node name, full key or key prefix -> full public key (hex). Must be unique.
fn resolve_node(db: &std::path::Path, id: &str) -> Result<String> {
    let key = id.to_lowercase();
    if key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(key);
    }
    let c = store::open_ro(db)?;
    let rows = store::query_json(&c, "SELECT public_key, name FROM nodes WHERE name = ?2 OR (length(?1) >= 2 AND public_key LIKE ?1 || '%')", &[&key, &id])?;
    match rows.len() {
        1 => Ok(rows[0]["public_key"].as_str().unwrap_or_default().to_string()),
        0 => bail!("node not found: {id} (known from adverts only)"),
        n => bail!("ambiguous: {n} nodes match {id}: {}", json!(rows)),
    }
}

fn run(cli: &Cli) -> Result<()> {
    let (cfg_path, db_path) = paths(cli);
    let cfg = Config::load(&cfg_path)?;
    match &cli.cmd {
        Cmd::Devices => {
            let list = meshtadpole_radio::ch341::list(meshtadpole_radio::ch341::VID, meshtadpole_radio::ch341::PID)?;
            let v: Vec<Value> = list
                .iter()
                .map(|d| {
                    json!({
                        "bus": d.bus, "address": d.address, "port_path": d.port_path,
                        "vid": format!("{:04x}", d.vid), "pid": format!("{:04x}", d.pid),
                        "product": d.product, "serial": d.serial, "manufacturer": d.manufacturer,
                        "device_id": meshtadpole_radio::ch341::device_id(&d.product_raw).map(hex::encode),
                        "open_error": d.open_error,
                    })
                })
                .collect();
            print(&json!(v));
        }
        Cmd::Config { write, set } => {
            let mut cfg = cfg.clone();
            if !set.is_empty() {
                let mut v = serde_json::to_value(&cfg)?;
                for s in set {
                    let (p, val) = s.split_once('=').ok_or_else(|| anyhow!("expected PATH=VALUE: {s}"))?;
                    if p == "node.private_key" {
                        bail!("node.private_key cannot be set here; use `identity --generate` or edit the config file");
                    }
                    if val.contains(config::REDACTED) {
                        bail!("value contains {}; secrets cannot be written through redacted output", config::REDACTED);
                    }
                    let val = serde_json::from_str(val).unwrap_or(Value::String(val.to_string()));
                    set_path(&mut v, p, val)?;
                }
                cfg = serde_json::from_value(v).context("invalid config after set")?;
                cfg.lora()?;
                cfg.channels()?;
                config::adv_type_code(&cfg.node.adv_type)?;
                if !(1..=3).contains(&cfg.node.path_hash_size) {
                    bail!("node.path_hash_size must be 1..3");
                }
            }
            if *write || !set.is_empty() {
                cfg.save(&cfg_path)?;
            }
            let lora = cfg.lora()?;
            let chans: Vec<Value> = cfg
                .channels()?
                .iter()
                .map(|c| json!({"name": c.name, "hash": format!("{:02x}", c.hash), "key_bits": if c.secret[16..].iter().all(|&b| b == 0) { 128 } else { 256 }}))
                .collect();
            print(&json!({
                "config_path": cfg_path, "config_exists": cfg_path.exists(), "db_path": db_path,
                "config": cfg.redacted(),
                "derived": {
                    "freq_hz": lora.freq_hz, "bw_hz": lora.bw_hz, "sf": lora.sf, "cr": format!("4/{}", lora.cr),
                    "sync_word": format!("0x{:02x}", lora.sync_word), "preamble_len": lora.preamble_len,
                    "ldro": lora.ldro(), "symbol_ms": lora.symbol_us() / 1000.0,
                    "channels": chans,
                }
            }));
        }
        Cmd::Identity { generate, force } => {
            if *generate {
                if cfg.node.private_key.is_some() && !force {
                    bail!("identity exists (public key {}); use --force to replace it", cfg.identity()?.map(|i| i.public_hex()).unwrap_or_default());
                }
                let mut cfg = cfg.clone();
                cfg.node.private_key = Some(hex::encode(crypto::Identity::generate().prv));
                cfg.save(&cfg_path)?;
                let mut v = identity_json(&cfg)?;
                v["generated"] = json!(true);
                v["config_path"] = json!(cfg_path);
                print(&v);
            } else {
                print(&identity_json(&cfg)?);
            }
        }
        Cmd::Daemon => daemon::run(&cfg, &db_path)?,
        Cmd::Advert { flood, wait } => {
            let mut req = json!({"cmd": "advert", "flood": flood});
            if let Some(w) = wait {
                req["wait_s"] = json!(w);
            }
            print(&daemon::call(&cfg.api, &req)?);
        }
        Cmd::Send { to, text, flood, retries, wait } => {
            let channel = if to.starts_with('#') {
                Some(to.clone())
            } else {
                to.strip_prefix("ch:").map(String::from)
            };
            let req = match channel {
                Some(ch) => {
                    if !cfg.channels.iter().any(|c| c.name == ch) {
                        bail!("channel {ch} not configured");
                    }
                    let mut r = json!({"cmd": "send_channel", "channel": ch, "text": text});
                    if let Some(w) = wait {
                        r["wait_s"] = json!(w);
                    }
                    r
                }
                None => {
                    let key = resolve_node(&db_path, to)?;
                    let mut r = json!({"cmd": "send_text", "to": key, "text": text, "retries": retries, "flood": flood});
                    if let Some(w) = wait {
                        r["extra_wait_s"] = json!(w);
                    }
                    r
                }
            };
            print(&daemon::call(&cfg.api, &req)?);
        }
        Cmd::Status => print(&daemon::call(&cfg.api, &json!({"cmd": "status"}))?),
        Cmd::Listen { ok_only, seconds } => {
            let mut s = daemon::connect(&cfg.api)?;
            if let Some(sec) = seconds {
                let sec = *sec;
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(sec));
                    std::process::exit(0);
                });
            }
            writeln!(s, "{}", json!({"cmd": "subscribe"}))?;
            let out = std::io::stdout();
            for line in BufReader::new(s).lines() {
                let line = line?;
                let v: Value = serde_json::from_str(&line)?;
                if v.get("subscribed").is_some() || (*ok_only && v["status"] != "ok") {
                    continue;
                }
                let mut o = out.lock();
                writeln!(o, "{line}")?;
                o.flush()?;
            }
        }
        Cmd::Packets { since, ptype, from, via, status, channel, dups, limit } => {
            let c = store::open_ro(&db_path)?;
            let mut q = String::from("SELECT * FROM v_packets WHERE 1=1");
            let mut args: Vec<Box<dyn store::rusqlite_ToSql>> = Vec::new();
            if let Some(s) = since {
                q += " AND rx_time > ?";
                args.push(Box::new(store::now() - s));
            }
            if let Some(t) = ptype {
                let n = packet::ptype_from_name(t).ok_or_else(|| anyhow!("unknown payload type {t}"))?;
                q += " AND payload_type = ?";
                args.push(Box::new(packet::ptype_name(n)));
            }
            if let Some(f) = from {
                let f = f.to_lowercase();
                if f.len() == 2 {
                    q += " AND (src_hash = ? OR src_key LIKE ? || '%')";
                    args.push(Box::new(f.clone()));
                    args.push(Box::new(f));
                } else {
                    q += " AND src_key LIKE ? || '%'";
                    args.push(Box::new(f));
                }
            }
            if let Some(h) = via {
                q += " AND ',' || path || ',' LIKE '%,' || ? || ',%'";
                args.push(Box::new(h.to_lowercase()));
            }
            if let Some(s) = status {
                q += " AND status = ?";
                args.push(Box::new(s.clone()));
            }
            if let Some(ch) = channel {
                q += " AND channel = ?";
                args.push(Box::new(ch.clone()));
            }
            if !dups {
                q += " AND dup_of IS NULL";
            }
            q += " ORDER BY id DESC LIMIT ?";
            args.push(Box::new(*limit));
            let refs: Vec<&dyn store::rusqlite_ToSql> = args.iter().map(|b| b.as_ref()).collect();
            print(&json!(store::query_json(&c, &q, &refs)?));
        }
        Cmd::Nodes { since, adv_type } => {
            let c = store::open_ro(&db_path)?;
            let cutoff = since.map(|s| store::now() - s).unwrap_or(0.0);
            let q = "SELECT public_key, hash, name, adv_type, latitude, longitude, advert_timestamp,
                       adverts_heard, receptions, first_heard, last_heard,
                       CAST(strftime('%s','now') AS REAL) - last_heard AS age_s,
                       last_rssi, last_snr, last_route, last_path_hops, last_path,
                       last_direct_heard, last_direct_rssi, last_direct_snr, out_path, out_path_len, out_path_time
                     FROM nodes WHERE last_heard > ?1 AND (?2 IS NULL OR adv_type = ?2) ORDER BY last_heard DESC";
            print(&json!(store::query_json(&c, q, &[&cutoff, adv_type])?));
        }
        Cmd::Node { id } => {
            let c = store::open_ro(&db_path)?;
            let key = id.to_lowercase();
            let nodes = store::query_json(&c, "SELECT * FROM nodes WHERE public_key LIKE ?1 || '%' OR name = ?2", &[&key, id])?;
            if nodes.len() > 1 {
                let names: Vec<Value> = nodes.iter().map(|n| json!({"public_key": n["public_key"], "name": n["name"]})).collect();
                bail!("ambiguous: {} nodes match: {}", nodes.len(), json!(names));
            }
            let node = nodes.into_iter().next().ok_or_else(|| anyhow!("node not found: {id}"))?;
            let adverts = store::query_json(
                &c,
                "SELECT frame_id, rx_time, advert_timestamp, route, path_hops, path, last_hop, rssi, snr, dup_of FROM v_adverts WHERE public_key = ?1 ORDER BY rx_time DESC LIMIT 50",
                &[&node["public_key"].as_str().unwrap_or_default()],
            )?;
            print(&json!({"node": node, "adverts": adverts}));
        }
        Cmd::Discover { types, wait } => {
            let mut filter = 0u8;
            for t in types.split(',').map(str::trim) {
                filter |= 1 << config::adv_type_code(t)?;
            }
            print(&daemon::call(&cfg.api, &json!({"cmd": "discover", "type_filter": filter, "wait_s": wait}))?);
        }
        Cmd::Login { node, password } => {
            let targets = resolve_targets(&cfg, &db_path, node)?;
            print(&for_targets(&targets, |(key, name, t)| {
                let pw = password.clone().or_else(|| cfg.password_for(name.as_deref(), key)).ok_or_else(|| anyhow!("no password for {} in config `passwords`", name.as_deref().unwrap_or(key)))?;
                daemon::call(&cfg.api, &json!({"cmd": "login", "to": key, "password": pw, "room": t.as_deref() == Some("room")}))
            }));
        }
        Cmd::Request { node, kind, retries } => {
            repeater::kind(kind).ok_or_else(|| anyhow!("unknown kind {kind} (status, telemetry, neighbours, acl, owner)"))?;
            let targets = resolve_targets(&cfg, &db_path, node)?;
            print(&for_targets(&targets, |(key, name, t)| {
                let mut req = json!({"cmd": "request", "to": key, "kind": kind, "retries": retries, "room": t.as_deref() == Some("room")});
                if let Some(pw) = cfg.password_for(name.as_deref(), key) {
                    req["password"] = json!(pw);
                }
                daemon::call(&cfg.api, &req)
            }));
        }
        Cmd::Remote { node, command, retries, wait } => {
            let targets = resolve_targets(&cfg, &db_path, node)?;
            print(&for_targets(&targets, |(key, name, t)| {
                let mut req = json!({"cmd": "cli", "to": key, "command": command, "retries": retries, "wait_s": wait, "room": t.as_deref() == Some("room")});
                if let Some(pw) = cfg.password_for(name.as_deref(), key) {
                    req["password"] = json!(pw);
                }
                daemon::call(&cfg.api, &req)
            }));
        }
        Cmd::Trace { path, no_return, hash_size, wait } => {
            if ![1, 2, 4, 8].contains(hash_size) {
                bail!("--hash-size must be 1, 2, 4 or 8");
            }
            let mut hops = Vec::new();
            for p in path.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                let is_hex = p.chars().all(|c| c.is_ascii_hexdigit()) && p.len() == hash_size * 2;
                let key = if is_hex { p.to_lowercase() } else { resolve_node(&db_path, p)? };
                if key.len() < hash_size * 2 {
                    bail!("{p}: key prefix shorter than hash size");
                }
                hops.push(key[..hash_size * 2].to_string());
            }
            if hops.is_empty() {
                bail!("empty path");
            }
            if !no_return && hops.len() > 1 {
                let back: Vec<String> = hops[..hops.len() - 1].iter().rev().cloned().collect();
                hops.extend(back);
            }
            let mut req = json!({"cmd": "trace", "path": hops.join(",")});
            if let Some(w) = wait {
                req["wait_s"] = json!(w);
            }
            let mut v = daemon::call(&cfg.api, &req)?;
            // Names for hops.
            if let (Ok(c), Some(hs)) = (store::open_ro(&db_path), v["hops"].as_array_mut()) {
                for h in hs {
                    let p = h["hash"].as_str().unwrap_or_default().to_string();
                    if let Ok(r) = store::query_json(&c, "SELECT name FROM nodes WHERE public_key LIKE ?1 || '%'", &[&p]) {
                        if r.len() == 1 {
                            h["name"] = r[0]["name"].clone();
                        }
                    }
                }
            }
            print(&v);
        }
        Cmd::Topology { since, sources } => {
            let c = store::open_ro(&db_path)?;
            let me = cfg.identity()?.map(|i| i.public_hex());
            let mut v = topology::build(&c, store::now() - since, me.as_deref())?;
            if let Some(s) = sources {
                let keep: Vec<&str> = s.split(',').map(str::trim).collect();
                if let Some(e) = v["edges"].as_array_mut() {
                    e.retain(|x| keep.contains(&x["source"].as_str().unwrap_or_default()));
                }
            }
            print(&v);
        }
        Cmd::Path { node, reset } => {
            let key = resolve_node(&db_path, node)?;
            if *reset {
                print(&daemon::call(&cfg.api, &json!({"cmd": "path_reset", "to": key}))?);
            } else {
                let c = store::open_ro(&db_path)?;
                let row = store::query_json(&c, "SELECT public_key, name, out_path, out_path_len, out_path_time FROM nodes WHERE public_key=?1", &[&key])?;
                let mut v = row.into_iter().next().unwrap_or(json!({"public_key": key}));
                if let Some(l) = v["out_path_len"].as_u64() {
                    let hs = ((l >> 6) + 1) as usize;
                    let p = v["out_path"].as_str().unwrap_or_default().to_string();
                    v["hops"] = json!(l & 63);
                    v["hash_size"] = json!(hs);
                    v["route"] = json!(if l & 63 == 0 { "zero_hop".to_string() } else { (0..p.len() / (hs * 2)).map(|i| &p[i * hs * 2..(i + 1) * hs * 2]).collect::<Vec<_>>().join(",") });
                } else {
                    v["route"] = json!(null);
                    v["note"] = json!("no learned route: DMs and requests flood");
                }
                print(&v);
            }
        }
        Cmd::Sql { query } => {



            let c = store::open_ro(&db_path)?;
            print(&json!(store::query_json(&c, query, &[])?));
        }
        Cmd::Schema => println!("{}", store::full_schema()),
        Cmd::Decode { hex: h } => {
            let raw = hex::decode(h.trim()).context("hex")?;
            let mut keys = decode::Keys { me: cfg.identity()?, channels: cfg.channels()?, ..Default::default() };
            if let Ok(c) = store::open_ro(&db_path) {
                if let Ok(ks) = store::load_peer_keys(&c) {
                    for k in ks {
                        keys.add_peer(k);
                    }
                }
            }
            print(&decode::to_json(&decode::decode_frame(&raw, false, &keys)));
        }
    }
    Ok(())
}
