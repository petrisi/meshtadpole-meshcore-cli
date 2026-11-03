//! Link graph from stored evidence: flood paths, neighbour reports, TRACE results, DISCOVER replies.
//!
//! Edges are directed: `from` transmitted, `to` received. Path hashes are key prefixes (1-3 bytes; 6 in
//! neighbour reports); a prefix is mapped to a node when exactly one known key matches, else it stays a
//! prefix node (`ambiguous` lists candidates when several match).

use crate::store;
use anyhow::Result;
use meshtadpole_radio::store::rusqlite::Connection;
use serde_json::{Value, json};
use std::collections::BTreeMap;

struct Known {
    keys: Vec<(String, Option<String>, Option<String>)>, // key, name, type
    /// All prefixes seen in the evidence (paths, neighbour reports, traces).
    seen: Vec<String>,
}

impl Known {
    /// Node id for a key prefix: the full key when unique, else "prefix:<hex>".
    fn id(&self, prefix: &str) -> (String, Vec<String>) {
        let p = prefix.to_lowercase();
        let c: Vec<&(String, Option<String>, Option<String>)> = self.keys.iter().filter(|(k, _, _)| k.starts_with(&p)).collect();
        match c.len() {
            1 => (c[0].0.clone(), vec![]),
            0 => {
                // Unknown key: use the longest prefix seen for the same node (consistent chain only),
                // so 2-byte and 3/6-byte hashes of one node merge.
                let longer: Vec<&String> = self.seen.iter().filter(|q| q.len() > p.len() && q.starts_with(&p)).collect();
                let best = longer.iter().max_by_key(|q| q.len()).copied();
                match best {
                    Some(b) if longer.iter().all(|q| b.starts_with(q.as_str())) => (format!("prefix:{b}"), vec![]),
                    Some(_) => (format!("prefix:{p}"), longer.iter().map(|q| q.to_string()).collect()),
                    None => (format!("prefix:{p}"), vec![]),
                }
            }
            _ => (
                format!("prefix:{p}"),
                c.iter().map(|(k, n, _)| format!("{}{}", &k[..12], n.as_deref().map(|n| format!(" {n}")).unwrap_or_default())).collect(),
            ),
        }
    }
}

#[derive(Default)]
struct Edge {
    count: u64,
    last: f64,
    snr: Vec<f64>,
    rssi: Vec<f64>,
}

impl Edge {
    fn add(&mut self, t: f64, snr: Option<f64>, rssi: Option<f64>) {
        self.count += 1;
        self.last = self.last.max(t);
        self.snr.extend(snr);
        self.rssi.extend(rssi);
    }
    fn json(&self) -> Value {
        let avg = |v: &Vec<f64>| (!v.is_empty()).then(|| (v.iter().sum::<f64>() / v.len() as f64 * 100.0).round() / 100.0);
        let min = |v: &Vec<f64>| v.iter().copied().reduce(f64::min);
        json!({"count": self.count, "last": self.last, "snr_avg": avg(&self.snr), "snr_min": min(&self.snr), "rssi_avg": avg(&self.rssi)})
    }
}

pub fn build(c: &Connection, since: f64, me: Option<&str>) -> Result<Value> {
    let rows = store::query_json(c, "SELECT public_key, name, adv_type FROM nodes", &[])?;
    let mut keys: Vec<(String, Option<String>, Option<String>)> = rows
        .iter()
        .map(|r| {
            (
                r["public_key"].as_str().unwrap_or_default().to_string(),
                r["name"].as_str().map(String::from),
                r["adv_type"].as_str().map(String::from),
            )
        })
        .collect();
    let me = me.map(String::from).unwrap_or_else(|| "me".into());
    keys.push((me.clone(), Some("(this node)".into()), None));
    let mut seen: Vec<String> = Vec::new();
    for r in store::query_json(c, "SELECT DISTINCT path FROM rx_frames WHERE rx_time > ?1 AND path != ''", &[&since])? {
        seen.extend(r["path"].as_str().unwrap_or_default().split(',').map(String::from));
    }
    for r in store::query_json(c, "SELECT data_json FROM node_reports WHERE kind IN ('neighbours','trace')", &[])? {
        for n in r["data_json"]["neighbours"].as_array().into_iter().flatten() {
            seen.extend(n["key_prefix"].as_str().map(String::from));
        }
        for h in r["data_json"]["hops"].as_array().into_iter().flatten() {
            seen.extend(h["hash"].as_str().map(String::from));
        }
    }
    seen.sort();
    seen.dedup();
    let known = Known { keys, seen };
    let mut edges: BTreeMap<(String, String, &'static str), Edge> = BTreeMap::new();
    let mut ambiguous: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let node = |p: &str, amb: &mut BTreeMap<String, Vec<String>>| {
        let (id, cands) = known.id(p);
        if !cands.is_empty() {
            amb.insert(id.clone(), cands);
        }
        id
    };

    // 1. Flood paths: origin -> p0 -> ... -> pn -> me. RF values only for the hop we measured (pn -> me).
    let frames = store::query_json(
        c,
        "SELECT rx_time, path, src_key, rssi, snr, path_hops FROM rx_frames
         WHERE rx_time > ?1 AND route IN ('flood','transport_flood') AND status NOT IN ('crc_error','header_error','malformed')
           AND payload_type != 'TRACE' AND tx_id IS NULL",
        &[&since],
    )?;
    for f in &frames {
        let t = f["rx_time"].as_f64().unwrap_or(0.0);
        let hops: Vec<String> =
            f["path"].as_str().unwrap_or_default().split(',').filter(|s| !s.is_empty()).map(|h| node(h, &mut ambiguous)).collect();
        let mut chain = Vec::new();
        if let Some(k) = f["src_key"].as_str() {
            chain.push(k.to_string());
        }
        chain.extend(hops);
        chain.push(me.clone());
        for w in chain.windows(2) {
            let last = w[1] == me;
            let e = edges.entry((w[0].clone(), w[1].clone(), "path")).or_default();
            if last { e.add(t, f["snr"].as_f64(), f["rssi"].as_f64()) } else { e.add(t, None, None) }
        }
    }

    // 2. Neighbour reports (latest per reporter): neighbour -> reporter, SNR measured by the reporter.
    let reps = store::query_json(
        c,
        "SELECT r.public_key, r.t, r.data_json FROM node_reports r
         WHERE r.kind='neighbours' AND r.id = (SELECT max(id) FROM node_reports x WHERE x.kind='neighbours' AND x.public_key=r.public_key)",
        &[],
    )?;
    for r in &reps {
        let to = r["public_key"].as_str().unwrap_or_default().to_string();
        let t = r["t"].as_f64().unwrap_or(0.0);
        for n in r["data_json"]["neighbours"].as_array().into_iter().flatten() {
            let from = node(n["key_prefix"].as_str().unwrap_or_default(), &mut ambiguous);
            let heard = t - n["heard_s_ago"].as_f64().unwrap_or(0.0);
            if heard >= since {
                edges.entry((from, to.clone(), "neighbours")).or_default().add(heard, n["snr_db"].as_f64(), None);
            }
        }
    }

    // 3. TRACE results: me -> h0 -> h1 ... -> me, SNR at each receiver.
    let traces = store::query_json(c, "SELECT t, data_json FROM node_reports WHERE kind='trace' AND t > ?1", &[&since])?;
    for r in &traces {
        let t = r["t"].as_f64().unwrap_or(0.0);
        let d = &r["data_json"];
        let mut prev = me.clone();
        for h in d["hops"].as_array().into_iter().flatten() {
            let id = node(h["hash"].as_str().unwrap_or_default(), &mut ambiguous);
            edges.entry((prev.clone(), id.clone(), "trace")).or_default().add(t, h["snr_db"].as_f64(), None);
            prev = id;
        }
        edges.entry((prev, me.clone(), "trace")).or_default().add(t, d["final_snr_db"].as_f64(), d["final_rssi"].as_f64());
    }

    // 4. DISCOVER replies: node -> me (our RF) and me -> node (SNR the node reported).
    let disc = store::query_json(
        c,
        "SELECT rx_time, src_key, rssi, snr, json_extract(data_json,'$.snr') AS their_snr FROM rx_frames
         WHERE rx_time > ?1 AND payload_type='CONTROL' AND json_extract(data_json,'$.sub_type_name')='DISCOVER_RESP' AND src_key IS NOT NULL",
        &[&since],
    )?;
    for d in &disc {
        let t = d["rx_time"].as_f64().unwrap_or(0.0);
        let k = d["src_key"].as_str().unwrap_or_default().to_string();
        edges.entry((k.clone(), me.clone(), "discover")).or_default().add(t, d["snr"].as_f64(), d["rssi"].as_f64());
        edges.entry((me.clone(), k, "discover")).or_default().add(t, d["their_snr"].as_f64(), None);
    }

    // Nodes appearing in edges.
    let mut ids: BTreeMap<String, Value> = BTreeMap::new();
    for (f, t, _) in edges.keys() {
        for id in [f, t] {
            ids.entry(id.clone()).or_insert_with(|| {
                let k = known.keys.iter().find(|(k, _, _)| k == id);
                json!({"id": id, "name": k.and_then(|k| k.1.clone()), "type": k.and_then(|k| k.2.clone()), "ambiguous": ambiguous.get(id)})
            });
        }
    }
    let label = |id: &str| ids.get(id).and_then(|n| n["name"].as_str().map(String::from)).unwrap_or_else(|| id.chars().take(16).collect());
    let edges_json: Vec<Value> = edges
        .iter()
        .map(|((f, t, src), e)| {
            let mut v = e.json();
            v["from"] = json!(f);
            v["to"] = json!(t);
            v["from_name"] = json!(label(f));
            v["to_name"] = json!(label(t));
            v["source"] = json!(src);
            v
        })
        .collect();
    let mut by_source: BTreeMap<&str, u64> = BTreeMap::new();
    for (_, _, s) in edges.keys() {
        *by_source.entry(s).or_default() += 1;
    }
    Ok(json!({"me": me, "since": since, "edge_counts": by_source, "nodes": ids.into_values().collect::<Vec<_>>(), "edges": edges_json}))
}
