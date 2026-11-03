# tadpole-mc CLI

All output is JSON on stdout. Errors: `{"error": "..."}` on stderr, exit code 1 (3 = no device, 4 = daemon not reachable). Global options: `--config PATH`, `--db PATH`.

## Setup

| Command | Effect |
|---|---|
| `devices` | attached sticks (USB serial, device id, open error) |
| `config` | effective config (private key redacted), derived LoRa parameters, channel hashes |
| `config --write` | write effective config (defaults on first use) |
| `config --set PATH=VALUE` | set by dotted path, value as JSON else string; validated; restart daemon to apply. `node.private_key` cannot be set this way |
| `identity` | name, adv_type, public key, hash |
| `identity --generate [--force]` | create key pair in the config file; refused if one exists unless `--force` (old identity lost) |

Config keys: `node.{name, adv_type, private_key, latitude, longitude, duty_cycle_limit, duty_cycle_enforce, path_hash_size}`, `radio.{frequency_mhz, bandwidth_khz, spreading_factor, coding_rate, tx_power_dbm, rx_boosted_gain, agc_reset_interval_s}`, `channels` (array of `{name, key?}`; key base64 or hex, 16/32 bytes; omitted for `#name`), `api`, `usb_serial`, `groups.<name>` (node lists).

Example: add a private channel:
`tadpole-mc config --set 'channels=[{"name":"Public","key":"izOH6cXN6mrJ5e26oRXNcg=="},{"name":"ops","key":"<base64>"}]'`

## Daemon

| Command | Effect |
|---|---|
| `daemon` | foreground. Owns the stick, stores frames, serves API on `127.0.0.1:47404`. Starts without a stick and reconnects (backoff 1-30 s). Ctrl-C ends the session cleanly |
| `status` | pid, session, radio state, USB serial, radio parameters, frames, known peer keys, TX airtime last hour |
| `listen [--ok-only] [--seconds N]` | NDJSON frame events (same fields as `decode` plus frame_id, rx_time, rssi, snr, freq_error_hz, len, airtime_ms, dup_of) |

API: TCP, one JSON object per line: `status`, `subscribe`, `advert`, `send_text`, `send_channel` (see `src/daemon.rs` header). Requests that transmit are logged in `requests`.

## Transmit (daemon required)

| Command | Effect |
|---|---|
| `advert [--flood] [--wait S]` | signed advert (name, type, optional location). Default zero hop (not repeated); `--flood` propagates. Returns transmission and `echoes`: copies repeated by repeaters that we heard (path, last_hop, rssi, snr) |
| `send '#name'\|ch:NAME TEXT [--wait S]` | channel message as `<node.name>: TEXT` (flood, no ACK); returns echoes |
| `send NODE TEXT [--flood] [--retries N] [--wait S]` | DM to a node known from adverts (name, key or prefix). Direct along the learned path if any, else flood; last retry always floods. Waits firmware ACK timeout (flood 500 ms + 16 x airtime; direct 500 ms + (6 x airtime + 250 ms) x (hops + 1)) plus `--wait` (default 3 s). Returns acked, ack_attempt, rtt_ms, ack path/rssi/snr, transmissions, echoes, out_path |

Floods we originate use `node.path_hash_size` (default 2, as observed on meshpirkanmaa) and no region scope. Max text 160 bytes (channel: including `name: `). Duty cycle enforced (`node.duty_cycle_limit`).

Automatic replies to frames addressed to us (first reception only):
- Text message (plain or signed) from a known peer: ACK. Message received by flood: ACK inside a PATH return (flood), so the sender learns the route to us. Received direct: ACK along our learned path, else flood.
- PATH from a peer: learned route stored (`nodes.out_path`); if it arrived by flood, a reciprocal PATH return is sent along the learned route.
- CLI messages: no ACK. Never repeats other nodes' packets.

## Management (repeaters, room servers; daemon required)

Passwords: config `passwords`, keyed by node name or public key prefix; redacted in all output and in the `requests` log. Set with `config --set 'passwords.Vuores North=...'`. NODE: name, key prefix, comma list or `@group` (config `groups`); several targets return `{"targets":[{node, name, ok, result|error}]}`.

| Command | Effect |
|---|---|
| `discover [--types repeater,room,chat,sensor] [--wait S]` | zero-hop DISCOVER_REQ; direct neighbours answer with full key, type and the SNR they hear us at (`snr_at_node_db`). Answering nodes are added to `nodes` (name from adverts or owner info later). Nodes may be configured not to answer |
| `login NODE [--password P]` | ANON_REQ login; result: ok, role (guest/read_only/read_write/admin), permissions, server_time, firmware_ver_level, rtt_ms. A wrong password gets no reply (`ok: false` after timeout). Login adds us to the node's ACL |
| `request NODE status\|telemetry\|neighbours\|acl\|owner [--retries N]` | logs in first if not logged in this daemon session. status: RepeaterStats (batt_mv, noise_floor_dbm, packet/airtime counters, uptime_s, dups, errors). telemetry: Cayenne LPP sensors. neighbours: all pages, strongest first (key_prefix 6 bytes, heard_s_ago, snr_db). acl: key prefixes and roles (admin only). owner: firmware, name, owner_info (fills a missing node name) |
| `cmd NODE 'COMMAND' [--retries N] [--wait S]` | remote CLI (admin): e.g. `ver`, `clock`, `get radio`, `get repeat`, `set owner.info ...`, `neighbors`. Reply text returned. Default no retry (a retry executes again) |

Routing: direct along the learned path when known (learned from the node's PATH return after a flooded login/request), else flood; the last retry floods. Requests use fresh timestamps (firmware replay protection). All results are stored in `node_reports`.

Writes: plan, read before, write, read back, restore when testing. Disruptive settings (radio parameters, `prv.key`, `password`, `reboot`, `erase`, region, repeat off) can cut the node off the mesh; avoid unless intended.

## Queries (read-only, daemon not required)


| Command | Effect |
|---|---|
| `packets [--since S] [--type T] [--from KEY] [--via HASH] [--status S] [--channel NAME] [--dups] [--limit N]` | v_packets, newest first. `--from`: key prefix, or 1-byte hash (2 hex digits). `--via`: path contains repeater hash. Duplicates excluded unless `--dups` |
| `nodes [--since S] [--type chat\|repeater\|room\|sensor]` | nodes from adverts, most recent first |
| `node ID` | one node by name, key or key prefix, with its last 50 advert receptions |
| `sql QUERY` | read-only SQL; BLOBs as hex, `*_json` columns parsed |
| `schema` | DDL |
| `decode HEX` | decode a raw frame offline with configured channels, identity and known keys |

See [schema.md](schema.md) for tables, statuses and decoded fields.

## Topology notes

- Flood packets carry the repeater path (`path`); `last_hop` is the repeater heard directly. `v_heard_repeaters` summarises direct links by hash.
- With 1-byte path hashes, several nodes can share a hash. Resolve against `nodes.hash` (`SELECT name FROM nodes WHERE hash='a3'`); ambiguity remains when more than one matches.
- All copies of one packet share `pkt_hash`: `packets --dups` with `sql "... WHERE pkt_hash='...'"` shows every path it arrived by.
