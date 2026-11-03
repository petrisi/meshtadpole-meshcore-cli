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

Config keys: `node.{name, adv_type, private_key, latitude, longitude, duty_cycle_limit, duty_cycle_enforce}`, `radio.{frequency_mhz, bandwidth_khz, spreading_factor, coding_rate, tx_power_dbm, rx_boosted_gain, agc_reset_interval_s}`, `channels` (array of `{name, key?}`; key base64 or hex, 16/32 bytes; omitted for `#name`), `api`, `usb_serial`, `groups.<name>` (node lists).

Example: add a private channel:
`tadpole-mc config --set 'channels=[{"name":"Public","key":"izOH6cXN6mrJ5e26oRXNcg=="},{"name":"ops","key":"<base64>"}]'`

## Daemon

| Command | Effect |
|---|---|
| `daemon` | foreground. Owns the stick, stores frames, serves API on `127.0.0.1:47404`. Starts without a stick and reconnects (backoff 1-30 s). Ctrl-C ends the session cleanly |
| `status` | pid, session, radio state, USB serial, radio parameters, frames, known peer keys, TX airtime last hour |
| `listen [--ok-only] [--seconds N]` | NDJSON frame events (same fields as `decode` plus frame_id, rx_time, rssi, snr, freq_error_hz, len, airtime_ms, dup_of) |

API: TCP, one JSON object per line. `{"cmd":"status"}`, `{"cmd":"subscribe"}`.

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
