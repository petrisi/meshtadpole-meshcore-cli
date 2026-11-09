# tadpole-mc CLI

All output is JSON on stdout. Errors: `{"error": "..."}` on stderr, exit code 1 (3 = no device, 4 = daemon not reachable). Global options: `--config PATH`, `--db PATH`.

## Setup

| Command | Effect |
|---|---|
| `devices` | attached sticks (USB serial, device id, open error) |
| `config` | effective config (private key redacted), derived LoRa parameters, channel hashes |
| `config --write` | write effective config (defaults on first use) |
| `config --set PATH=VALUE` | set by dotted path, value as JSON else string; validated; restart daemon to apply. `node.private_key` cannot be set this way |
| `identity` | name, adv_type, public key, hash (without `node.private_key` in the config: the running daemon's), `private_key_in_config` |
| `identity --generate [--force]` | create key pair in the config file; refused if one exists unless `--force` (old identity lost) |

Config keys: `node.{name, adv_type, private_key, latitude, longitude, duty_cycle_limit, duty_cycle_enforce, path_hash_size, flood_scope, room_keepalive_s, telemetry.{base, location}}`, `radio.{frequency_mhz, bandwidth_khz, spreading_factor, coding_rate, tx_power_dbm, rx_boosted_gain, agc_reset_interval_s}`, `channels` (array of `{name, key?}`; key base64 or hex, 16/32 bytes; omitted for `#name`), `api`, `usb_serial`, `groups.<name>` (node lists).

Example: add a private channel:
`tadpole-mc config --set 'channels=[{"name":"Public","key":"izOH6cXN6mrJ5e26oRXNcg=="},{"name":"ops","key":"<base64>"}]'`

## Daemon

| Command | Effect |
|---|---|
| `daemon` | foreground. Owns the stick, stores frames, serves API on `127.0.0.1:47404`. Starts without a stick and reconnects (backoff 1-30 s). Ctrl-C ends the session cleanly |
| `status` | pid, session, radio state, USB serial, radio parameters, frames, known peer keys, TX airtime last hour |
| `listen [--ok-only] [--seconds N]` | NDJSON frame events (same fields as `decode` plus frame_id, rx_time, rssi, snr, freq_error_hz, len, airtime_ms, dup_of) |

API: TCP, one JSON object per line (commands and fields: `src/daemon.rs` header). Requests that transmit are logged in `requests`. `status` also lists the room keeper state (`rooms`) and `flood_scope`.

## Transmit (daemon required)

| Command | Effect |
|---|---|
| `advert [--flood] [--scope R] [--wait S]` | signed advert (name, type, optional location). Default zero hop (not repeated); `--flood` propagates. Returns transmission and `echoes`: copies repeated by repeaters that we heard (path, last_hop, rssi, snr) |
| `send '#name'\|ch:NAME TEXT [--scope R] [--wait S]` | channel message as `<node.name>: TEXT` (flood, no ACK); returns echoes |
| `send NODE TEXT [--flood] [--retries N] [--scope R] [--wait S]` | DM to a node known from adverts (name, key or prefix). Direct along the learned path if any, else flood; last retry always floods. When the direct attempts get no ACK, the learned path is forgotten before the flood (`path_reset: true`); the flood's PATH return teaches a new one. Waits firmware ACK timeout (flood 500 ms + 16 x airtime; direct 500 ms + (6 x airtime + 250 ms) x (hops + 1)) plus `--wait` (default 3 s). Returns acked, ack_attempt, rtt_ms, ack path/rssi/snr, transmissions, echoes, out_path |
| `send-data CHANNEL HEX [--type N] [--scope R] [--wait S]` | channel datagram (GRP_DATA, flood, no ACK) for apps and bots: data type (u16; default 0xFFFF = developer namespace, 0 reserved) and up to 165 bytes. Received datagrams decode as `data_type`, `data_len`, `data_hex` |

Floods we originate use `node.path_hash_size` (default 2, as observed on meshpirkanmaa). Max text 160 bytes (channel: including `name: `). Duty cycle enforced (`node.duty_cycle_limit`).

Region scope: `node.flood_scope` (e.g. `fi`; default null = unscoped) makes every flood we originate (adverts, channel messages, DMs, logins, requests, ACK/PATH replies) a transport flood with the region's code, as firmware companions do with their default scope. Repeaters forward a scoped flood only when they have that region and it allows flooding; unscoped floods are limited by their `flood.max.unscoped`. `--scope R` (or `none`) overrides per command. `anon NODE regions` lists the regions a repeater floods. Only public (hashtag) regions: key = sha256("#name")[0..16]; private `$` regions are not supported. Transport codes of received frames are in `rx_frames.transport_code1/2`.

Duplicates: copies of a packet within 30 s are not answered again. An identical text message arriving later (a resend: room servers re-push a post after re-login and repeat the random attempt bits 1 time in 4) is ACKed again.

Automatic replies to frames addressed to us (first reception only):
- Text message (plain or signed) from a known peer: ACK. Message received by flood: ACK inside a PATH return (flood), so the sender learns the route to us. Received direct: ACK along our learned path, else flood.
- PATH from a peer: learned route stored (`nodes.out_path`); if it arrived by flood, a reciprocal PATH return is sent along the learned route.
- Telemetry request (REQ type 0x03) from a known peer: answered as companion firmware does when `node.telemetry.base` = `allow` (default): voltage 0.0 V (the stick has no battery), plus GPS when `node.telemetry.location` = `allow` and latitude/longitude are set (default `deny`). The request's inverse permission mask is applied. Flood request: answer inside a PATH return; direct: RESPONSE along the learned path, else flood. Other request types are not answered (as firmware companions).
- CLI messages: no ACK. Never repeats other nodes' packets.

## Management (repeaters, room servers; daemon required)

Passwords: config `passwords`, keyed by node name or public key prefix; redacted in all output and in the `requests` log. Prefer the key prefix (8 hex digits): owners rename nodes, and a name key stops matching. Set with `config --set 'passwords.9734c10d=...'`. A request without a password uses the daemon's config `passwords`, so clients may use a config without `passwords` and `node.private_key` (secrets readable by the daemon's user only). NODE: name, key prefix, comma list or `@group` (config `groups`); several targets return `{"targets":[{node, name, ok, result|error}]}`.

| Command | Effect |
|---|---|
| `discover [--types repeater,room,chat,sensor] [--wait S]` | zero-hop DISCOVER_REQ; direct neighbours answer with full key, type and the SNR they hear us at (`snr_at_node_db`). Answering nodes are added to `nodes` (name from adverts or owner info later). Nodes may be configured not to answer, and the firmware rate-limits replies: one empty attempt does not prove absence; repeat after a while |
| `login NODE [--password P] [--since S]` | ANON_REQ login with `--password`, else config `passwords`, else the daemon's config `passwords` (a client config may leave them out); result: ok, role (guest/read_only/read_write/admin), permissions, server_time, firmware_ver_level, rtt_ms. A wrong password gets no reply (`ok: false` after timeout). Login adds us to the node's ACL. Room servers: the login carries "sync since"; the room then pushes newer posts as signed messages (ACKed automatically). Default: posts after login; `--since S`: posts from the last S seconds by our clock (the room compares with its own clock; a room clock running behind suppresses pushes). A successful room login joins the room (see Rooms) |
| `anon NODE regions\|owner\|clock [--retries N]` | anonymous request, no login (repeaters; answered on air by firmware 1.17.1 and 1.18.0; room servers do not answer). regions: region names the repeater floods (`*` = unscoped allowed). owner: name, owner_info. clock: node clock (`server_time`), bridge type, `repeat_disabled`. Sent direct only (firmware rule): along the learned path with the reversed path for the reply, else zero hop (neighbours). For a repeater we only hear via others, set a route first (`path NODE --set`, e.g. the reverse of its advert path). Rate limited by the repeater. Stored in node_reports (kind `anon_<kind>`) |
| `rooms` | joined room servers: `rooms` table plus live keeper state (`keeper`: misses, relogin_pending, last_ok, last_error, next_keepalive_in_s) when the daemon runs |
| `leave NODE` | stop keeping a room membership (no more keep-alives or re-logins); the room still has us in its ACL and pushes until 3 pushes fail |
| `request NODE status\|telemetry\|neighbours\|acl\|owner [--retries N]` | logs in first if not logged in this daemon session. status: RepeaterStats (batt_mv, noise_floor_dbm, packet/airtime counters, uptime_s, dups, errors). telemetry: Cayenne LPP sensors. neighbours: all pages, strongest first (key_prefix 6 bytes, heard_s_ago, snr_db). acl: key prefixes and roles (admin only). owner: firmware, name, owner_info (fills a missing node name) |
| `path NODE [--reset \| --set HASHES]` | learned route to a node (`route`: `zero_hop` or hop hashes, `hops`, `hash_size`, `out_path_time`); `--reset` forgets it (daemon), so the next DM/request floods and the node's PATH return teaches a fresh route. Done automatically when direct attempts fail (see Routing). `--set 5b5f,3133` sets a route by hand (repeater hashes in order from us, equal size 1-3 bytes; `""` = zero hop), e.g. the reverse of the node's advert path; replaced by the next learned PATH |
| `cmd NODE 'COMMAND' [--retries N] [--wait S] [--allow-disruptive]` | remote CLI (admin). Without --allow-disruptive only harmless commands run: `ver`, `clock`, `board`, `neighbors`, `region`, `gps`, `powersaving`, `get KEY` (not secrets), `sensor get/list`, `advert`, `advert.zerohop`, `clock sync`, `set` on safe keys. Everything else (reboot, erase, ota, password, prv.key, radio/tx/repeat/flood settings, region changes, ...) is refused locally (nothing transmitted). Reply text returned. Default no retry (a retry executes again) |
| `set NODE KEY VALUE [--apply] [--allow-disruptive]` | guarded setting write: `get KEY` (before), compare, dry run unless --apply, `set KEY VALUE`, `get KEY` (read back; numeric values compared numerically). Result: before, after, changed, dry_run, set_reply, read_back, verified, applied. Safe keys: name, owner.info, lat, lon, advert.interval, flood.advert.interval; others need --allow-disruptive. Secret keys (prv.key, *password*, *secret*) are written without read-back (`applied: null`) |

Routing: direct along the learned path when known (learned from the node's PATH return after a flooded login/request), else flood. When direct attempts get no answer, the learned path is forgotten and the last retry floods (DM, login, request; firmware companion behaviour). `cmd` is not retried; an unanswered direct `cmd` forgets the path (`path_reset: true`), so the next call floods. Requests use fresh timestamps (firmware replay protection). All results are stored in `node_reports`.

Rooms: a successful room login joins the room (`rooms` table). The daemon keeps joined rooms alive: every `node.room_keepalive_s` (default 600; 0 = off) without traffic from the room it sends a keep-alive request (REQ 0x02 with the latest post timestamp received; direct only, as firmware), which also resumes pushes the room had stopped after 3 failed deliveries. After 2 unanswered keep-alives, or without a learned route, it logs in again with sync since = latest post received, so missed posts are pushed. On daemon start and stick reconnect, keep-alives go out within seconds. Re-login uses the password from the last API login (memory only) or config `passwords`. Room servers (firmware 1.18) keep posts in RAM only (lost on reboot) and their clock resets on power loss unless the board has a clock battery or GPS: after a room reboot run `cmd NODE 'clock sync'` (admin) and check `cmd NODE clock`. A room clock behind ours suppresses pushes of new posts to members whose sync since is ahead of it.


Secrets: commands touching `prv.key`, `password` or `secret` have their value and reply replaced by `<redacted>` in output, `requests`, `node_reports`, `tx_frames` and the stored copies of the CLI traffic in `rx_frames` (the reply to a pending secret command is redacted by the daemon).

Writes: prefer `set` (read, dry run, write, verify). Plan, read before, write, read back, restore when testing. Disruptive settings (radio parameters, `prv.key`, `password`, `reboot`, `erase`, region, repeat off) can cut the node off the mesh; avoid unless intended.

## Diagnostics

| Command | Effect |
|---|---|
| `trace PATH [--no-return] [--hash-size 1\|2\|4\|8] [--wait S]` | TRACE along repeaters (names or key prefixes). Round trip by default: `A,B` is sent as `A,B,A` so the result comes back to us. `--no-return` sends PATH as given (asymmetric routes, loops: `A,B,C` = out via A, B, back via C; we must hear the last hop). Each hop appends the SNR it received at. Returns `hops` [{hash, name, snr_db}], `final_snr_db`/`final_rssi` (last hop to us), rtt_ms, and `progress` (copies heard while under way). Needs: first hop hears us, each hop hears the previous, we hear the last. Stored in node_reports (kind `trace`) |
| `topology [--since S] [--sources path,neighbours,trace,discover]` | directed link graph (edge from->to: `to` received `from`), offline. Sources: flood paths in rx_frames (origin -> hops -> us; RF values only for the last hop to us), latest neighbour report per repeater (SNR measured by the reporter; heard time within --since), traces (SNR per hop), discover replies (both directions). Edge fields: count, last, snr_avg, snr_min, rssi_avg, source. Nodes: full key when a prefix matches exactly one known key; else `prefix:<hex>` using the longest consistent prefix seen (2-byte path hashes and 6-byte neighbour prefixes of one node merge); `ambiguous` lists candidate keys when a prefix matches several |

Hash collisions: with 1-byte path hashes many nodes share a hash. Use `topology` `ambiguous`, or `sql "SELECT name, public_key FROM nodes WHERE hash='aa'"`.

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
