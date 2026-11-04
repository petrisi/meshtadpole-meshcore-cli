# meshtadpole-meshcore-cli

Host-side MeshCore node for the MeshTadpole SX1262 USB stick. Binary: `tadpole-mc`. Windows, Linux.

Target users: AI agents and engineers operating MeshCore networks. The CLI is an interface to the mesh; analysis is done by the caller.

## Architecture

- Radio and daemon infrastructure: `meshtadpole-radio` (CH341 + SX1262 driver, radio session loop with reconnect/CSMA/duty cycle/noise stats/watchdog, NDJSON API transport, common SQLite tables). No firmware on the stick.
- Daemon: owns the stick and node identity (Ed25519), decodes and stores every received frame (raw, RF metadata, decoded/decrypted payload, failures) in SQLite. Never repeats packets.
- CLI: JSON on stdout, errors as JSON on stderr, stable exit codes, non-interactive. Talks to the daemon over `127.0.0.1:47404`; read queries open SQLite read-only.

## Quick start

```
tadpole-mc identity --generate     # new key pair in the config file (once)
tadpole-mc config                  # effective config, LoRa parameters, channel hashes
tadpole-mc daemon                  # foreground; run under a service manager
tadpole-mc status
tadpole-mc listen --seconds 60     # NDJSON frame stream
tadpole-mc nodes --type repeater
tadpole-mc packets --type GRP_TXT --since 3600
tadpole-mc sql "SELECT * FROM v_heard_repeaters ORDER BY last_heard DESC"
tadpole-mc advert --flood          # announce us; echoes show which repeaters relayed it
tadpole-mc send '#test' 'hello'    # channel message
tadpole-mc send 'Node name' 'hi'   # DM with ACK
```

Files: `<data dir>/meshtadpole/meshcore.json` (config, contains the private key) and `meshcore.db`. Data dir: `%LOCALAPPDATA%` (Windows), `~/.local/share` (Linux). Override with `--config`/`--db` or `TADPOLE_MC_CONFIG`/`TADPOLE_MC_DB`.

Exit codes: 0 ok, 1 error, 3 no device, 4 daemon not reachable.

Docs: [docs/cli.md](docs/cli.md), [docs/schema.md](docs/schema.md).

## Install

Requirements: Rust >= 1.85 (rustup), git.

Prebuilt binaries (Linux x86_64, Windows x86_64): GitHub Releases of this repo, built by `.github/workflows/release.yml` on a `v*` tag. Linux: `tar xzf tadpole-mc-<version>-x86_64-linux.tar.gz`, then install the binary as below (needs `libudev1`, present on desktop/server installs). Windows: unzip `tadpole-mc-<version>-x86_64-windows.zip`.

Build from source: dependency `meshtadpole-radio` (MIT) is fetched by cargo from the public repo `https://github.com/petrisi/meshtadpole-radio` (revision pinned in `Cargo.lock`; `cargo update -p meshtadpole-radio` moves to its latest commit).

Changing `meshtadpole-radio` together with this tool (both repos checked out side by side): build with an explicit patch, and do not commit the `Cargo.lock` it produces (it loses the git source):

```
cargo build --config 'patch."https://github.com/petrisi/meshtadpole-radio".meshtadpole-radio.path="../meshtadpole-radio"'
```

After pushing the radio change: `cargo update -p meshtadpole-radio` and commit `Cargo.lock`. CI builds with `--locked`.

Linux (tested Ubuntu 26.04, kernel 7.0):

```
sudo apt install build-essential pkg-config libudev-dev
cd meshtadpole-meshcore-cli && cargo build --release
sudo install -m 755 target/release/tadpole-mc /usr/local/bin/
```

USB access: root works as is (the kernel `spi_ch341` driver is detached automatically). Non-root: udev rule in the `meshtadpole-radio` README.

Windows (tested Windows 10):

```
cd meshtadpole-meshcore-cli
cargo build --release
mkdir %LOCALAPPDATA%\Programs\meshtadpole
copy target\release\tadpole-mc.exe %LOCALAPPDATA%\Programs\meshtadpole\
```

Add that directory to PATH. The stick needs the WinUSB driver (Zadig, device `1a86:5512`); the vendor CH341PAR driver is not used.

Then: `tadpole-mc config --write`, edit or `--set` the config, start `tadpole-mc daemon` (see "Running as a service").

## Running as a service

The daemon reconnects to the stick on its own (backoff 1-30 s) and starts without it. It exits on database errors and when the radio loop is blocked for 120 s (`radio_events` `stalled`, exit code 70); run it under a service manager that restarts it.

Linux (systemd), `/etc/systemd/system/tadpole-mc.service`:

```
[Unit]
Description=MeshCore node (tadpole-mc)
After=network.target

[Service]
ExecStart=/usr/local/bin/tadpole-mc daemon
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

`systemctl stop` (SIGTERM) ends the daemon session cleanly (`sessions.ended`); any exit, including a kill or the watchdog's exit 70, is restarted after 5 s. Tested with the v0.1.0 release binary on Ubuntu 26.04 (systemd 259). Logs: `journalctl -u tadpole-mc`.

Non-root: add the udev rule from `meshtadpole-radio` README and set `User=`. Config/DB then live in that user's `~/.local/share/meshtadpole/`.

Windows: Task Scheduler task "At startup", action `tadpole-mc.exe daemon`, settings "If the task fails, restart every 1 minute"; or a service wrapper (e.g. NSSM).

## Defaults (EU/UK Narrow, meshpirkanmaa.org)

| Parameter | Value |
|---|---|
| Frequency | 869.618 MHz |
| Bandwidth / SF / CR | 62.5 kHz / 8 / 4/8 |
| Sync word | 0x12 (RadioLib private) |
| Preamble | 32 symbols (SF ≤ 8, firmware `preambleLengthForSF`) |
| TX power | 14 dBm |
| Duty cycle | 10 % per rolling hour, enforced |
| Channels | Public (`izOH6cXN6mrJ5e26oRXNcg==`), #finland, #bot, #test, #telemetry, #ping, #parrot, #wardriving, #testing |

Hashtag channel key: `sha256("#name")[0..16]`. Channel hash: `sha256(key)[0]`.

## Protocol reference

MeshCore firmware v1.18.0 (`docs/packet_format.md`, `docs/payloads.md`, `src/Mesh.cpp`, `src/Utils.cpp`, `src/Identity.cpp`).

- Identity: Ed25519; private key stored as the 64-byte expanded form (orlp/ed25519). Node hash = first byte(s) of the public key. Keys starting 0x00/0xFF are reserved.
- Peer encryption: shared secret = X25519(clamped private scalar, Montgomery form of peer Ed25519 key), unhashed. AES-128-ECB with key = secret[0..16], zero padding; MAC = HMAC-SHA256(secret[0..32], ciphertext)[0..2].
- Packet hash (duplicate detection): sha256(payload type [+ path_len for TRACE] + payload)[0..8].

## Status

| Feature | State |
|---|---|
| RX, decode all payload types, advert signatures, channel decryption, store | working |
| Node table from adverts and DISCOVER, flood paths, last hop, duplicate linking | working |
| Adverts (zero hop / flood), channel messages, echo tracking | working (on air) |
| DMs with ACK, retries, path learning, automatic ACK / PATH replies | working (on air, direct neighbour; multi-hop flood DM to us not yet tested) |
| Telemetry answers to requests addressed to us | working (on air: companion shows 0.0 V) |
| Repeater management: login, status, telemetry, neighbours, ACL, owner, remote CLI, bulk targets | working (on air, firmware 1.17.1 and 1.18.0) |
| Learned route show / reset (`path`); automatic reset and flood after failed direct attempts | working |
| TRACE (round trip, asymmetric), topology graph, DISCOVER | working (on air) |
| Daemon: start without stick, reconnect, loop watchdog, stuck-receiver recovery | working (shared meshtadpole-radio) |
| Linux (Ubuntu 26.04.1, kernel 7.0) | working: build, tests, RX, TX (discover, trace), reconnect on attach |
| Room servers: login, posting, pushed posts ACKed, catch-up (`--since`), keep-alive and re-login (`rooms`, `leave`) | working (on air, stock firmware 1.18.0) |
| Region-scoped floods (`node.flood_scope`, `--scope`), anonymous requests (`anon`), channel datagrams (`send-data`) | working (on air) |

| Guarded setting writes (`set`: dry run, read-back), disruptive-command guard on `cmd`, secret redaction | working (on air) |

Development phases:

- Phase 1 (receive): decode and store of all payload types, advert signature verification, channel decryption, node table from adverts, flood path and last-hop recording.
- Phase 2 (transmit): adverts (zero hop / flood), channel messages, DMs with ACK and retries, path learning from PATH returns, automatic ACK / PATH replies, echo tracking of our own packets.
- Phase 3 (management): DISCOVER of direct neighbours, login, status/telemetry/neighbours/ACL/owner requests, remote CLI commands, bulk targets, report history (`node_reports`).
- Phase 4 (diagnostics): TRACE with per-hop SNR, topology graph from flood paths, neighbour reports, traces and discover replies, path hash resolution.
- Phase 5 (hardening): radio loop watchdog (exit 70 on a blocked loop), `status.loop_age_s`, service setup, Linux verification.

## License

MIT
