# meshtadpole-meshcore-cli

Host-side MeshCore node for the MeshTadpole SX1262 USB stick. Binary: `tadpole-mc`. Windows, Linux.

Target users: AI agents and engineers operating dense MeshCore networks. The CLI is an interface to the mesh; analysis is done by the caller.

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

- Phase 1 (receive): decode and store of all payload types, advert signature verification, channel decryption, node table from adverts, flood path and last-hop recording.
- Phase 2 (transmit): adverts (zero hop / flood), channel messages, DMs with ACK and retries, path learning from PATH returns, automatic ACK / PATH replies, echo tracking of our own packets.
- Phase 3 (management): DISCOVER of direct neighbours, login, status/telemetry/neighbours/ACL/owner requests, remote CLI commands, bulk targets, report history (`node_reports`).
- Next: diagnostics (TRACE, topology from paths and neighbour reports).

## License

MIT
