# meshtadpole-meshcore-cli

Host-side MeshCore node for the MeshTadpole SX1262 USB stick. Binary: `tadpole-mc`. Windows, Linux.

Target users: AI agents and engineers operating dense MeshCore networks. The CLI is an interface to the mesh; analysis is done by the caller.

## Architecture

- Radio: `meshtadpole-radio` (CH341 + SX1262). No firmware on the stick.
- Daemon: owns the stick and node identity (Ed25519), stores every received frame (raw, RF metadata, decrypted/decoded payload, decode failures) in SQLite.
- CLI: JSON/NDJSON on stdout, stable exit codes, non-interactive. Talks to the daemon over a local socket; read queries may access SQLite directly.
- Protocol: MeshCore packet format, adverts, path routing, ECDH + AES-128 + HMAC, repeater/room-server login and remote CLI.

## Target network defaults (EU/UK Narrow)

| Parameter | Value |
|---|---|
| Frequency | 869.618 MHz |
| Bandwidth | 62.5 kHz |
| Spreading factor | 8 |
| Coding rate | 4/8 |

Source: https://meshpirkanmaa.org

## Status

Skeleton.

## License

MIT
