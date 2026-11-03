# Database schema

SQLite, WAL mode. `meta.schema_version` = 1. Full DDL: `tadpole-mc schema`. Times are Unix seconds (REAL, host clock). Keys and hashes are lowercase hex.

Common tables (`sessions`, `radio_stats`, `radio_events`, `requests`) come from `meshtadpole-radio` and have the same meaning as in `tadpole-mt`:

| Table | Content |
|---|---|
| sessions | one row per daemon run: started, last_alive (60 s heartbeat), ended (NULL = crashed or running), usb_serial, radio parameters, redacted config |
| radio_stats | per 60 s: noise_min/avg/max (instantaneous RSSI ~1/s while idle, dBm), frames, crc_errors, header_errors, rx_airtime_ms |
| radio_events | `connected`, `disconnected`, `open_failed`, `rx_restored` |
| requests | daemon API requests that act on the mesh, with results |

## rx_frames

Every reception, including errors and duplicates. Source of truth.

| Column | Meaning |
|---|---|
| raw, len, airtime_ms | full over-the-air frame; computed time on air |
| rssi, snr, signal_rssi, freq_error_hz | SX1262 packet status |
| status | see below |
| route | `flood`, `direct`, `transport_flood`, `transport_direct` |
| payload_type, payload_ver | `ADVERT`, `GRP_TXT`, `GRP_DATA`, `TXT_MSG`, `REQ`, `RESPONSE`, `ANON_REQ`, `PATH`, `ACK`, `TRACE`, `MULTIPART`, `CONTROL`, `RAW_CUSTOM`, `TYPE_n` |
| transport_code1, transport_code2 | region scope codes (transport routes only) |
| path_hash_size, path_hops | path entry size (1-3 bytes) and count |
| path | comma-separated path entries. Flood: repeaters that relayed the packet, in order (origin side first). Direct: remaining route. TRACE: NULL (path holds SNRs, see data_json) |
| last_hop | flood with hops > 0: last path entry = repeater this copy was received from |
| pkt_hash | firmware packet hash (8 bytes): sha256(type [+ path_len for TRACE] + payload). Same for all copies of one packet |
| src_key | sender public key when known: ADVERT, ANON_REQ, DISCOVER_RESP (full key), decrypted peer message |
| src_hash, dest_hash | 1-byte node hashes from peer payloads (ambiguous: 256 values) |
| channel | matched channel name (GRP_TXT, GRP_DATA) |
| data_json | decoded payload, see below |
| dup_of | id of the first reception with the same pkt_hash within 1 h; NULL = first |

Status values:
- `ok`: parsed; decrypted where applicable.
- `crc_error`: payload CRC failed; fields may be garbage.
- `header_error`: LoRa header failed; only rx_time and instantaneous rssi stored.
- `malformed`: invalid wire format or payload too short.
- `unsupported_version`: payload version other than 1.
- `bad_signature`: advert signature invalid.
- `no_channel`: group message without a configured channel matching hash and MAC.
- `encrypted`: peer payload not to/from us, or peer key unknown.
- `decode_error`: decrypted, content invalid.

data_json by type:

| Type | Fields |
|---|---|
| ADVERT | public_key, timestamp (sender clock), signature_valid, flags, adv_type, adv_type_name, latitude, longitude, feat1, feat2, name |
| GRP_TXT | channel_hash, plain: {timestamp, txt_type, attempt, sender, text} |
| GRP_DATA | channel_hash, plain: {data_type, data_len, data_hex} |
| TXT_MSG / REQ / RESPONSE / PATH | ciphertext_len; when decrypted: peer, direction (`in`/`out`), plain |
| ANON_REQ | sender_public_key, ciphertext_len; plain when addressed to us |
| ACK | ack_crc, extra |
| TRACE | tag, auth_code, flags, hash_size, route (hashes to visit), snrs (dB per hop so far) |
| CONTROL | sub_type; DISCOVER_REQ: prefix_only, type_filter, tag, since; DISCOVER_RESP: node_type, snr, tag, public_key |
| MULTIPART | remaining, inner_type, ack_crc or data_hex |

## nodes

One row per public key, from verified adverts.

| Column | Meaning |
|---|---|
| public_key, hash | key; first byte (the node's path hash with 1-byte paths) |
| name, adv_type, flags, latitude, longitude, feat1, feat2, app_data_json | advertised data, taken from the newest advert by sender timestamp |
| advert_timestamp | sender clock of that advert |
| first_heard, last_heard, last_frame_id | any reception of its adverts |
| adverts_heard, receptions | distinct adverts; all copies |
| last_rssi, last_snr, last_route, last_path_hops, last_path | last received copy |
| last_direct_heard, last_direct_rssi, last_direct_snr | last copy with 0 hops (heard directly from the node) |

## tx_frames

Every transmission by this node (from phase 2): raw, len, airtime_ms, route, payload_type, pkt_hash, dest, data_json, attempt, error.

## Views

| View | Content |
|---|---|
| v_packets | rx_frames with rx_utc and src_name (from nodes) |
| v_adverts | verified adverts (all copies; dup_of marks relays) |
| v_channel_text | channel messages, first reception |
| v_heard_repeaters | per last_hop hash: frames, avg/min/max snr, avg rssi, first/last heard. Repeaters we receive directly |
