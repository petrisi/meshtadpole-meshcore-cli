//! Tool configuration (JSON file).

use crate::crypto::{self, Identity};
use crate::decode::Channel;
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use meshtadpole_radio::sx1262::LoraConfig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// RadioLib SX126X private sync word, used by MeshCore.
pub const SYNC_WORD: u8 = 0x12;
pub const DEFAULT_API: &str = "127.0.0.1:47404";
pub const REDACTED: &str = "<redacted>";
/// MeshCore default Public channel key.
pub const PUBLIC_KEY_B64: &str = "izOH6cXN6mrJ5e26oRXNcg==";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadioConfig {
    pub frequency_mhz: f64,
    pub bandwidth_khz: f64,
    pub spreading_factor: u8,
    /// Coding rate denominator 5..8.
    pub coding_rate: u8,
    pub tx_power_dbm: i8,
    pub rx_boosted_gain: bool,
    /// Preventive receiver (AGC) reset interval in seconds; null = off (stuck detection still active).
    #[serde(default)]
    pub agc_reset_interval_s: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Advertised name.
    pub name: String,
    /// Advert type: chat (companion), repeater, room, sensor. This tool never repeats.
    pub adv_type: String,
    /// 64-byte expanded Ed25519 private key, hex. Generate with `tadpole-mc identity --generate`.
    pub private_key: Option<String>,
    /// Optional advertised location.
    #[serde(default)]
    pub latitude: Option<f64>,
    #[serde(default)]
    pub longitude: Option<f64>,
    /// Max fraction of airtime over a rolling hour (EU868 869.4-869.65 MHz: 0.10).
    pub duty_cycle_limit: f64,
    #[serde(default = "yes")]
    pub duty_cycle_enforce: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    pub name: String,
    /// Base64 or hex, 16 or 32 bytes. Omitted for `#name` channels: key = sha256("#name")[0..16].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub node: NodeConfig,
    pub radio: RadioConfig,
    pub channels: Vec<ChannelConfig>,
    pub api: String,
    #[serde(default)]
    pub usb_serial: Option<String>,
    /// Named node lists for bulk operations, referenced as `@name`.
    #[serde(default)]
    pub groups: std::collections::BTreeMap<String, Vec<String>>,
}

impl Default for Config {
    /// EU/UK Narrow (meshpirkanmaa.org) with Public and the local hashtag channels.
    fn default() -> Self {
        let mut channels = vec![ChannelConfig { name: "Public".into(), key: Some(PUBLIC_KEY_B64.into()) }];
        for n in ["#finland", "#bot", "#test", "#telemetry", "#ping", "#parrot", "#wardriving", "#testing"] {
            channels.push(ChannelConfig { name: n.into(), key: None });
        }
        Config {
            node: NodeConfig {
                name: "zerg admin".into(),
                adv_type: "chat".into(),
                private_key: None,
                latitude: None,
                longitude: None,
                duty_cycle_limit: 0.10,
                duty_cycle_enforce: true,
            },
            radio: RadioConfig {
                frequency_mhz: 869.618,
                bandwidth_khz: 62.5,
                spreading_factor: 8,
                coding_rate: 8,
                tx_power_dbm: 14,
                rx_boosted_gain: true,
                agc_reset_interval_s: None,
            },
            channels,
            api: DEFAULT_API.into(),
            usb_serial: None,
            groups: Default::default(),
        }
    }
}

fn decode_key(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(hex::decode(s)?);
    }
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

impl Config {
    pub fn channels(&self) -> Result<Vec<Channel>> {
        self.channels
            .iter()
            .map(|c| {
                let key = match (&c.key, c.name.starts_with('#')) {
                    (Some(k), _) => decode_key(k).with_context(|| format!("channel {} key", c.name))?,
                    (None, true) => crypto::hashtag_key(&c.name).to_vec(),
                    (None, false) => bail!("channel {}: key required (only #name channels derive it)", c.name),
                };
                let (secret, hash) = crypto::channel_secret(&key)?;
                Ok(Channel { name: c.name.clone(), secret, hash })
            })
            .collect()
    }

    pub fn identity(&self) -> Result<Option<Identity>> {
        self.node.private_key.as_deref().map(Identity::from_hex).transpose()
    }

    pub fn lora(&self) -> Result<LoraConfig> {
        let r = &self.radio;
        let bw = match r.bandwidth_khz as u32 {
            62 => 62.5,
            31 => 31.25,
            41 => 41.7,
            20 => 20.8,
            15 => 15.6,
            10 => 10.4,
            7 => 7.8,
            _ => r.bandwidth_khz,
        };
        if !(5..=8).contains(&r.coding_rate) {
            bail!("coding_rate must be 5..8");
        }
        Ok(LoraConfig {
            freq_hz: (r.frequency_mhz * 1e6).round() as u32,
            bw_hz: (bw * 1000.0).round() as u32,
            sf: r.spreading_factor,
            cr: r.coding_rate,
            sync_word: SYNC_WORD,
            // Firmware RadioLibWrapper::preambleLengthForSF.
            preamble_len: if r.spreading_factor <= 8 { 32 } else { 16 },
            tx_power_dbm: r.tx_power_dbm,
            tcxo_mv: 1800,
            rx_boosted_gain: r.rx_boosted_gain,
            current_limit_ma: 140,
        })
    }

    /// Copy with the private key replaced by `<redacted>`.
    pub fn redacted(&self) -> Config {
        let mut c = self.clone();
        if c.node.private_key.is_some() {
            c.node.private_key = Some(REDACTED.into());
        }
        c
    }

    pub fn load(path: &Path) -> Result<Config> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let s = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&s).with_context(|| format!("parse {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)? + "\n")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

pub fn default_dir() -> PathBuf {
    dirs::data_local_dir().unwrap_or_else(|| PathBuf::from(".")).join("meshtadpole")
}

pub fn adv_type_code(s: &str) -> Result<u8> {
    Ok(match s {
        "chat" => 1,
        "repeater" => 2,
        "room" => 3,
        "sensor" => 4,
        _ => return Err(anyhow!("unknown adv_type {s}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults() {
        let c = Config::default();
        let l = c.lora().unwrap();
        assert_eq!(l.freq_hz, 869_618_000);
        assert_eq!(l.bw_hz, 62_500);
        assert_eq!(l.preamble_len, 32);
        let ch = c.channels().unwrap();
        assert_eq!(hex::encode(&ch[0].secret[..16]), "8b3387e9c5cdea6ac9e5edbaa115cd72");
    }
}
