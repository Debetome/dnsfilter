//! TOML configuration. `deny_unknown_fields` everywhere so a typo in the
//! config file is a startup error instead of a silently ignored setting.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: Listen,
    pub upstream: Upstream,
    #[serde(default)]
    pub block: Block,
    pub lists: Lists,
    /// Omit this whole section to disable DoT.
    pub tls: Option<Tls>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    /// Plain DNS. Every address is bound for BOTH udp and tcp.
    pub plain: Vec<SocketAddr>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// Your unbound instance, e.g. 127.0.0.1:5335
    pub addr: SocketAddr,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockMode {
    /// Answer NXDOMAIN for every blocked name (any record type).
    #[default]
    Nxdomain,
    /// Answer 0.0.0.0 / :: for A / AAAA, NOERROR+empty for everything else.
    NullIp,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Block {
    pub mode: BlockMode,
    /// TTL on synthetic answers (only used by `null_ip`).
    pub ttl: u32,
}

impl Default for Block {
    fn default() -> Self {
        Self { mode: BlockMode::default(), ttl: 60 }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lists {
    /// Where downloaded lists are cached (needs to be writable by the service user).
    pub cache_dir: PathBuf,
    #[serde(default = "default_interval_hours")]
    pub update_interval_hours: u64,
    /// Each entry is an http(s) URL or a local file path.
    #[serde(default)]
    pub blocklists: Vec<String>,
    #[serde(default)]
    pub allowlists: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub listen: Vec<SocketAddr>,
    pub cert: PathBuf,
    pub key: PathBuf,
    /// If non-empty, a TLS client must send one of these exact names as SNI,
    /// otherwise it is dropped before the handshake completes.
    #[serde(default)]
    pub allowed_sni: Vec<String>,
}

fn default_timeout_ms() -> u64 {
    3000
}
fn default_interval_hours() -> u64 {
    24
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
    }
}
