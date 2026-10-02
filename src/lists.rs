//! Downloading, caching and (re)building the rule set.
//!
//! Flow:   URL --download--> cache_dir/<hash>.list --parse--> Rules --ArcSwap::store--> live
//!
//! * Lists are always loaded *from disk*. A download only refreshes the cache.
//!   That means startup is fast and works offline, and a failed download just
//!   leaves yesterday's list in place.
//! * Parsing happens on a blocking thread; the new `Rules` is swapped in
//!   atomically, so queries never see a half-built list and never block.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
use tokio::sync::mpsc;

use crate::{
    config::Lists,
    rules::{Rules, parse_into},
};

const CHECK_EVERY: Duration = Duration::from_secs(3600);
const MAX_LIST_BYTES: usize = 200 * 1024 * 1024;

pub enum Cmd {
    /// Re-read everything from disk (SIGHUP). No network.
    Reload,
    /// Re-download every list now, then reload (SIGUSR1).
    ForceUpdate,
}

pub struct ListManager {
    cfg: Lists,
    rules: Arc<ArcSwap<Rules>>,
    client: reqwest::Client,
}

fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// Stable, dependency-free hash for cache file names (std's DefaultHasher is
/// explicitly not stable across Rust releases).
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |h, &b| (h ^ b as u64).wrapping_mul(0x100000001b3))
}

impl ListManager {
    pub fn new(cfg: Lists, rules: Arc<ArcSwap<Rules>>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent(concat!("dnsfilter/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { cfg, rules, client })
    }

    fn path_for(&self, source: &str) -> PathBuf {
        if is_url(source) {
            self.cfg.cache_dir.join(format!("{:016x}.list", fnv1a(source.as_bytes())))
        } else {
            PathBuf::from(source)
        }
    }

    /// Download every URL whose cache is missing or older than the interval
    /// (or all of them if `force`). Returns how many were refreshed.
    pub async fn refresh(&self, force: bool) -> usize {
        let max_age = Duration::from_secs(self.cfg.update_interval_hours.max(1) * 3600);
        let mut updated = 0;
        for url in self.cfg.blocklists.iter().chain(&self.cfg.allowlists).filter(|s| is_url(s)) {
            let path = self.path_for(url);
            if !force && is_fresh(&path, max_age).await {
                continue;
            }
            match self.download(url, &path).await {
                Ok(bytes) => {
                    tracing::info!(%url, bytes, "list downloaded");
                    updated += 1;
                }
                Err(e) => tracing::warn!(%url, "download failed (keeping cached copy): {e:#}"),
            }
        }
        updated
    }

    async fn download(&self, url: &str, path: &Path) -> Result<usize> {
        let body = self.client.get(url).send().await?.error_for_status()?.bytes().await?;
        ensure!(body.len() <= MAX_LIST_BYTES, "list is suspiciously large ({} bytes)", body.len());

        // Don't let an HTML error page that came back as "200 OK" replace a good cache.
        let text = body.clone();
        let entries = tokio::task::spawn_blocking(move || {
            let mut s = HashSet::new();
            parse_into(&String::from_utf8_lossy(&text), &mut s);
            s.len()
        })
        .await?;
        ensure!(entries > 0, "no domains found in response, refusing to overwrite cache");

        tokio::fs::create_dir_all(&self.cfg.cache_dir).await?;
        let tmp = path.with_extension("tmp");
        tokio::fs::write(&tmp, &body).await?;
        tokio::fs::rename(&tmp, path).await?; // atomic on the same filesystem
        Ok(body.len())
    }

    /// Rebuild the live rule set from whatever is on disk right now.
    pub async fn rebuild(&self) -> Result<()> {
        let block: Vec<PathBuf> = self.cfg.blocklists.iter().map(|s| self.path_for(s)).collect();
        let allow: Vec<PathBuf> = self.cfg.allowlists.iter().map(|s| self.path_for(s)).collect();

        let new = tokio::task::spawn_blocking(move || {
            let load = |paths: &[PathBuf]| {
                let mut set = HashSet::new();
                for p in paths {
                    match std::fs::read(p) {
                        Ok(b) => parse_into(&String::from_utf8_lossy(&b), &mut set),
                        Err(e) => tracing::warn!(path = %p.display(), "list not readable (yet): {e}"),
                    }
                }
                set
            };
            Rules::new(load(&allow), load(&block))
        })
        .await
        .context("rebuild task panicked")?;

        let old = self.rules.load();
        if new.block_len() == 0 && old.block_len() > 0 {
            tracing::error!("rebuild produced an empty blocklist; keeping the previous rules");
            return Ok(());
        }
        tracing::info!(block = new.block_len(), allow = new.allow_len(), "rules loaded");
        self.rules.store(Arc::new(new));
        Ok(())
    }

    /// Background task: refresh stale lists every hour, react to signals.
    pub async fn run(self: Arc<Self>, mut cmds: mpsc::UnboundedReceiver<Cmd>) {
        // First pass right away: on a fresh install this is what fetches the lists.
        if self.refresh(false).await > 0 {
            self.rebuild_logged().await;
        }
        loop {
            tokio::select! {
                _ = tokio::time::sleep(CHECK_EVERY) => {
                    if self.refresh(false).await > 0 {
                        self.rebuild_logged().await;
                    }
                }
                cmd = cmds.recv() => match cmd {
                    Some(Cmd::Reload) => self.rebuild_logged().await,
                    Some(Cmd::ForceUpdate) => {
                        self.refresh(true).await;
                        self.rebuild_logged().await;
                    }
                    None => return,
                }
            }
        }
    }

    async fn rebuild_logged(&self) {
        if let Err(e) = self.rebuild().await {
            tracing::error!("rebuild failed: {e:#}");
        }
    }
}

async fn is_fresh(path: &Path, max_age: Duration) -> bool {
    let Ok(meta) = tokio::fs::metadata(path).await else { return false };
    let Ok(modified) = meta.modified() else { return false };
    SystemTime::now().duration_since(modified).map(|age| age < max_age).unwrap_or(true)
}
