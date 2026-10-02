mod config;
mod filter;
mod lists;
mod rules;
mod server;

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use tokio::{
    net::{TcpListener, UdpSocket},
    signal::unix::{SignalKind, signal},
    sync::mpsc,
};

use crate::{
    config::Config,
    filter::Filter,
    lists::{Cmd, ListManager},
    rules::Rules,
    server::State,
};

const DEFAULT_CONFIG: &str = "/etc/dnsfilter/config.toml";

fn parse_args() -> (PathBuf, Option<String>) {
    // dnsfilter [--config PATH] [check DOMAIN]
    let mut args = std::env::args().skip(1);
    let mut cfg = PathBuf::from(DEFAULT_CONFIG);
    let mut check = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" | "-c" => cfg = args.next().map(PathBuf::from).unwrap_or(cfg),
            "check" => check = args.next(),
            "--help" | "-h" => {
                eprintln!("usage: dnsfilter [--config PATH] [check DOMAIN]");
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument {other:?} (try --help)");
                std::process::exit(2);
            }
        }
    }
    (cfg, check)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Logs go to stderr so `dnsfilter check` output on stdout stays clean.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    // reqwest is built with `rustls-no-provider`; pick ring once, process-wide.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let (cfg_path, check) = parse_args();
    let cfg = Config::load(&cfg_path)?;

    let rules = Arc::new(ArcSwap::from_pointee(Rules::default()));
    let lists = Arc::new(ListManager::new(cfg.lists, rules.clone())?);

    // Load whatever is already cached *before* we start answering, so a restart
    // never has a window where nothing is blocked.
    lists.rebuild().await?;

    if let Some(domain) = check {
        let name = domain.trim_end_matches('.').to_ascii_lowercase();
        match rules.load().lookup(&name) {
            Some((kind, rule)) => println!("{name}: {kind:?} (matched rule: {rule})"),
            None => println!("{name}: not listed (would be forwarded)"),
        }
        return Ok(());
    }

    let state = Arc::new(State {
        filter: Filter::new(rules.clone(), cfg.block.mode, cfg.block.ttl),
        upstream: cfg.upstream.addr,
        timeout: Duration::from_millis(cfg.upstream.timeout_ms),
    });

    // Bind everything up front so a bad address / busy port fails loudly at startup.
    for addr in &cfg.listen.plain {
        let udp = UdpSocket::bind(addr).await.with_context(|| format!("binding udp {addr} (is something else on port 53?)"))?;
        let tcp = TcpListener::bind(addr).await.with_context(|| format!("binding tcp {addr}"))?;
        tokio::spawn(server::serve_udp(udp, state.clone()));
        tokio::spawn(server::serve_tcp(tcp, state.clone()));
        tracing::info!(%addr, "listening (udp+tcp)");
    }

    let mut tls_reload = None;
    if let Some(tls) = &cfg.tls {
        let tls_cfg = Arc::new(ArcSwap::new(server::load_tls_config(&tls.cert, &tls.key)?));
        let allowed = Arc::new(tls.allowed_sni.clone());
        for addr in &tls.listen {
            let l = TcpListener::bind(addr).await.with_context(|| format!("binding dot {addr}"))?;
            tokio::spawn(server::serve_tls(l, state.clone(), tls_cfg.clone(), allowed.clone()));
            tracing::info!(%addr, sni_restricted = !allowed.is_empty(), "listening (DoT)");
        }
        tls_reload = Some((tls_cfg, tls.cert.clone(), tls.key.clone()));
    }

    // Background list updater + signal handling.
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    tokio::spawn(lists.clone().run(cmd_rx));

    let mut hup = signal(SignalKind::hangup())?;
    let mut usr1 = signal(SignalKind::user_defined1())?;
    let mut term = signal(SignalKind::terminate())?;
    loop {
        tokio::select! {
            _ = hup.recv() => {
                tracing::info!("SIGHUP: reloading certificate and lists");
                if let Some((swap, cert, key)) = &tls_reload {
                    match server::load_tls_config(cert, key) {
                        Ok(c) => { swap.store(c); tracing::info!("TLS certificate reloaded"); }
                        Err(e) => tracing::error!("TLS reload failed, keeping the old certificate: {e:#}"),
                    }
                }
                let _ = cmd_tx.send(Cmd::Reload);
            }
            _ = usr1.recv() => {
                tracing::info!("SIGUSR1: forcing list download");
                let _ = cmd_tx.send(Cmd::ForceUpdate);
            }
            _ = term.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    tracing::info!("shutting down");
    Ok(())
}
