//! Network front-end: UDP, TCP and DoT listeners plus the upstream client.
//!
//! All three transports funnel into `State::resolve`, which is
//!     packet -> Filter::decide -> (reply | forward to unbound)

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use hickory_proto::op::ResponseCode;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, mpsc},
    time::timeout,
};
use tokio_rustls::{LazyConfigAcceptor, rustls};

use crate::filter::{Decision, Filter, error_reply};

const MAX_UDP_INFLIGHT: usize = 2048;
const MAX_CONNECTIONS: usize = 512;
const MAX_INFLIGHT_PER_CONN: usize = 32;
const TCP_IDLE: Duration = Duration::from_secs(30);
const TLS_HANDSHAKE: Duration = Duration::from_secs(10);

pub struct State {
    pub filter: Filter,
    pub upstream: SocketAddr,
    pub timeout: Duration,
}

impl State {
    /// Full pipeline for one query. `None` means "send nothing".
    async fn resolve(&self, packet: &[u8], tcp: bool) -> Option<Vec<u8>> {
        match self.filter.decide(packet) {
            Decision::Drop => None,
            Decision::Reply(bytes) => Some(bytes),
            Decision::Forward => {
                let res = if tcp { self.forward_tcp(packet).await } else { self.forward_udp(packet).await };
                match res {
                    Ok(r) => Some(r),
                    Err(e) => {
                        tracing::warn!("upstream {} failed: {e:#}", self.upstream);
                        error_reply(packet, ResponseCode::ServFail)
                    }
                }
            }
        }
    }

    /// One short-lived connected socket per query: the kernel gives us a random
    /// source port, and only replies from the upstream address get through.
    async fn forward_udp(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let bind = if self.upstream.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let sock = UdpSocket::bind(bind).await?;
        sock.connect(self.upstream).await?;
        sock.send(packet).await?;
        let mut buf = vec![0u8; 65535];
        let id = [packet[0], packet[1]];
        timeout(self.timeout, async {
            loop {
                let n = sock.recv(&mut buf).await?;
                if n >= 12 && buf[..2] == id {
                    return Ok::<usize, std::io::Error>(n);
                }
            }
        })
        .await
        .context("timed out")?
        .map(|n| buf[..n].to_vec())
        .map_err(Into::into)
    }

    async fn forward_tcp(&self, packet: &[u8]) -> Result<Vec<u8>> {
        timeout(self.timeout, async {
            let mut s = TcpStream::connect(self.upstream).await?;
            s.set_nodelay(true)?;
            write_frame(&mut s, packet).await?;
            match read_frame(&mut s).await? {
                Some(r) => Ok(r),
                None => bail!("upstream closed the connection"),
            }
        })
        .await
        .context("timed out")?
    }
}

// ---------------------------------------------------------------- UDP

pub async fn serve_udp(sock: UdpSocket, state: Arc<State>) {
    let sock = Arc::new(sock);
    let permits = Arc::new(Semaphore::new(MAX_UDP_INFLIGHT));
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("udp recv: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        // Overloaded? Shed load instead of queueing forever.
        let Ok(permit) = permits.clone().try_acquire_owned() else { continue };
        let packet = buf[..n].to_vec();
        let (sock, state) = (sock.clone(), state.clone());
        tokio::spawn(async move {
            if let Some(resp) = state.resolve(&packet, false).await {
                if let Err(e) = sock.send_to(&resp, peer).await {
                    tracing::debug!("udp send to {peer}: {e}");
                }
            }
            drop(permit);
        });
    }
}

// ---------------------------------------------------------------- TCP

pub async fn serve_tcp(listener: TcpListener, state: Arc<State>) {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("tcp accept: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else { continue };
        let state = state.clone();
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            handle_stream(stream, state).await;
            tracing::trace!("tcp connection from {peer} closed");
            drop(permit);
        });
    }
}

// ---------------------------------------------------------------- DoT

pub async fn serve_tls(
    listener: TcpListener,
    state: Arc<State>,
    tls: Arc<ArcSwap<rustls::ServerConfig>>,
    allowed_sni: Arc<Vec<String>>,
) {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("tls accept: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else { continue };
        let (state, tls, allowed) = (state.clone(), tls.clone(), allowed_sni.clone());
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            match accept_tls(stream, &tls, &allowed).await {
                Ok(s) => handle_stream(s, state).await,
                Err(e) => tracing::debug!("dot handshake with {peer} rejected: {e:#}"),
            }
            drop(permit);
        });
    }
}

async fn accept_tls(
    stream: TcpStream,
    tls: &ArcSwap<rustls::ServerConfig>,
    allowed_sni: &[String],
) -> Result<tokio_rustls::server::TlsStream<TcpStream>> {
    // Read just the ClientHello first so we can look at the SNI *before*
    // committing to a handshake. `tls.load_full()` picks up a renewed cert
    // for every new connection with no restart.
    let start = timeout(TLS_HANDSHAKE, LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream))
        .await
        .context("clienthello timed out")??;
    if !allowed_sni.is_empty() {
        let hello = start.client_hello();
        let sni = hello.server_name().unwrap_or("");
        if !allowed_sni.iter().any(|a| a.eq_ignore_ascii_case(sni)) {
            bail!("SNI {sni:?} not allowed");
        }
    }
    let stream = timeout(TLS_HANDSHAKE, start.into_stream(tls.load_full()))
        .await
        .context("handshake timed out")??;
    Ok(stream)
}

pub fn load_tls_config(cert: &std::path::Path, key: &std::path::Path) -> Result<Arc<rustls::ServerConfig>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let certs = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("opening {}", cert.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parsing {}", cert.display()))?;
    let key = PrivateKeyDer::from_pem_file(key).with_context(|| format!("reading key {}", key.display()))?;
    // Explicit provider => no "which crypto backend?" panic if two are linked in.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("cert/key don't match or are unusable")?;
    cfg.alpn_protocols = vec![b"dot".to_vec()]; // what Android's Private DNS offers
    Ok(Arc::new(cfg))
}

// ------------------------------------------------- shared TCP/DoT logic

/// DNS over a byte stream (RFC 1035 sec 4.2.2 / RFC 7858): every message is
/// prefixed with a 2-byte big-endian length. Clients (Android especially)
/// pipeline many queries on one connection, so each query is handled
/// concurrently and a single writer task serialises the responses.
async fn handle_stream<S>(stream: S, state: Arc<State>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(MAX_INFLIGHT_PER_CONN);

    let writer = tokio::spawn(async move {
        while let Some(resp) = rx.recv().await {
            if write_frame(&mut wr, &resp).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT_PER_CONN));
    loop {
        let frame = match timeout(TCP_IDLE, read_frame(&mut rd)).await {
            Ok(Ok(Some(f))) => f,
            _ => break, // EOF, error, or idle timeout
        };
        let Ok(permit) = inflight.clone().acquire_owned().await else { break };
        let (state, tx) = (state.clone(), tx.clone());
        tokio::spawn(async move {
            if let Some(resp) = state.resolve(&frame, true).await {
                let _ = tx.send(resp).await;
            }
            drop(permit);
        });
    }
    drop(tx); // writer exits once the in-flight queries have sent their answers
    let _ = writer.await;
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u16::from_be_bytes(len) as usize;
    if len == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "zero-length DNS message"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, msg: &[u8]) -> std::io::Result<()> {
    let len = u16::try_from(msg.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "message > 65535 bytes"))?;
    // One write => one TLS record, instead of a 2-byte record and a body record.
    let mut out = Vec::with_capacity(2 + msg.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(msg);
    w.write_all(&out).await?;
    w.flush().await
}
