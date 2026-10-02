# dnsfilter

A deliberately tiny DNS filter. Its whole job: **is this name on a blocklist? yes → answer "blocked", no → pass the original packet to unbound untouched.** Everything else (DNSSEC, caching, encrypted upstream, relays, certs) stays in the tools that already do it well.

```
 phone ──DoT :853───┐
                    ▼
 LAN ──── :53 ──▶ dnsfilter ──blocked──▶ NXDOMAIN (or 0.0.0.0)
                    │ not blocked: raw bytes, unmodified
                    ▼
              unbound 127.0.0.1:5335        DNSSEC validation + cache
                    │
                    ▼
        dnscrypt-proxy 127.0.0.1:5353       DNSCrypt + anonymised relays
                    │
                    ▼
              relay ─▶ resolver
```

| Port | Who | Reachable from |
|------|-----|----------------|
| 53 udp+tcp | dnsfilter | LAN only |
| 853 tcp (DoT) | dnsfilter | internet, if the phone must work away from home (see Security) |
| 5335 | unbound | loopback |
| 5353 | dnscrypt-proxy | loopback |

## Design decisions worth understanding

1. **dnsfilter sits in front of unbound, not behind it.** Blocked names never cost an upstream query, and unbound's cache can't "remember" an answer past a list update.
2. **We parse packets only to read the question.** Forwarded queries/answers are the original bytes. The DO bit, EDNS options, RRSIGs and unbound's AD flag all pass through untouched, so DNSSEC keeps working. Only blocked names get a response we build ourselves. (Tested: an upstream reply with `ad` set reaches the client with `ad` set.)
3. **Matching is by label suffix, most specific rule first, allow beats block on a tie.**
   `ads.example.com` in a list also blocks `x.ads.example.com`. Allow `cdn.example.com` and it punches a hole in a blocked `example.com`. Pi-hole's gravity lists are exact-match; if you want that instead, delete the `loop` in `Rules::lookup` and test only the full name.
4. **Lists are always loaded from disk.** A download only refreshes the cache. Startup is instant and works offline; a failed or garbage download (HTML error page, empty file) never replaces a good cache.
5. **Lock-free reloads.** Rules live in an `ArcSwap<Rules>`; a reload builds a new set on a blocking thread and swaps the pointer. Queries never wait.
6. **DoT handles pipelined queries concurrently** (Android sends many on one connection), so a fast blocked answer can overtake a slow forwarded one. That is legal; clients match on the query ID.
7. **Upstream failure → SERVFAIL** quickly (not a hang), and blocked names keep working with unbound down.

## Build

Needs Rust ≥ 1.85 (edition 2024). No OpenSSL, no C toolchain: TLS is rustls + ring.

```sh
cargo test
cargo build --release          # ~6 MB binary
sudo install -m 755 target/release/dnsfilter /usr/local/bin/
```

## Setup order

1. **dnscrypt-proxy** — apply `deploy/dnscrypt-proxy.settings.toml` (move it to :5353, DNSCrypt only, relays). Replace the `anon-RELAY-*` placeholders with real names from the relay list.
2. **unbound** — drop in `deploy/unbound-dnsfilter.conf`. Two lines matter most: `do-not-query-localhost: no` (otherwise every query SERVFAILs because dnscrypt-proxy is on loopback) and `forward-first: no`.
3. **Free port 53.** On Ubuntu/Debian: `DNSStubListener=no` in `/etc/systemd/resolved.conf`, restart `systemd-resolved`, and point `/etc/resolv.conf` at `127.0.0.1`.
4. **dnsfilter** —
   ```sh
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin dnsfilter
   sudo install -d /etc/dnsfilter && sudo cp config.example.toml /etc/dnsfilter/config.toml   # edit it
   sudo cp deploy/dnsfilter.service /etc/systemd/system/ && sudo systemctl daemon-reload
   sudo systemctl enable --now dnsfilter
   ```
   First start with no cache is fine: it serves immediately, fetches the lists in the background and hot-swaps them in (watch `journalctl -u dnsfilter -f`).
5. **Certificate** (needed for DoT). Android's Private DNS needs a hostname with a publicly trusted cert, so: a domain, a DNS-01 Let's Encrypt cert, then
   ```sh
   sudo install -m 755 deploy/dnsfilter-cert-deploy.sh /etc/letsencrypt/renewal-hooks/deploy/dnsfilter.sh
   sudo cp deploy/cron.certbot /etc/cron.d/certbot-dnsfilter       # or use your distro's certbot.timer, not both
   ```
   Do a first run of the hook by hand so `/etc/dnsfilter/tls/*.pem` exist before starting the service.
6. **Phone (Android):** Settings → Network → Private DNS → hostname = your `allowed_sni` name.

## Verify each layer

```sh
dnsfilter -c /etc/dnsfilter/config.toml check ad.doubleclick.net   # which rule matches? (reads cache, no network)
dig @127.0.0.1 ad.doubleclick.net                                  # blocked -> NXDOMAIN
dig @127.0.0.1 +adflag cloudflare.com                              # 'ad' in flags = unbound validated DNSSEC
dig @127.0.0.1 dnssec-failed.org                                   # deliberately broken DNSSEC -> SERVFAIL
RUST_LOG=debug dnsfilter ...                                       # logs every block decision
```
Note: BIND's `dig +tls` does not send SNI in some versions, so it will be rejected by `allowed_sni`. Test DoT with `openssl s_client -servername <name> -alpn dot` or a real phone.

## Signals

| Signal | Effect |
|--------|--------|
| `SIGHUP` (`systemctl reload`) | reload TLS cert + re-read lists from disk. A bad cert is rejected; the old one keeps serving |
| `SIGUSR1` | re-download every list now |
| `SIGTERM` / Ctrl-C | clean exit |

## Security: read this before opening 853 to the internet

An unauthenticated DoT port on the internet is an **open resolver**. Scanners find it within hours and it gets abused. Options, best first:
- **Don't expose it.** Put the phone on WireGuard/Tailscale and bind DoT to the VPN address. A DNS-01 cert works fine for a name that points at a private IP.
- **If you must expose it, use `allowed_sni`.** Handshakes without the right SNI are dropped. Use a **wildcard** certificate: a cert for the exact secret name would put that name in public Certificate-Transparency logs and defeat the point. Caveat: SNI is sent in clear (no ECH), so this stops scanners, not someone watching your phone's network.
- Firewall port 53 to the LAN. Never let plain DNS face the internet.

## Known limitations / sensible next steps

- **CNAME cloaking isn't caught**: only the name the client asked for is checked, not CNAME targets in the answer. Fix: parse unbound's answer and re-check each CNAME target (≈15 lines).
- **Memory**: ~60 bytes/domain. Measured: 1.5M domains = ~88 MB steady, ~121 MB peak during a reload. On a tiny board, store 64-bit hashes instead of strings (≈8 MB per million; collision odds are negligible).
- **TCP/DoT queries open a fresh loopback connection to unbound each time.** Fine at home scale; a small connection pool is the next optimisation.
- No query log, stats, per-client policy or regex rules (Pi-hole's regex list). By design, for now.
- Lists are re-downloaded in full; adding `ETag`/`If-Modified-Since` would save bandwidth.
