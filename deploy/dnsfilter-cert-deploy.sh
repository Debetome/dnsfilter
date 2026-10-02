#!/bin/sh
# Install as: /etc/letsencrypt/renewal-hooks/deploy/dnsfilter.sh   (chmod +x)
# certbot runs this ONLY after a certificate was actually renewed, with
# RENEWED_LINEAGE=/etc/letsencrypt/live/<name> in the environment.
set -eu
DEST=/etc/dnsfilter/tls
install -d -m 750 -o root -g dnsfilter "$DEST"
install -m 640 -o root -g dnsfilter "$RENEWED_LINEAGE/fullchain.pem" "$DEST/fullchain.pem"
install -m 640 -o root -g dnsfilter "$RENEWED_LINEAGE/privkey.pem"   "$DEST/privkey.pem"
# SIGHUP: dnsfilter re-reads the cert for new connections. If the new cert is
# broken it logs an error and keeps serving the old one.
systemctl reload dnsfilter
