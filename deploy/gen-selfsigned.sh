#!/bin/sh
# Self-signed TLS certificate for the lab controller (production: use a real CA certificate).
set -eu
DIR="$(dirname "$0")/../secrets/tls"
mkdir -p "$DIR"
[ -f "$DIR/nixfort.crt" ] && { echo "certificate already exists: $DIR"; exit 0; }
openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes \
  -keyout "$DIR/nixfort.key" -out "$DIR/nixfort.crt" \
  -subj "/CN=nixfort-controller" \
  -addext "subjectAltName=IP:127.0.0.1,IP:10.77.0.10,DNS:localhost"
chmod 600 "$DIR/nixfort.key"
echo "created $DIR/nixfort.crt"
