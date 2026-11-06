#!/usr/bin/env bash
set -euo pipefail

OUT=${1:-certs}
mkdir -p "$OUT"
cd "$OUT"
umask 077

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out ca.key
openssl req -x509 -new -sha256 -days 3650 -key ca.key \
  -subj "/CN=Inline Secure Channel Lab CA" -out ca.crt

for device in d1 d2; do
  if [[ "$device" == d1 ]]; then dns=dev1; else dns=dev2; fi
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$device.key"
  openssl req -new -key "$device.key" -subj "/CN=$dns" -out "$device.csr"
  cat > "$device.ext" <<EXT
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:$dns
EXT
  openssl x509 -req -in "$device.csr" -CA ca.crt -CAkey ca.key \
    -CAcreateserial -days 825 -sha256 -extfile "$device.ext" -out "$device.crt"
  rm -f "$device.csr" "$device.ext"
done
chmod 600 ca.key d1.key d2.key
printf 'Created CA and mutual-TLS identities in %s/\n' "$OUT"
