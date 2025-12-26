#!/bin/sh

# Generate CA private key
openssl genrsa -out ca.key 4096

# Generate CA certificate
openssl req -new -x509 -days 3650 -key ca.key -out ca.pem \
  -subj "/C=US/ST=State/L=City/O=TinyScale/CN=TinyScale CA"

  echo "CA certificate and key generated: ca.pem, ca.key"