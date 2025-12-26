#!/bin/sh

SERVER_NAME=$1
if [ -z "$SERVER_NAME" ]; then
  echo "Usage: $0 <server-name>"
  exit 1
fi

# Generate server private key
openssl genrsa -out server.key 2048

# Create server CSR
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=State/L=City/O=TinyScale/CN=${SERVER_NAME}"

# Create server certificate config
cat > server.ext << EOF
subjectAltName = DNS:${SERVER_NAME},DNS:*.${SERVER_NAME},DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF

# Sign server certificate
openssl x509 -req -days 365 -in server.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.crt -extfile server.ext