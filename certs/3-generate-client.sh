#!/bin/sh

ORG_ID=$1
USER_ID=$2

if [ -z "$USER_ID" ] || [ -z "$ORG_ID" ]; then
  echo "Usage: $0 <org-id> <user-id>"
  exit 1
fi

# Generate client private key
openssl genrsa -out client.key 2048

# Create client CSR
openssl req -new -key client.key -out client.csr \
  -subj "/C=US/ST=State/L=City/O=TinyScale/CN=user@tinyscale.com"

# Create client certificate config with SPIFFE URI
cat > client.ext << EOF
subjectAltName = URI:spiffe://tinyscale.com/orgs/${ORG_ID}/users/${USER_ID}
extendedKeyUsage = clientAuth
EOF

# Sign client certificate
openssl x509 -req -days 365 -in client.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out client.crt -extfile client.ext