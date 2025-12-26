#!/bin/sh

ORG_ID=$1
USER_ID=$2

if [ -z "$USER_ID" ] || [ -z "$ORG_ID" ]; then
  echo "Usage: $0 <org-id> <user-id>"
  exit 1
fi

# Generate client private key
openssl genrsa -out ${USER_ID}.key 2048

# Create client CSR
openssl req -new -key ${USER_ID}.key -out ${USER_ID}.csr \
  -subj "/C=US/ST=State/L=City/O=TinyScale/CN=user@tinyscale.com"

# Create client certificate config with SPIFFE URI
cat > ${USER_ID}.ext << EOF
subjectAltName = URI:spiffe://tinyscale.com/orgs/${ORG_ID}/users/${USER_ID}
extendedKeyUsage = clientAuth
EOF

# Sign client certificate
openssl x509 -req -days 365 -in ${USER_ID}.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out ${USER_ID}.crt -extfile ${USER_ID}.ext