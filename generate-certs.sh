#!/bin/bash

# Exit on error
set -e

mkdir -p certs

# Generate a private key
openssl genpkey -algorithm RSA -out certs/server.key

# Create a config file for the certificate
cat > certs/openssl.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
EOF

# Generate a self-signed certificate
openssl req -new -x509 -key certs/server.key -out certs/server.crt -days 365 -config certs/openssl.cnf -extensions v3_req

echo "Certificates generated in certs/ directory"
