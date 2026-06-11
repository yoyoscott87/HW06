#!/bin/bash
# Generate a self-signed CA plus a server cert (with SAN=IP:192.168.2.1)
# and a client cert, both signed by that CA. Run this once, then copy
# the relevant files to VM1 (client) and VM2 (server) as noted below.
set -e

# 1. CA: private key + self-signed certificate
openssl genrsa -out ca-key.pem 4096
openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 3650 \
    -out ca-cert.pem -subj "/C=TW/O=MyVPN/CN=MyVPN-CA"

# 2. Server (VM2, 192.168.2.1) key + CSR + cert signed by the CA
openssl genrsa -out server-key.pem 2048
openssl req -new -key server-key.pem -out server.csr \
    -subj "/C=TW/O=MyVPN/CN=vpn-server"
echo "subjectAltName=IP:192.168.2.1" > server-ext.cnf
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
    -out server-cert.pem -days 825 -sha256 -extfile server-ext.cnf

# 3. Client (VM1) key + CSR + cert signed by the CA
openssl genrsa -out client-key.pem 2048
openssl req -new -key client-key.pem -out client.csr \
    -subj "/C=TW/O=MyVPN/CN=vpn-client"
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
    -out client-cert.pem -days 825 -sha256

echo
echo "Done. Files to copy:"
echo "  VM2 (server): ca-cert.pem server-cert.pem server-key.pem"
echo "  VM1 (client): ca-cert.pem client-cert.pem client-key.pem"
