#!/bin/bash

# Exit on error
set -e

echo "Building server..."
go build -o x-proxy-server cmd/server/main.go

echo "Building client..."
go build -o x-proxy-client cmd/client/main.go

echo "Build complete."
echo "Binaries: ./x-proxy-server and ./x-proxy-client"
