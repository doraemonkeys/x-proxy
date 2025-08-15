#!/bin/bash

# Exit on error
set -e

# Detect architecture using Go environment
echo "Detecting architecture using Go..."
GO_ARCH=$(go env GOARCH)

case "$GO_ARCH" in
    "amd64")
        ARCH="amd64"
        ;;
    "arm64")
        ARCH="arm64"
        ;;
    "arm")
        ARCH="arm"
        ;;
    "386")
        ARCH="x86"
        ;;
    *)
        echo "Warning: Unsupported Go architecture $GO_ARCH, defaulting to amd64"
        ARCH="amd64"
        ;;
esac

echo "Detected architecture: $ARCH"

# Copy the appropriate wintun.dll
if [[ -f "wintun/bin/$ARCH/wintun.dll" ]]; then
    echo "Copying wintun/bin/$ARCH/wintun.dll to current directory..."
    cp "wintun/bin/$ARCH/wintun.dll" ./
else
    echo "Error: wintun.dll not found for architecture $ARCH"
    exit 1
fi

echo "Building server..."
go build -o x-proxy-server.exe cmd/server/main.go

echo "Building client..."
go build -o x-proxy-client.exe cmd/client/main.go

echo "Build complete."
echo "Binaries: ./x-proxy-server.exe and ./x-proxy-client.exe"