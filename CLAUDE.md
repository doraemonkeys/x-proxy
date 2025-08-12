# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is `x-proxy`, a Go-based client-server proxy application that provides secure and obfuscated tunneling for network traffic. The system uses XOR cipher obfuscation and supports multiple transport protocols (TCP with TLS, KCP) and proxy modes (SOCKS5, HTTP, transparent).

## Common Build and Development Commands

### Building
```bash
./build.sh
```
This builds both binaries: `x-proxy-server` and `x-proxy-client`

Individual builds:
```bash
go build -o x-proxy-server cmd/server/main.go
go build -o x-proxy-client cmd/client/main.go
```

### Running
Server (requires `config.server.json`):
```bash
./x-proxy-server
```

Client (requires `config.client.json`):
```bash
./x-proxy-client
```

### Certificate Generation
```bash
./generate-certs.sh
```
Generates TLS certificates in the `certs/` directory for secure communication.

### Deployment
```bash
./rsync.sh
```
Syncs code to remote server (configured for `us.jonwinters.pw`).

## Architecture

### Package Structure
- `cmd/`: Main applications
  - `cmd/server/main.go`: Server entry point
  - `cmd/client/main.go`: Client entry point
- `pkg/`: Reusable packages
  - `pkg/config/`: JSON configuration loading for both client and server
  - `pkg/logger/`: Simple logging with configurable levels
  - `pkg/obfuscator/`: XOR cipher implementation for traffic obfuscation
  - `pkg/proxy/`: Core proxy logic
    - `client.go`: Client-side proxy handling multiple modes
    - `server.go`: Server-side connection handling and forwarding
    - `transparent_linux.go`: Linux-specific transparent proxy support
    - `transparent_other.go`: Fallback for non-Linux platforms

### Key Components

**Transport Layer**: Supports both TCP with TLS encryption and KCP (UDP-based) for different network conditions.

**Obfuscation**: Uses XOR cipher with shared key to obfuscate traffic patterns between client and server.

**Proxy Modes**: 
- SOCKS5: Standard SOCKS5 proxy protocol
- HTTP: HTTP proxy support  
- Transparent: Transparent proxy mode (Linux only with iptables integration)

**Configuration**: JSON-based configuration files with separate client and server configs supporting TLS certificates, transport selection, and multiple proxy mode definitions.

### Data Flow
1. Client receives local connections on configured proxy modes
2. Client obfuscates traffic using XOR cipher and forwards to server over chosen transport (TCP+TLS or KCP)
3. Server deobfuscates traffic and forwards to target destinations
4. Responses follow reverse path with obfuscation

## Configuration Files

### Server Config (`config.server.json`)
- `listen_addr`: Server bind address and port
- `key`: Shared obfuscation key (must match client)
- `transport`: "tcp" or "kcp"
- `tls`: Certificate and key file paths for TLS
- `log_level`: Logging verbosity

### Client Config (`config.client.json`) 
- `server_addr`: x-proxy server address
- `key`: Shared obfuscation key (must match server)
- `transport`: "tcp" or "kcp" 
- `tls`: CA certificate for server verification
- `modes`: Array of proxy configurations with type and listen address
- `log_level`: Logging verbosity

## Dependencies

Key external dependencies from `go.mod`:
- `github.com/xtaci/kcp-go`: KCP transport protocol implementation
- `github.com/klauspost/reedsolomon`: Reed-Solomon error correction for KCP
- `golang.org/x/crypto`, `golang.org/x/net`, `golang.org/x/sys`: Go extended libraries

Uses Go 1.24.6+ standard library for networking, TLS, and JSON handling.