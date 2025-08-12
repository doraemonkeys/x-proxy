# x-proxy

A Go-based client-server proxy application that provides secure and obfuscated tunneling for network traffic. The system uses XOR cipher obfuscation and supports multiple transport protocols and proxy modes.

## Features

- **Multiple Transport Protocols**: TCP with TLS encryption and KCP (UDP-based) support
- **Traffic Obfuscation**: XOR cipher with shared key to obfuscate traffic patterns
- **Multiple Proxy Modes**: SOCKS5, HTTP, and transparent proxy support
- **Cross-Platform**: Works on Linux, macOS, and Windows (transparent mode Linux-only)
- **TLS Encryption**: Built-in TLS support for secure communication

## Quick Start

### Prerequisites

- Go 1.24.6 or later
- For transparent proxy mode: Linux with iptables

### Building

Build both binaries:
```bash
./build.sh
```

Or build individually:
```bash
go build -o x-proxy-server cmd/server/main.go
go build -o x-proxy-client cmd/client/main.go
```

### Certificate Generation

Generate TLS certificates for secure communication:
```bash
./generate-certs.sh
```

### Configuration

Create configuration files based on the examples:

**Server Config (`config.server.json`)**:
```json
{
  "listen_addr": ":8080",
  "key": "your-shared-secret-key",
  "transport": "tcp",
  "tls": {
    "cert_file": "certs/server.crt",
    "key_file": "certs/server.key"
  },
  "log_level": "info"
}
```

**Client Config (`config.client.json`)**:
```json
{
  "server_addr": "your-server:8080",
  "key": "your-shared-secret-key",
  "transport": "tcp",
  "tls": {
    "ca_file": "certs/ca.crt"
  },
  "modes": [
    {
      "type": "socks5",
      "listen_addr": ":1080"
    }
  ],
  "log_level": "info"
}
```

### Running

Start the server:
```bash
./x-proxy-server
```

Start the client:
```bash
./x-proxy-client
```

## Architecture

### Package Structure

- `cmd/`: Main applications
  - `server/`: Server entry point
  - `client/`: Client entry point
- `pkg/`: Reusable packages
  - `config/`: Configuration loading
  - `logger/`: Logging utilities
  - `obfuscator/`: XOR cipher implementation
  - `proxy/`: Core proxy logic

### Data Flow

1. Client receives local connections on configured proxy modes
2. Client obfuscates traffic using XOR cipher and forwards to server
3. Server deobfuscates traffic and forwards to target destinations
4. Responses follow reverse path with obfuscation

## Transport Protocols

### TCP with TLS
- Default transport protocol
- Uses TLS for encryption and authentication
- Reliable connection-oriented communication

### KCP
- UDP-based transport protocol
- Better performance in high-latency or lossy networks
- Built-in Reed-Solomon error correction

## Proxy Modes

### SOCKS5
Standard SOCKS5 proxy protocol supporting TCP connections.

### HTTP
HTTP proxy support for web traffic.

### Transparent (Linux only)
Transparent proxy mode that works with iptables for seamless traffic redirection.

## Configuration Options

### Server Configuration

| Option | Description | Required |
|--------|-------------|----------|
| `listen_addr` | Server bind address and port | Yes |
| `key` | Shared obfuscation key | Yes |
| `transport` | Transport protocol ("tcp" or "kcp") | Yes |
| `tls` | TLS certificate configuration | If using TCP |
| `log_level` | Logging verbosity | No |

### Client Configuration

| Option | Description | Required |
|--------|-------------|----------|
| `server_addr` | x-proxy server address | Yes |
| `key` | Shared obfuscation key (must match server) | Yes |
| `transport` | Transport protocol ("tcp" or "kcp") | Yes |
| `tls` | TLS certificate configuration | If using TCP |
| `modes` | Array of proxy configurations | Yes |
| `log_level` | Logging verbosity | No |


## Dependencies

Key external dependencies:
- `github.com/xtaci/kcp-go`: KCP transport protocol
- `github.com/klauspost/reedsolomon`: Reed-Solomon error correction
- `golang.org/x/crypto`, `golang.org/x/net`, `golang.org/x/sys`: Go extended libraries

## Security Considerations

- Always use strong, unique shared keys for obfuscation
- Use TLS transport for additional encryption layer
- Regularly rotate shared keys in production environments
- Monitor logs for suspicious activity
- Keep certificates up to date

## License

[License information not specified]

## Contributing

[Contributing guidelines not specified]