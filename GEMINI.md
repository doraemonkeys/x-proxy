# GEMINI Analysis: x-proxy

## Project Overview

This project is a Go-based client-server proxy application called `x-proxy`. It provides a secure and obfuscated tunnel for network traffic. The communication between the client and server is encrypted using TLS and can be transported over TCP or KCP. Additionally, the traffic is obfuscated using a simple XOR cipher.

The server listens for incoming connections from the client, de-obfuscates the traffic, and forwards it to the requested target destination. The client listens for local connections and supports multiple proxy modes: SOCKS5, HTTP, and transparent (including UDP on Linux). It obfuscates the traffic and sends it to the server.

The main technologies used are Go, with a clear separation of concerns into packages for configuration, logging, obfuscation, and proxy logic.

## Building and Running

### Building

The project can be built using the provided `build.sh` script. This will generate two binaries in the root directory: `x-proxy-server` and `x-proxy-client`.

```bash
./build.sh
```

### Running

**Server:**

To run the server, you need a `config.server.json` file. The server can be started with the following command:

```bash
./x-proxy-server
```

**Client:**

To run the client, you need a `config.client.json` file. The client can be started with the following command:

```bash
./x-proxy-client
```

### Configuration

**Server (`config.server.json`):**

```json
{
  "listen_addr": "0.0.0.0:8388",
  "key": "your-secret-key",
  "log_level": "debug",
  "transport": "tcp",
  "tls": {
    "cert_file": "certs/server.crt",
    "key_file": "certs/server.key"
  }
}
```

*   `listen_addr`: The address and port the server will listen on.
*   `key`: The secret key used for traffic obfuscation. This must match the client's key.
*   `log_level`: The logging level (e.g., "debug", "info", "warn", "error").
*   `transport`: The transport protocol to use ("tcp" or "kcp").
*   `tls`: TLS configuration.
    *   `cert_file`: Path to the server's TLS certificate.
    *   `key_file`: Path to the server's TLS private key.

**Client (`config.client.json`):**

```json
{
  "server_addr": "us.jonwinters.pw:8388",
  "key": "your-secret-key",
  "log_level": "info",
  "transport": "tcp",
  "tls": {
    "ca_file": "certs/server.crt"
  },
  "modes": [
    {
      "type": "socks5",
      "listen_addr": "127.0.0.1:4080"
    },
    {
      "type": "http",
      "listen_addr": "127.0.0.1:4081"
    },
    {
      "type": "transparent",
      "listen_addr": "127.0.0.1:4082"
    }
  ]
}
```

*   `server_addr`: The address and port of the `x-proxy` server.
*   `key`: The secret key for traffic obfuscation. Must match the server's key.
*   `log_level`: The logging level.
*   `transport`: The transport protocol to use ("tcp" or "kcp").
*   `tls`: TLS configuration.
    *   `ca_file`: Path to the CA certificate for verifying the server's certificate.
*   `modes`: An array of proxy modes to enable. Each mode has a `type` and a `listen_addr`.

## Development Conventions

*   **Structure:** The code is organized into `cmd` and `pkg` directories. `cmd` contains the main applications (client and server), and `pkg` contains reusable packages for different functionalities (config, logger, obfuscator, proxy).
*   **Configuration:** The application uses JSON files for configuration, with separate files for the client and server.
*   **Logging:** A simple logger is used, with configurable log levels.
*   **Obfuscation:** Traffic is obfuscated using an XOR cipher. The implementation is in `pkg/obfuscator/xor.go`. An empty key disables obfuscation.
*   **Proxy Logic:** The core proxy logic is implemented in the `pkg/proxy` package, with separate files for the client and server. The client supports multiple proxy modes.
*   **Transport:** The application supports both TCP and KCP as transport protocols.
*   **Security:** TLS is used to encrypt the connection between the client and server.
*   **Transparent Proxy:** Transparent proxying is supported on Linux for both TCP and UDP. For other operating systems, this feature is gracefully disabled.