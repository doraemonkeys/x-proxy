# x-proxy

x-proxy is a secure and obfuscated client-server proxy application.

## Protocol

The communication between the client and server in transparent proxy mode is as follows:

### TCP

For TCP connections, the client sends a header to the server indicating the target destination. The format is:

```
tcp:{target_address}\0
```

- `{target_address}`: The destination address and port (e.g., `www.google.com:443`).
- `\0`: A null terminator byte.

After sending this header, the client starts relaying the TCP stream.

### UDP

For UDP packets, the client sends a header with each packet that includes the original destination and the packet length. The format is:

```
udp:{original_destination}\0{data_length}{data}
```

- `udp:{original_destination}\0`: The string "udp:", followed by the original destination address (e.g., `8.8.8.8:53`), terminated by a null byte.
- `{data_length}`: A 2-byte big-endian unsigned integer representing the length of the UDP data.
- `{data}`: The raw UDP packet data.
