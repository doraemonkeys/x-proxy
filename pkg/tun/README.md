# TUN Package

This package implements TUN interface support, allowing x-proxy to handle traffic from a TUN device and forward it through an existing proxy server.

## Features

- **TUN Device Management**: Create and configure TUN interfaces on Linux.
- **Packet Parsing**: Parse IPv4/IPv6 packets, with support for TCP and UDP protocols.
- **Traffic Forwarding**: Forward TUN traffic through the existing x-proxy client to the server.
- **Connection Management**: Automatically manage the lifecycle of TCP and UDP connections.
- **Cross-platform**: Full support on Linux, with stub implementations for other platforms.

## Architecture

### Components

1.  **TunDevice**: An abstraction for the TUN device, responsible for reading and writing packets.
2.  **PacketParser**: Parses IP packets to extract source/destination addresses and ports.
3.  **Handler**: Processes TUN traffic and manages connection states.
4.  **ProxyForwarder**: An implementation that forwards traffic to the x-proxy server.

### Workflow

```
TUN Device → Packet Parsing → Connection Management → Proxy Forwarding → x-proxy Server
```

1.  Read raw IP packets from the TUN device.
2.  Parse the packets to get protocol, source/destination addresses, etc.
3.  Manage TCP/UDP connection states based on connection information.
4.  Forward data to the x-proxy server via the ProxyForwarder.
5.  Server responses are returned through the same path.

## Configuration Example

Add the TUN mode to the client configuration file:

```json
{
  "modes": [
    {
      "type": "tun",
      "tun_name": "tun0",
      "tun_ip": "10.0.0.1",
      "tun_netmask": "24"
    }
  ]
}
```

## Limitations and Notes

1.  **Linux Only**: Full functionality is only available on Linux.
2.  **Permissions Required**: Root privileges are needed to create TUN devices.
3.  **TCP State Machine**: The current implementation simplifies TCP state management.
4.  **UDP Sessions**: UDP connections are managed as sessions based on source/destination address pairs.
5.  **Dependencies**: Relies on the existing x-proxy client for actual network forwarding.

## Recent Improvements (Implemented)

- [x] **Mature Network Stack**: Uses the `github.com/google/gopacket` library for professional packet construction.
- [x] **Complete TCP State Machine**: Implemented handling for TCP states like SYN, SYN-ACK, ACK, FIN, RST.
- [x] **Correct Packet Construction**:
    - Automatic calculation of IP and TCP/UDP checksums.
    - Correct IP header settings (IPv4/IPv6 support).
    - RFC-compliant TCP/UDP header construction.
- [x] **TCP Connection Management**:
    - Sequence number tracking and management.
    - Connection establishment and termination handling.
    - Data transfer acknowledgment mechanism.
- [x] **UDP Packet Handling**: Complete UDP packet construction and forwarding.

## Technical Implementation Details

### New Components

1.  **PacketBuilder** (`packet_builder.go`):
    - Uses the gopacket library to build standard IP/TCP/UDP packets.
    - Supports IPv4 and IPv6.
    - Automatically calculates all necessary checksums and length fields.
    - Provides convenient methods to build various TCP control packets (SYN-ACK, ACK, FIN, RST).

2.  **TCPSeqTracker** (`packet_builder.go`):
    - Tracks TCP connection sequence and acknowledgment numbers.
    - Manages connection state and timeouts.

3.  **Enhanced Connection Management**:
    - TCP connections now include complete state information (IP addresses, ports, sequence number tracker).
    - UDP connections include necessary address information for packet construction.
    - Correct connection establishment and termination flow.

### Resolved TODOs

- ✅ `pkg/tun/handler.go:216` - Build and write TCP packets to the TUN device.
- ✅ `pkg/tun/handler.go:308` - Build and write UDP packets to the TUN device.

### Optimized Workflow

```
Inbound Packet (TUN → Proxy Server):
TUN Device → Packet Parsing → TCP/UDP State Management → Data Forwarding → Proxy Server

Outbound Packet (Proxy Server → TUN):
Proxy Server → Data Reception → PacketBuilder constructs response packet → Write to TUN Device
```

## Future Improvements

- [ ] More efficient packet reassembly and buffering.
- [ ] Support for more platforms (macOS, Windows).
- [ ] Performance optimization and memory pooling.
- [ ] Better error handling and reconnection mechanisms.
- [ ] TCP window management and flow control.
