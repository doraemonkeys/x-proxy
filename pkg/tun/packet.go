package tun

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	IPv4HeaderLen = 20
	IPv6HeaderLen = 40
	TCPHeaderLen  = 20
	UDPHeaderLen  = 8
)

// IPPacket represents an IP packet
type IPPacket struct {
	Version    uint8
	Protocol   uint8
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	Data       []byte
	IsIPv6     bool
	TCPFlags   uint8
	TCPSeq     uint32
	TCPAck     uint32
}

// ParseIPPacket parses an IP packet from raw bytes
func ParseIPPacket(data []byte) (*IPPacket, error) {
	if len(data) < IPv4HeaderLen {
		return nil, fmt.Errorf("packet too short for IP header")
	}

	packet := &IPPacket{}
	
	// Parse IP version
	packet.Version = (data[0] >> 4) & 0xF
	
	if packet.Version == 4 {
		return parseIPv4Packet(data, packet)
	} else if packet.Version == 6 {
		return parseIPv6Packet(data, packet)
	}
	
	return nil, fmt.Errorf("unsupported IP version: %d", packet.Version)
}

func parseIPv4Packet(data []byte, packet *IPPacket) (*IPPacket, error) {
	if len(data) < IPv4HeaderLen {
		return nil, fmt.Errorf("packet too short for IPv4 header")
	}

	packet.IsIPv6 = false
	headerLen := int((data[0] & 0xF) * 4)
	if headerLen < IPv4HeaderLen {
		return nil, fmt.Errorf("invalid IPv4 header length: %d", headerLen)
	}

	packet.Protocol = data[9]
	packet.SrcIP = net.IP(data[12:16])
	packet.DstIP = net.IP(data[16:20])

	if len(data) < headerLen {
		return nil, fmt.Errorf("packet too short for complete IPv4 header")
	}

	payload := data[headerLen:]
	return parseTransportLayer(payload, packet)
}

func parseIPv6Packet(data []byte, packet *IPPacket) (*IPPacket, error) {
	if len(data) < IPv6HeaderLen {
		return nil, fmt.Errorf("packet too short for IPv6 header")
	}

	packet.IsIPv6 = true
	packet.Protocol = data[6] // Next Header field
	packet.SrcIP = net.IP(data[8:24])
	packet.DstIP = net.IP(data[24:40])

	payload := data[IPv6HeaderLen:]
	return parseTransportLayer(payload, packet)
}

func parseTransportLayer(data []byte, packet *IPPacket) (*IPPacket, error) {
	switch packet.Protocol {
	case 6: // TCP
		return parseTCPPacket(data, packet)
	case 17: // UDP
		return parseUDPPacket(data, packet)
	default:
		// For other protocols, we still store the data
		packet.Data = data
		return packet, nil
	}
}

func parseTCPPacket(data []byte, packet *IPPacket) (*IPPacket, error) {
	if len(data) < TCPHeaderLen {
		return nil, fmt.Errorf("packet too short for TCP header")
	}

	packet.SrcPort = binary.BigEndian.Uint16(data[0:2])
	packet.DstPort = binary.BigEndian.Uint16(data[2:4])
	packet.TCPSeq = binary.BigEndian.Uint32(data[4:8])
	packet.TCPAck = binary.BigEndian.Uint32(data[8:12])
	packet.TCPFlags = data[13]

	headerLen := int((data[12] >> 4) * 4)
	if headerLen < TCPHeaderLen || len(data) < headerLen {
		return nil, fmt.Errorf("invalid TCP header length")
	}

	packet.Data = data[headerLen:]
	return packet, nil
}

func parseUDPPacket(data []byte, packet *IPPacket) (*IPPacket, error) {
	if len(data) < UDPHeaderLen {
		return nil, fmt.Errorf("packet too short for UDP header")
	}

	packet.SrcPort = binary.BigEndian.Uint16(data[0:2])
	packet.DstPort = binary.BigEndian.Uint16(data[2:4])
	packet.Data = data[UDPHeaderLen:]
	
	return packet, nil
}

// String returns a string representation of the packet
func (p *IPPacket) String() string {
	protocol := "Unknown"
	switch p.Protocol {
	case 6:
		protocol = "TCP"
	case 17:
		protocol = "UDP"
	case 1:
		protocol = "ICMP"
	}

	return fmt.Sprintf("%s %s:%d -> %s:%d", 
		protocol, p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
}

// IsTCP returns true if the packet is a TCP packet
func (p *IPPacket) IsTCP() bool {
	return p.Protocol == 6
}

// IsUDP returns true if the packet is a UDP packet
func (p *IPPacket) IsUDP() bool {
	return p.Protocol == 17
}

// GetTarget returns the target address in host:port format
func (p *IPPacket) GetTarget() string {
	return net.JoinHostPort(p.DstIP.String(), fmt.Sprintf("%d", p.DstPort))
}