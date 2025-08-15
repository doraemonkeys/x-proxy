package tun

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCPFlag defines the type for TCP flags.
type TCPFlag uint8

// Constants for TCP flags.
const (
	TCPFin TCPFlag = 1 << 0
	TCPSyn TCPFlag = 1 << 1
	TCPRst TCPFlag = 1 << 2
	TCPPsh TCPFlag = 1 << 3
	TCPAck TCPFlag = 1 << 4
	TCPUrg TCPFlag = 1 << 5
	TCPEce TCPFlag = 1 << 6
	TCPCwr TCPFlag = 1 << 7
)

// PacketBuilder provides utilities for constructing IP packets
type PacketBuilder struct {
	buffer gopacket.SerializeBuffer
}

// NewPacketBuilder creates a new packet builder
func NewPacketBuilder() *PacketBuilder {
	return &PacketBuilder{
		buffer: gopacket.NewSerializeBuffer(),
	}
}

// BuildTCPResponse builds a TCP response packet
func (pb *PacketBuilder) BuildTCPResponse(
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	seq, ack uint32,
	flags TCPFlag,
	data []byte,
) ([]byte, error) {
	// Clear the buffer for reuse
	pb.buffer.Clear()

	// Determine IP version
	var ipLayer gopacket.SerializableLayer
	if srcIP.To4() != nil {
		// IPv4
		ip4 := &layers.IPv4{
			Version:    4,
			IHL:        5,
			TOS:        0,
			Length:     0, // Will be calculated automatically
			Id:         0,
			Flags:      layers.IPv4DontFragment,
			FragOffset: 0,
			TTL:        64,
			Protocol:   layers.IPProtocolTCP,
			Checksum:   0, // Will be calculated automatically
			SrcIP:      srcIP,
			DstIP:      dstIP,
		}
		ipLayer = ip4
	} else {
		// IPv6
		ip6 := &layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       0, // Will be calculated automatically
			NextHeader:   layers.IPProtocolTCP,
			HopLimit:     64,
			SrcIP:        srcIP,
			DstIP:        dstIP,
		}
		ipLayer = ip6
	}

	// TCP layer
	tcp := &layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		Seq:        seq,
		Ack:        ack,
		DataOffset: 5,
		FIN:        flags&TCPFin != 0,
		SYN:        flags&TCPSyn != 0,
		RST:        flags&TCPRst != 0,
		PSH:        flags&TCPPsh != 0,
		ACK:        flags&TCPAck != 0,
		URG:        flags&TCPUrg != 0,
		ECE:        flags&TCPEce != 0,
		CWR:        flags&TCPCwr != 0,
		Window:     65535,
		Checksum:   0, // Will be calculated automatically
		Urgent:     0,
		Options:    nil,
	}

	// Set network layer for checksum calculation
	if srcIP.To4() != nil {
		tcp.SetNetworkLayerForChecksum(ipLayer.(*layers.IPv4))
	} else {
		tcp.SetNetworkLayerForChecksum(ipLayer.(*layers.IPv6))
	}

	// Serialize the packet
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	var layersToSerialize []gopacket.SerializableLayer
	layersToSerialize = append(layersToSerialize, ipLayer)
	layersToSerialize = append(layersToSerialize, tcp)

	if len(data) > 0 {
		payload := gopacket.Payload(data)
		layersToSerialize = append(layersToSerialize, payload)
	}

	err := gopacket.SerializeLayers(pb.buffer, options, layersToSerialize...)
	if err != nil {
		return nil, err
	}

	return pb.buffer.Bytes(), nil
}

// BuildUDPResponse builds a UDP response packet
func (pb *PacketBuilder) BuildUDPResponse(
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	data []byte,
) ([]byte, error) {
	// Clear the buffer for reuse
	pb.buffer.Clear()

	// Determine IP version
	var ipLayer gopacket.SerializableLayer
	if srcIP.To4() != nil {
		// IPv4
		ip4 := &layers.IPv4{
			Version:    4,
			IHL:        5,
			TOS:        0,
			Length:     0, // Will be calculated automatically
			Id:         0,
			Flags:      layers.IPv4DontFragment,
			FragOffset: 0,
			TTL:        64,
			Protocol:   layers.IPProtocolUDP,
			Checksum:   0, // Will be calculated automatically
			SrcIP:      srcIP,
			DstIP:      dstIP,
		}
		ipLayer = ip4
	} else {
		// IPv6
		ip6 := &layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       0, // Will be calculated automatically
			NextHeader:   layers.IPProtocolUDP,
			HopLimit:     64,
			SrcIP:        srcIP,
			DstIP:        dstIP,
		}
		ipLayer = ip6
	}

	// UDP layer
	udp := &layers.UDP{
		SrcPort:  layers.UDPPort(srcPort),
		DstPort:  layers.UDPPort(dstPort),
		Length:   0, // Will be calculated automatically
		Checksum: 0, // Will be calculated automatically
	}

	// Set network layer for checksum calculation
	if srcIP.To4() != nil {
		udp.SetNetworkLayerForChecksum(ipLayer.(*layers.IPv4))
	} else {
		udp.SetNetworkLayerForChecksum(ipLayer.(*layers.IPv6))
	}

	// Serialize the packet
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	var layersToSerialize []gopacket.SerializableLayer
	layersToSerialize = append(layersToSerialize, ipLayer)
	layersToSerialize = append(layersToSerialize, udp)

	if len(data) > 0 {
		payload := gopacket.Payload(data)
		layersToSerialize = append(layersToSerialize, payload)
	}

	err := gopacket.SerializeLayers(pb.buffer, options, layersToSerialize...)
	if err != nil {
		return nil, err
	}

	return pb.buffer.Bytes(), nil
}

// BuildTCPSynAck builds a TCP SYN-ACK response packet
func (pb *PacketBuilder) BuildTCPSynAck(
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	seq, ack uint32,
) ([]byte, error) {
	return pb.BuildTCPResponse(srcIP, dstIP, srcPort, dstPort, seq, ack,
		TCPSyn|TCPAck, nil)
}

// BuildTCPAck builds a TCP ACK packet
func (pb *PacketBuilder) BuildTCPAck(
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	seq, ack uint32,
) ([]byte, error) {
	return pb.BuildTCPResponse(srcIP, dstIP, srcPort, dstPort, seq, ack,
		TCPAck, nil)
}

// BuildTCPRst builds a TCP RST packet
func (pb *PacketBuilder) BuildTCPRst(
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	seq uint32,
) ([]byte, error) {
	return pb.BuildTCPResponse(srcIP, dstIP, srcPort, dstPort, seq, 0,
		TCPRst, nil)
}

// BuildTCPFin builds a TCP FIN packet
func (pb *PacketBuilder) BuildTCPFin(
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	seq, ack uint32,
) ([]byte, error) {
	return pb.BuildTCPResponse(srcIP, dstIP, srcPort, dstPort, seq, ack,
		TCPFin|TCPAck, nil)
}

// TCPSeqTracker tracks TCP sequence numbers for a connection
type TCPSeqTracker struct {
	LocalSeq  uint32
	RemoteSeq uint32
	lastSeen  time.Time
}

// NewTCPSeqTracker creates a new TCP sequence tracker
func NewTCPSeqTracker(initialSeq uint32) *TCPSeqTracker {
	return &TCPSeqTracker{
		LocalSeq:  initialSeq,
		RemoteSeq: 0,
		lastSeen:  time.Now(),
	}
}

// UpdateSeq updates the sequence numbers based on a received packet from the client
func (t *TCPSeqTracker) UpdateSeq(packet *IPPacket) {
	if packet.IsTCP() {
		// The next sequence number we expect from the client
		nextRemoteSeq := packet.TCPSeq
		if len(packet.Data) > 0 {
			nextRemoteSeq += uint32(len(packet.Data))
		}
		// SYN and FIN flags also consume a sequence number
		if packet.TCPFlags&uint8(TCPSyn) != 0 || packet.TCPFlags&uint8(TCPFin) != 0 {
			nextRemoteSeq++
		}

		// Only update if the new sequence number is greater than the old one
		// This is a simplified check for sequence number wrapping
		if nextRemoteSeq > t.RemoteSeq {
			t.RemoteSeq = nextRemoteSeq
		}

		t.lastSeen = time.Now()
	}
}

// GetNextSeq returns the next expected sequence number
func (t *TCPSeqTracker) GetNextSeq() uint32 {
	return t.LocalSeq
}

// GetNextAck returns the next acknowledgment number
func (t *TCPSeqTracker) GetNextAck() uint32 {
	return t.RemoteSeq
}

// IsStale returns true if the tracker hasn't been updated recently
func (t *TCPSeqTracker) IsStale(timeout time.Duration) bool {
	return time.Since(t.lastSeen) > timeout
}
