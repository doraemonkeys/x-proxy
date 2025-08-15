package tun

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"x-proxy/pkg/logger"
)

// Handler handles TUN device traffic
type Handler struct {
	device        *TunDevice
	forwarder     Forwarder
	tcpConns      map[string]*TCPConnection
	udpConns      map[string]*UDPConnection
	connMutex     sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	packetBuilder *PacketBuilder
}

// Forwarder interface defines how to forward traffic
type Forwarder interface {
	ForwardTCP(target string) (net.Conn, error)
	ForwardUDP(target string) (net.PacketConn, error)
}

// TCPConnection represents a TCP connection state
type TCPConnection struct {
	LocalAddr   string
	RemoteAddr  string
	Conn        net.Conn
	LastSeen    time.Time
	Cancel      context.CancelFunc
	SeqTracker  *TCPSeqTracker
	LocalIP     net.IP
	RemoteIP    net.IP
	LocalPort   uint16
	RemotePort  uint16
	Established bool
}

// UDPConnection represents a UDP connection state
type UDPConnection struct {
	LocalAddr  string
	RemoteAddr string
	Conn       net.PacketConn
	LastSeen   time.Time
	Cancel     context.CancelFunc
	LocalIP    net.IP
	RemoteIP   net.IP
	LocalPort  uint16
	RemotePort uint16
}

// NewHandler creates a new TUN handler
func NewHandler(device *TunDevice, forwarder Forwarder) *Handler {
	ctx, cancel := context.WithCancel(context.Background())

	return &Handler{
		device:        device,
		forwarder:     forwarder,
		tcpConns:      make(map[string]*TCPConnection),
		udpConns:      make(map[string]*UDPConnection),
		ctx:           ctx,
		cancel:        cancel,
		packetBuilder: NewPacketBuilder(),
	}
}

// Start starts the TUN handler
func (h *Handler) Start() error {
	logger.Infof("Starting TUN handler for device %s", h.device.Name)

	// Start connection cleanup routine
	go h.cleanupConnections()

	// Start packet processing
	go h.processPackets()

	return nil
}

// Stop stops the TUN handler
func (h *Handler) Stop() {
	logger.Infof("Stopping TUN handler")
	h.cancel()

	// Close all connections
	h.connMutex.Lock()
	defer h.connMutex.Unlock()

	for _, conn := range h.tcpConns {
		conn.Cancel()
		conn.Conn.Close()
	}

	for _, conn := range h.udpConns {
		conn.Cancel()
		conn.Conn.Close()
	}
}

// processPackets processes packets from the TUN device
func (h *Handler) processPackets() {
	buf := make([]byte, 65535)

	for {
		select {
		case <-h.ctx.Done():
			return
		default:
			n, err := h.device.Read(buf)
			if err != nil {
				logger.Errorf("Failed to read from TUN device: %v", err)
				continue
			}

			packet, err := ParseIPPacket(buf[:n])
			if err != nil {
				logger.Debugf("Failed to parse IP packet: %v", err)
				continue
			}

			h.handlePacket(packet, buf[:n])
		}
	}
}

// handlePacket handles a single IP packet
func (h *Handler) handlePacket(packet *IPPacket, rawData []byte) {
	logger.Debugf("Handling packet: %s", packet.String())
	logger.Debugf("Raw packet data:\n%s", hex.Dump(rawData))

	if packet.IsTCP() {
		h.handleTCPPacket(packet, rawData)
	} else if packet.IsUDP() {
		h.handleUDPPacket(packet, rawData)
	} else {
		logger.Debugf("Ignoring non-TCP/UDP packet: protocol %d", packet.Protocol)
	}
}

// writeToDevice writes a packet to the TUN device with a timeout
func (h *Handler) writeToDevice(data []byte) {
	// Using a channel to avoid blocking indefinitely on write
	errCh := make(chan error, 1)
	go func() {
		_, err := h.device.Write(data)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err != nil {
			logger.Errorf("Failed to write to TUN device: %v", err)
		}
	case <-time.After(5 * time.Second):
		logger.Errorf("Timeout writing to TUN device")
	}
}

// handleTCPPacket handles TCP packets
func (h *Handler) handleTCPPacket(packet *IPPacket, rawData []byte) {
	connKey := fmt.Sprintf("%s:%d->%s:%d",
		packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort)

	h.connMutex.RLock()
	conn, exists := h.tcpConns[connKey]
	h.connMutex.RUnlock()

	if exists {
		conn.SeqTracker.UpdateSeq(packet)
	}

	// Check TCP flags
	isSYN := packet.TCPFlags&0x02 != 0
	isACK := packet.TCPFlags&0x10 != 0
	isFIN := packet.TCPFlags&0x01 != 0
	isRST := packet.TCPFlags&0x04 != 0
	isPSH := packet.TCPFlags&0x08 != 0

	if isSYN && !isACK && !exists {
		// New TCP connection (SYN packet)
		h.handleNewTCPConnection(packet, connKey)
	} else if isACK && exists && !conn.Established {
		// ACK for SYN-ACK, connection established
		conn.Established = true
		conn.LastSeen = time.Now()
		logger.Debugf("TCP connection established: %s", connKey)

		// Handle the case where the ACK packet also contains data
		if len(packet.Data) > 0 {
			_, err := conn.Conn.Write(packet.Data)
			if err != nil {
				logger.Errorf("Failed to forward initial data to remote: %v", err)
				h.closeTCPConnection(connKey)
				return
			}
			// Send ACK for received data
			ackPacket, _ := h.packetBuilder.BuildTCPAck(
				conn.LocalIP, conn.RemoteIP,
				conn.LocalPort, conn.RemotePort,
				conn.SeqTracker.GetNextSeq(),
				conn.SeqTracker.GetNextAck()+uint32(len(packet.Data)),
			)
			h.writeToDevice(ackPacket)
			logger.Debugf("Forwarded %d bytes from initial ACK to remote for TCP connection %s", len(packet.Data), connKey)
		}
	} else if (isFIN || isRST) && exists {
		// Connection termination
		if isFIN {
			// Send FIN-ACK response
			finAckPacket, _ := h.packetBuilder.BuildTCPResponse(
				conn.LocalIP, conn.RemoteIP,
				conn.LocalPort, conn.RemotePort,
				conn.SeqTracker.GetNextSeq(),
				conn.SeqTracker.GetNextAck()+1,
				TCPFin|TCPAck,
				nil,
			)
			h.writeToDevice(finAckPacket)
		}
		h.closeTCPConnection(connKey)
	} else if exists && conn.Established && (isPSH || len(packet.Data) > 0) {
		// Data packet - forward to remote connection
		if conn.Established && len(packet.Data) > 0 {
			conn.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			_, err := conn.Conn.Write(packet.Data)
			if err != nil {
				logger.Errorf("Failed to forward data to remote: %v", err)
				h.closeTCPConnection(connKey)
				return
			}
			conn.Conn.SetWriteDeadline(time.Time{})
			// Send ACK for received data
			ackPacket, _ := h.packetBuilder.BuildTCPAck(
				conn.LocalIP, conn.RemoteIP,
				conn.LocalPort, conn.RemotePort,
				conn.SeqTracker.GetNextSeq(),
				conn.SeqTracker.GetNextAck(),
			)
			h.writeToDevice(ackPacket)
			logger.Debugf("Forwarded %d bytes from TUN to remote for TCP connection %s", len(packet.Data), connKey)
		}
		conn.LastSeen = time.Now()
	} else if exists {
		// Keep-alive or other packet
		conn.LastSeen = time.Now()
	}
}

// handleNewTCPConnection handles new TCP connections
func (h *Handler) handleNewTCPConnection(packet *IPPacket, connKey string) {
	target := packet.GetTarget()
	logger.Debugf("New TCP connection: %s -> %s", connKey, target)

	// Forward the connection through the proxy first
	remoteConn, err := h.forwarder.ForwardTCP(target)
	if err != nil {
		logger.Errorf("Failed to forward TCP connection to %s: %v", target, err)
		// Send RST packet to indicate connection failure
		rstPacket, _ := h.packetBuilder.BuildTCPRst(
			packet.DstIP, packet.SrcIP,
			packet.DstPort, packet.SrcPort,
			packet.TCPSeq+1,
		)
		h.writeToDevice(rstPacket)
		return
	}

	// Now that the remote connection is established, send SYN-ACK
	initialSeq := rand.New(rand.NewSource(time.Now().UnixNano())).Uint32()
	synAckPacket, err := h.packetBuilder.BuildTCPSynAck(
		packet.DstIP, packet.SrcIP,
		packet.DstPort, packet.SrcPort,
		initialSeq,
		packet.TCPSeq+1,
	)
	if err != nil {
		logger.Errorf("Failed to build SYN-ACK packet: %v", err)
		remoteConn.Close() // Close the forwarded connection
		return
	}

	_, err = h.device.Write(synAckPacket)
	if err != nil {
		logger.Errorf("Failed to write SYN-ACK to TUN device: %v", err)
		remoteConn.Close() // Close the forwarded connection
		return
	}

	ctx, cancel := context.WithCancel(h.ctx)

	tcpConn := &TCPConnection{
		LocalAddr:   fmt.Sprintf("%s:%d", packet.SrcIP, packet.SrcPort),
		RemoteAddr:  target,
		Conn:        remoteConn,
		LastSeen:    time.Now(),
		Cancel:      cancel,
		SeqTracker:  NewTCPSeqTracker(initialSeq + 1),
		LocalIP:     packet.DstIP,
		RemoteIP:    packet.SrcIP,
		LocalPort:   packet.DstPort,
		RemotePort:  packet.SrcPort,
		Established: false,
	}

	h.connMutex.Lock()
	h.tcpConns[connKey] = tcpConn
	h.connMutex.Unlock()

	// Start handling the connection
	go h.handleTCPConnection(tcpConn, connKey, ctx)
}

// handleTCPConnection handles an established TCP connection
func (h *Handler) handleTCPConnection(conn *TCPConnection, connKey string, ctx context.Context) {
	defer func() {
		h.closeTCPConnection(connKey)
	}()

	logger.Debugf("Handling TCP connection: %s", connKey)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Read from remote connection
			buf := make([]byte, 1460) // MSS size
			conn.Conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := conn.Conn.Read(buf)
			if err != nil {
				logger.Debugf("TCP connection closed: %s, error: %v", connKey, err)
				// Send FIN packet to properly close the connection
				finPacket, _ := h.packetBuilder.BuildTCPFin(
					conn.LocalIP, conn.RemoteIP,
					conn.LocalPort, conn.RemotePort,
					conn.SeqTracker.GetNextSeq(),
					conn.SeqTracker.GetNextAck(),
				)
				h.writeToDevice(finPacket)
				return
			}

			// Create proper IP/TCP packet with the received data
			tcpFlags := TCPPsh | TCPAck

			responsePacket, err := h.packetBuilder.BuildTCPResponse(
				conn.LocalIP, conn.RemoteIP,
				conn.LocalPort, conn.RemotePort,
				conn.SeqTracker.GetNextSeq(),
				conn.SeqTracker.GetNextAck(),
				tcpFlags,
				buf[:n],
			)
			if err != nil {
				logger.Errorf("Failed to build TCP response packet: %v", err)
				continue
			}

			// Write to TUN device
			h.writeToDevice(responsePacket)

			logger.Debugf("Writing TCP packet to tun device: %s:%d -> %s:%d", conn.LocalIP, conn.LocalPort, conn.RemoteIP, conn.RemotePort)
			logger.Debugf("Raw packet data:\n%s", hex.Dump(responsePacket))

			// Update sequence numbers
			conn.SeqTracker.LocalSeq += uint32(n)
			conn.LastSeen = time.Now()

			logger.Debugf("Forwarded %d bytes from remote to TUN for TCP connection %s", n, connKey)
		}
	}
}

// handleUDPPacket handles UDP packets
func (h *Handler) handleUDPPacket(packet *IPPacket, rawData []byte) {
	connKey := fmt.Sprintf("%s:%d->%s:%d",
		packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort)

	h.connMutex.RLock()
	conn, exists := h.udpConns[connKey]
	h.connMutex.RUnlock()

	if !exists {
		// New UDP connection
		h.handleNewUDPConnection(packet, connKey)
	} else {
		// Existing connection - update last seen and forward data
		conn.LastSeen = time.Now()
		if len(packet.Data) > 0 {
			h.forwardUDPData(conn, packet.Data)
		}
	}
}

// handleNewUDPConnection handles new UDP connections
func (h *Handler) handleNewUDPConnection(packet *IPPacket, connKey string) {
	target := packet.GetTarget()
	logger.Debugf("New UDP connection: %s -> %s", connKey, target)

	// Forward the connection through the proxy
	remoteConn, err := h.forwarder.ForwardUDP(target)
	if err != nil {
		logger.Errorf("Failed to forward UDP connection to %s: %v", target, err)
		return
	}

	ctx, cancel := context.WithCancel(h.ctx)

	udpConn := &UDPConnection{
		LocalAddr:  fmt.Sprintf("%s:%d", packet.SrcIP, packet.SrcPort),
		RemoteAddr: target,
		Conn:       remoteConn,
		LastSeen:   time.Now(),
		Cancel:     cancel,
		LocalIP:    packet.DstIP,
		RemoteIP:   packet.SrcIP,
		LocalPort:  packet.DstPort,
		RemotePort: packet.SrcPort,
	}

	h.connMutex.Lock()
	h.udpConns[connKey] = udpConn
	h.connMutex.Unlock()

	// Start handling the connection
	go h.handleUDPConnection(udpConn, connKey, ctx)

	// Forward the initial packet
	h.forwardUDPData(udpConn, packet.Data)
}

// forwardUDPData forwards UDP data to the remote connection
func (h *Handler) forwardUDPData(conn *UDPConnection, data []byte) {
	// Forward UDP data through the proxy connection
	conn.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := conn.Conn.WriteTo(data, nil) // WriteTo with nil addr since it's already established
	if err != nil {
		logger.Errorf("Failed to forward UDP data for connection %s: %v", conn.RemoteAddr, err)
		return
	}
	conn.Conn.SetWriteDeadline(time.Time{})
	logger.Debugf("Forwarded %d bytes of UDP data for connection %s", len(data), conn.RemoteAddr)
}

// handleUDPConnection handles an established UDP connection
func (h *Handler) handleUDPConnection(conn *UDPConnection, connKey string, ctx context.Context) {
	defer func() {
		h.closeUDPConnection(connKey)
	}()

	logger.Debugf("Handling UDP connection: %s", connKey)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Read from remote connection
			buf := make([]byte, 1500) // Standard MTU size
			conn.Conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, _, err := conn.Conn.ReadFrom(buf)
			if err != nil {
				logger.Debugf("UDP connection closed: %s, error: %v", connKey, err)
				return
			}

			// Create proper IP/UDP packet with the received data
			udpPacket, err := h.packetBuilder.BuildUDPResponse(
				conn.LocalIP, conn.RemoteIP,
				conn.LocalPort, conn.RemotePort,
				buf[:n],
			)
			if err != nil {
				logger.Errorf("Failed to build UDP response packet: %v", err)
				continue
			}

			// Write to TUN device
			h.writeToDevice(udpPacket)

			conn.LastSeen = time.Now()
			logger.Debugf("Forwarded %d bytes from remote to TUN for UDP connection %s", n, connKey)
		}
	}
}

// closeTCPConnection closes a TCP connection
func (h *Handler) closeTCPConnection(connKey string) {
	h.connMutex.Lock()
	defer h.connMutex.Unlock()

	if conn, exists := h.tcpConns[connKey]; exists {
		logger.Debugf("Closing TCP connection: %s", connKey)
		conn.Cancel()
		conn.Conn.Close()
		delete(h.tcpConns, connKey)
	}
}

// closeUDPConnection closes a UDP connection
func (h *Handler) closeUDPConnection(connKey string) {
	h.connMutex.Lock()
	defer h.connMutex.Unlock()

	if conn, exists := h.udpConns[connKey]; exists {
		logger.Debugf("Closing UDP connection: %s", connKey)
		conn.Cancel()
		conn.Conn.Close()
		delete(h.udpConns, connKey)
	}
}

// cleanupConnections periodically cleans up stale connections
func (h *Handler) cleanupConnections() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			logger.Infof("Running cleanup of stale connections")
			h.cleanupStaleConnections()
		}
	}
}

// cleanupStaleConnections removes connections that haven't been used recently
func (h *Handler) cleanupStaleConnections() {
	now := time.Now()
	timeout := 5 * time.Minute

	h.connMutex.Lock()
	defer h.connMutex.Unlock()

	// Clean up TCP connections
	for key, conn := range h.tcpConns {
		if now.Sub(conn.LastSeen) > timeout {
			logger.Infof("Cleaning up stale TCP connection: %s", key)
			conn.Cancel()
			conn.Conn.Close()
			delete(h.tcpConns, key)
		}
	}

	// Clean up UDP connections
	for key, conn := range h.udpConns {
		if now.Sub(conn.LastSeen) > timeout {
			logger.Infof("Cleaning up stale UDP connection: %s", key)
			conn.Cancel()
			conn.Conn.Close()
			delete(h.udpConns, key)
		}
	}
}
