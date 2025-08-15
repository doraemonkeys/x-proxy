package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"x-proxy/pkg/config"
	"x-proxy/pkg/logger"
	"x-proxy/pkg/obfuscator"
	"x-proxy/pkg/stats"

	"github.com/xtaci/kcp-go"
)

// Server is the proxy server.
type Server struct {
	Config       *config.ServerConfig
	Cipher       obfuscator.Cipher
	StatsManager *stats.StatsManager
}

// NewServer creates a new proxy server.
func NewServer(config *config.ServerConfig, cipher obfuscator.Cipher) *Server {
	if config.ReadWriteDeadline == 0 {
		config.ReadWriteDeadline = 120
	}

	// Enable stats by default if not explicitly configured
	if !config.EnableStats {
		config.EnableStats = true
	}

	return &Server{
		Config:       config,
		Cipher:       cipher,
		StatsManager: stats.NewStatsManager(config.EnableStats),
	}
}

// Run starts the proxy server.
func (s *Server) Run() {
	cert, err := tls.LoadX509KeyPair(s.Config.TLS.CertFile, s.Config.TLS.KeyFile)
	if err != nil {
		logger.Fatalf("Failed to load server certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	var listener net.Listener

	switch s.Config.Transport {
	case "kcp":
		listener, err = kcp.ListenWithOptions(s.Config.ListenAddr, nil, 0, 0)
	case "tcp":
		listener, err = tls.Listen("tcp", s.Config.ListenAddr, tlsConfig)
	default:
		logger.Fatalf("Unsupported transport type: %s", s.Config.Transport)
	}

	if err != nil {
		logger.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()
	logger.Infof("Server listening on %s", s.Config.ListenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Warnf("Failed to accept connection: %v", err)
			continue
		}

		go func() {
			var tlsConn net.Conn
			if s.Config.Transport == "kcp" {
				tlsConn = tls.Server(conn, tlsConfig)
			} else {
				tlsConn = conn
			}
			logger.Debugf("Accepted connection from %s", conn.RemoteAddr())
			s.handleConnection(tlsConn)
		}()
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	logger.Debugf("Handling connection for %s", conn.RemoteAddr())

	// For server side, we need to decrypt incoming data from client
	// XOR is symmetric, so we use the same Obfuscate method to decrypt
	deobfuscatedConn := s.Cipher.Obfuscate(conn)

	bconn := &bufferedConn{
		Conn:   deobfuscatedConn,
		reader: bufio.NewReader(deobfuscatedConn),
	}

	// Read the first header to determine the protocol
	targetAddrBytes, err := bconn.reader.ReadBytes(0)
	if err != nil {
		logger.Warnf("Failed to read target address from %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	targetAddrWithPrefix := string(bytes.TrimRight(targetAddrBytes, "\x00"))

	var proto, initialTargetAddr string

	if strings.HasPrefix(targetAddrWithPrefix, "udp:") {
		proto = "udp"
		initialTargetAddr = strings.TrimPrefix(targetAddrWithPrefix, "udp:")
	} else if strings.HasPrefix(targetAddrWithPrefix, "tcp:") {
		proto = "tcp"
		initialTargetAddr = strings.TrimPrefix(targetAddrWithPrefix, "tcp:")
	} else {
		//reject do nothing
		logger.Errorf("Invalid protocol prefix in target address from %s: %s", conn.RemoteAddr(), targetAddrWithPrefix)
		conn.Close()
		return
	}

	logger.Debugf("Initial request protocol %s for %s to %s", proto, conn.RemoteAddr(), initialTargetAddr)

	if proto == "tcp" {
		// Add connection statistics
		connID := stats.GenerateConnectionID(conn.RemoteAddr().String(), initialTargetAddr)
		s.StatsManager.AddConnection(connID, stats.ConnTypeTCP, conn.RemoteAddr().String(), initialTargetAddr, "server")
		defer s.StatsManager.RemoveConnection(connID)

		// Handle TCP tunnel
		d := &net.Dialer{
			KeepAliveConfig: net.KeepAliveConfig{
				Enable:   true,
				Idle:     time.Second * 2,
				Interval: time.Second * 2,
				Count:    5,
			},
		}
		targetConn, err := d.Dial("tcp", initialTargetAddr)
		if err != nil {
			logger.Warnf("Failed to connect to target %s for client %s: %v", initialTargetAddr, conn.RemoteAddr(), err)
			conn.Close()
			return
		}

		timeout := time.Duration(s.Config.ReadWriteDeadline) * time.Second
		relayWithTimeout(bconn, targetConn, timeout)
	} else if proto == "udp" {
		// Handle UDP datagram stream
		targetConns := make(map[string]net.Conn)
		var mu sync.Mutex
		defer func() {
			mu.Lock()
			for _, c := range targetConns {
				c.Close()
			}
			mu.Unlock()
		}()

		// Process the first packet that we've already read the header for
		if err := s.handleUDPPacket(bconn.reader, initialTargetAddr, conn.RemoteAddr().String(), bconn, targetConns, &mu); err != nil {
			logger.Warnf("Failed to handle initial UDP packet for %s: %v", conn.RemoteAddr(), err)
			return
		}

		// Loop to process subsequent packets in the same stream
		for {
			targetAddrBytes, err := bconn.reader.ReadBytes(0)
			if err != nil {
				if err != io.EOF {
					logger.Warnf("Failed to read subsequent UDP header for %s: %v", conn.RemoteAddr(), err)
				}
				return // End of stream or error
			}

			targetAddr := strings.TrimPrefix(string(bytes.TrimRight(targetAddrBytes, "\x00")), "udp:")

			if err := s.handleUDPPacket(bconn.reader, targetAddr, conn.RemoteAddr().String(), bconn, targetConns, &mu); err != nil {
				logger.Warnf("Failed to handle subsequent UDP packet for %s: %v", conn.RemoteAddr(), err)
				return
			}
		}
	}
}

func (s *Server) handleUDPPacket(reader *bufio.Reader, targetAddr, clientAddr string, deobfuscatedConn net.Conn, targetConns map[string]net.Conn, mu *sync.Mutex) error {
	timeout := time.Duration(s.Config.ReadWriteDeadline) * time.Second

	// Read the 2-byte length prefix with timeout
	lenBuf := make([]byte, 2)
	if err := deobfuscatedConn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := io.ReadFull(reader, lenBuf); err != nil {
		return err
	}
	payloadLen := binary.BigEndian.Uint16(lenBuf)

	// Read the UDP payload with timeout
	payload := make([]byte, payloadLen)
	if err := deobfuscatedConn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := io.ReadFull(reader, payload); err != nil {
		return err
	}

	mu.Lock()
	targetConn, found := targetConns[targetAddr]
	mu.Unlock()

	var err error
	if !found {
		targetConn, err = net.Dial("udp", targetAddr)
		if err != nil {
			logger.Errorf("failed to connect to UDP target %s: %v", targetAddr, err)
			return err
		}
		mu.Lock()
		targetConns[targetAddr] = targetConn
		mu.Unlock()

		// Add UDP connection statistics for new connection
		connID := stats.GenerateConnectionID(clientAddr, targetAddr)
		s.StatsManager.AddConnection(connID, stats.ConnTypeUDP, clientAddr, targetAddr, "server")

		// Store connection ID for cleanup (we'll use a simple approach by storing it in a map)
		// Note: In production, you might want a more sophisticated connection tracking system

		// Start a goroutine to handle responses from this new target
		go func() {
			logger.Debugf("Starting UDP response forwarder for %s -> %s", targetAddr, clientAddr)
			defer func() {
				logger.Debugf("Closing UDP response forwarder for %s", targetAddr)
				mu.Lock()
				delete(targetConns, targetAddr)
				mu.Unlock()
				targetConn.Close()
				s.StatsManager.RemoveConnection(connID)
			}()

			buf := make([]byte, 65535)
			for {
				err := targetConn.SetReadDeadline(time.Now().Add(time.Duration(s.Config.ReadWriteDeadline) * time.Second))
				if err != nil {
					logger.Warnf("Error setting read deadline for UDP target %s: %v", targetAddr, err)
					break
				}

				n, err := targetConn.Read(buf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						logger.Debugf("UDP response forwarder for %s timed out.", targetAddr)
						break
					}
					if err != io.EOF {
						logger.Warnf("Error in UDP response relay from %s: %v", targetAddr, err)
					}
					break
				}

				_, err = deobfuscatedConn.Write(buf[:n])
				if err != nil {
					logger.Warnf("Error writing UDP response to client stream for %s: %v", clientAddr, err)
					break
				}
			}
		}()
	}

	// Write the payload to the target
	_, err = targetConn.Write(payload)
	if err != nil {
		logger.Errorf("failed to write UDP payload to %s: %v", targetAddr, err)
		return err
	}

	logger.Debugf("Relayed %d UDP bytes for %s to %s", payloadLen, clientAddr, targetAddr)
	return nil
}
