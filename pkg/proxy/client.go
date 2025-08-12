package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"x-proxy/pkg/config"
	"x-proxy/pkg/logger"
	"x-proxy/pkg/obfuscator"
	"x-proxy/pkg/stats"

	"github.com/xtaci/kcp-go"
)

// Client is the proxy client.
type Client struct {
	Config      *config.ClientConfig
	Cipher      obfuscator.Cipher
	TLSConfig   *tls.Config
	StatsManager *stats.StatsManager
}

// NewClient creates a new proxy client.
func NewClient(config *config.ClientConfig, cipher obfuscator.Cipher) *Client {

	if config.ReadWriteDeadline == 0 {
		config.ReadWriteDeadline = 120
	}
	
	// Enable stats by default if not explicitly configured
	if !config.EnableStats {
		config.EnableStats = true
	}

	cert, err := os.ReadFile(config.TLS.CAFile)
	if err != nil {
		logger.Fatalf("Failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()

	if !caCertPool.AppendCertsFromPEM(cert) {
		logger.Fatalf("Failed to append CA certificate to pool")
	}

	tlsConfig := &tls.Config{
		RootCAs:    caCertPool,
		ServerName: "localhost", // Should match the CN in the certificate
	}

	return &Client{
		Config:       config,
		Cipher:       cipher,
		TLSConfig:    tlsConfig,
		StatsManager: stats.NewStatsManager(config.EnableStats),
	}
}

// Run starts the proxy client.
func (c *Client) Run() {
	var wg sync.WaitGroup

	for _, modeConfig := range c.Config.Modes {
		wg.Add(1)
		go func(mc config.ClientModeConfig) {
			defer wg.Done()

			if mc.Type == "transparent" {
				// TCP listener for transparent mode
				go func() {
					listener, err := net.Listen("tcp", mc.ListenAddr)
					if err != nil {
						logger.Errorf("Failed to listen on %s for transparent TCP: %v", mc.ListenAddr, err)
						return
					}
					defer listener.Close()
					logger.Infof("Client listening on %s, mode: transparent TCP", mc.ListenAddr)
					for {
						conn, err := listener.Accept()
						if err != nil {
							logger.Warnf("Failed to accept TCP connection for transparent mode: %v", err)
							continue
						}
						go c.handleConnection(conn, mc.Type)
					}
				}()

				// UDP listener for transparent mode
				udpListener, err := listenTransparentUDP("udp", mc.ListenAddr)
				if err != nil {
					logger.Errorf("Failed to listen on %s for transparent UDP: %v", mc.ListenAddr, err)
					return
				}
				logger.Infof("Client listening on %s, mode: transparent UDP (TPROXY enabled)", mc.ListenAddr)
				c.handleTransparentUDP(udpListener)
			} else {
				// Default TCP listener for other modes
				listener, err := net.Listen("tcp", mc.ListenAddr)
				if err != nil {
					logger.Errorf("Failed to listen on %s for mode %s: %v", mc.ListenAddr, mc.Type, err)
					return
				}
				defer listener.Close()
				logger.Infof("Client listening on %s, mode: %s", mc.ListenAddr, mc.Type)

				for {
					conn, err := listener.Accept()
					if err != nil {
						logger.Warnf("Failed to accept connection for mode %s: %v", mc.Type, err)
						continue
					}
					go c.handleConnection(conn, mc.Type)
				}
			}
		}(modeConfig)
	}

	select {}
}

func (c *Client) dial() (net.Conn, error) {
	switch c.Config.Transport {
	case "kcp":
		remoteConn, err := kcp.DialWithOptions(c.Config.ServerAddr, nil, 0, 0)
		if err != nil {
			return nil, err
		}
		return tls.Client(remoteConn, c.TLSConfig), nil
	case "tcp":
		return tls.Dial("tcp", c.Config.ServerAddr, c.TLSConfig)
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", c.Config.Transport)
	}
}

// handleConnection now takes the modeType as an argument
func (c *Client) handleConnection(localConn net.Conn, modeType string) {
	defer localConn.Close()
	logger.Debugf("Handling connection for %s, mode: %s", localConn.RemoteAddr(), modeType)

	switch modeType {
	case "socks5":
		c.handleSocks5(localConn)
	case "http", "https": // Both http and https modes use the same handler
		c.handleHttp(localConn)
	case "transparent":
		c.handleTransparent(localConn)
	default:
		logger.Errorf("Unsupported mode type: %s for connection from %s", modeType, localConn.RemoteAddr())
	}
}

func (c *Client) handleHttp(localConn net.Conn) {
	logger.Debugf("Handling HTTP request for %s", localConn.RemoteAddr())

	reader := bufio.NewReader(localConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		if err != io.EOF {
			logger.Warnf("Failed to read http request from %s: %v", localConn.RemoteAddr(), err)
		}
		return
	}

	host := req.Host
	if !strings.Contains(host, ":") {
		if req.Method == "CONNECT" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	logger.Debugf("HTTP target for %s is %s", localConn.RemoteAddr(), host)

	// Add connection statistics
	connID := stats.GenerateConnectionID(localConn.RemoteAddr().String(), host)
	c.StatsManager.AddConnection(connID, stats.ConnTypeTCP, localConn.RemoteAddr().String(), host, "http")
	defer c.StatsManager.RemoveConnection(connID)

	remoteConn, err := c.dial()
	if err != nil {
		logger.Warnf("Failed to connect to remote server %s for client %s: %v", c.Config.ServerAddr, localConn.RemoteAddr(), err)
		return
	}

	// Wrap the remote connection with the obfuscator
	obfuscatedRemoteConn := c.Cipher.Obfuscate(remoteConn)
	defer obfuscatedRemoteConn.Close()

	prefixedHost := "tcp:" + host
	if req.Method == "CONNECT" {
		logger.Debugf("Handling CONNECT request for %s", host)
		// Send target address to remote server
		_, err := obfuscatedRemoteConn.Write([]byte(prefixedHost + "\x00"))
		if err != nil {
			logger.Warnf("Failed to send target address to remote server: %v", err)
			return
		}
		_, err = localConn.Write([]byte("HTTP/1.1 200 Connection established"))
		if err != nil {
			logger.Warnf("Failed to write 200 OK to client %s: %v", localConn.RemoteAddr(), err)
			return
		}
		logger.Debugf("Established HTTPS tunnel for %s to %s", localConn.RemoteAddr(), host)
	} else {
		logger.Debugf("Handling plain HTTP request for %s", host)
		var reqBuf bytes.Buffer
		if err := req.Write(&reqBuf); err != nil {
			logger.Errorf("Failed to write request to buffer: %v", err)
			return
		}

		payload := append([]byte(prefixedHost+"\x00"), reqBuf.Bytes()...)

		_, err := obfuscatedRemoteConn.Write(payload)
		if err != nil {
			logger.Warnf("Failed to write obfuscated request to remote: %v", err)
			return
		}
		logger.Debugf("Forwarded HTTP request for %s to %s", localConn.RemoteAddr(), host)
	}

	// Relay data with timeout
	var wg sync.WaitGroup
	wg.Add(2)

	timeout := time.Duration(c.Config.ReadWriteDeadline) * time.Second

	go func() {
		defer wg.Done()
		defer obfuscatedRemoteConn.Close()
		for {
			err := localConn.SetReadDeadline(time.Now().Add(timeout))
			if err != nil {
				logger.Warnf("Failed to set read deadline on local connection for %s: %v", localConn.RemoteAddr(), err)
				break
			}
			
			buf := make([]byte, 32*1024)
			n, err := localConn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					logger.Debugf("Read timeout (local -> remote) for %s", localConn.RemoteAddr())
				} else if err != io.EOF {
					logger.Warnf("Relay error (local -> remote) for %s: %v", localConn.RemoteAddr(), err)
				}
				break
			}
			
			err = obfuscatedRemoteConn.SetWriteDeadline(time.Now().Add(timeout))
			if err != nil {
				logger.Warnf("Failed to set write deadline on remote connection for %s: %v", localConn.RemoteAddr(), err)
				break
			}
			
			_, err = obfuscatedRemoteConn.Write(buf[:n])
			if err != nil {
				logger.Warnf("Relay error (local -> remote write) for %s: %v", localConn.RemoteAddr(), err)
				break
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer localConn.Close()
		for {
			err := obfuscatedRemoteConn.SetReadDeadline(time.Now().Add(timeout))
			if err != nil {
				logger.Warnf("Failed to set read deadline on remote connection for %s: %v", localConn.RemoteAddr(), err)
				break
			}
			
			buf := make([]byte, 32*1024)
			n, err := obfuscatedRemoteConn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					logger.Debugf("Read timeout (remote -> local) for %s", localConn.RemoteAddr())
				} else if err != io.EOF {
					logger.Warnf("Relay error (remote -> local) for %s: %v", localConn.RemoteAddr(), err)
				}
				break
			}
			
			err = localConn.SetWriteDeadline(time.Now().Add(timeout))
			if err != nil {
				logger.Warnf("Failed to set write deadline on local connection for %s: %v", localConn.RemoteAddr(), err)
				break
			}
			
			_, err = localConn.Write(buf[:n])
			if err != nil {
				logger.Warnf("Relay error (remote -> local write) for %s: %v", localConn.RemoteAddr(), err)
				break
			}
		}
	}()

	wg.Wait()
}

func (c *Client) handleSocks5(localConn net.Conn) {
	logger.Debugf("Handling SOCKS5 request for %s", localConn.RemoteAddr())

	buf := make([]byte, 257)
	n, err := localConn.Read(buf)
	if err != nil || n < 2 {
		logger.Warnf("Failed to read SOCKS5 handshake from %s: %v", localConn.RemoteAddr(), err)
		return
	}
	logger.Debugf("SOCKS5 handshake from %s successful", localConn.RemoteAddr())

	localConn.Write([]byte{0x05, 0x00})

	n, err = localConn.Read(buf)
	if err != nil || n < 4 {
		logger.Warnf("Failed to read SOCKS5 request from %s: %v", localConn.RemoteAddr(), err)
		return
	}

	if buf[1] != 0x01 { // We only support CONNECT command
		logger.Warnf("Unsupported SOCKS5 command %d from %s", buf[1], localConn.RemoteAddr())
		localConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // Command not supported
		return
	}

	var targetAddr string
	switch buf[3] { // ATYP
	case 0x01: // IPv4
		targetAddr = net.IP(buf[4 : 4+net.IPv4len]).String()
	case 0x03: // Domain name
		domainLen := int(buf[4])
		targetAddr = string(buf[5 : 5+domainLen])
	case 0x04: // IPv6
		targetAddr = net.IP(buf[4 : 4+net.IPv6len]).String()
	default:
		logger.Warnf("Unsupported SOCKS5 address type %d from %s", buf[3], localConn.RemoteAddr())
		localConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // Address type not supported
		return
	}

	port := binary.BigEndian.Uint16(buf[n-2 : n])
	target := net.JoinHostPort(targetAddr, strconv.Itoa(int(port)))
	logger.Debugf("SOCKS5 target for %s is %s", localConn.RemoteAddr(), target)

	remoteConn, err := c.dial()
	if err != nil {
		logger.Warnf("Failed to connect to remote server %s for client %s: %v", c.Config.ServerAddr, localConn.RemoteAddr(), err)
		localConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // General SOCKS server failure
		return
	}

	// Wrap the remote connection with the obfuscator
	obfuscatedRemoteConn := c.Cipher.Obfuscate(remoteConn)
	defer obfuscatedRemoteConn.Close()

	prefixedTarget := "tcp:" + target
	_, err = obfuscatedRemoteConn.Write([]byte(prefixedTarget + "\x00"))
	if err != nil {
		logger.Warnf("Failed to send target address to remote server: %v", err)
		return
	}

	localConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	logger.Debugf("Established SOCKS5 tunnel for %s to %s", localConn.RemoteAddr(), target)

	// Add connection statistics
	connID := stats.GenerateConnectionID(localConn.RemoteAddr().String(), target)
	c.StatsManager.AddConnection(connID, stats.ConnTypeTCP, localConn.RemoteAddr().String(), target, "socks5")
	defer c.StatsManager.RemoveConnection(connID)

	// Relay data with timeout
	var wg sync.WaitGroup
	wg.Add(2)

	timeout := time.Duration(c.Config.ReadWriteDeadline) * time.Second

	go func() {
		defer wg.Done()
		defer obfuscatedRemoteConn.Close()
		for {
			err := localConn.SetReadDeadline(time.Now().Add(timeout))
			if err != nil {
				logger.Warnf("Failed to set read deadline on local connection for %s: %v", localConn.RemoteAddr(), err)
				break
			}
			
			buf := make([]byte, 32*1024)
			n, err := localConn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					logger.Debugf("Read timeout (local -> remote) for %s", localConn.RemoteAddr())
				} else if err != io.EOF {
					logger.Warnf("Relay error (local -> remote) for %s: %v", localConn.RemoteAddr(), err)
				}
				break
			}
			
			err = obfuscatedRemoteConn.SetWriteDeadline(time.Now().Add(timeout))
			if err != nil {
				logger.Warnf("Failed to set write deadline on remote connection for %s: %v", localConn.RemoteAddr(), err)
				break
			}
			
			_, err = obfuscatedRemoteConn.Write(buf[:n])
			if err != nil {
				logger.Warnf("Relay error (local -> remote write) for %s: %v", localConn.RemoteAddr(), err)
				break
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer localConn.Close()
		for {
			err := obfuscatedRemoteConn.SetReadDeadline(time.Now().Add(timeout))
			if err != nil {
				logger.Warnf("Failed to set read deadline on remote connection for %s: %v", localConn.RemoteAddr(), err)
				break
			}
			
			buf := make([]byte, 32*1024)
			n, err := obfuscatedRemoteConn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					logger.Debugf("Read timeout (remote -> local) for %s", localConn.RemoteAddr())
				} else if err != io.EOF {
					logger.Warnf("Relay error (remote -> local) for %s: %v", localConn.RemoteAddr(), err)
				}
				break
			}
			
			err = localConn.SetWriteDeadline(time.Now().Add(timeout))
			if err != nil {
				logger.Warnf("Failed to set write deadline on local connection for %s: %v", localConn.RemoteAddr(), err)
				break
			}
			
			_, err = localConn.Write(buf[:n])
			if err != nil {
				logger.Warnf("Relay error (remote -> local write) for %s: %v", localConn.RemoteAddr(), err)
				break
			}
		}
	}()

	wg.Wait()
}
