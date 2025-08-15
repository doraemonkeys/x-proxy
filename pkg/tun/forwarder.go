package tun

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"x-proxy/pkg/config"
	"x-proxy/pkg/logger"
	"x-proxy/pkg/obfuscator"

	"github.com/xtaci/kcp-go"
)

// ProxyForwarder implements the Forwarder interface using proxy client components
type ProxyForwarder struct {
	config    *config.ClientConfig
	cipher    obfuscator.Cipher
	tlsConfig *tls.Config
}

// NewProxyForwarder creates a new ProxyForwarder
func NewProxyForwarder(config *config.ClientConfig, cipher obfuscator.Cipher, tlsConfig *tls.Config) *ProxyForwarder {
	return &ProxyForwarder{
		config:    config,
		cipher:    cipher,
		tlsConfig: tlsConfig,
	}
}

// dial establishes a connection to the proxy server
func (f *ProxyForwarder) dial() (net.Conn, error) {
	logger.Debugf("Dialing to proxy server %s via %s", f.config.ServerAddr, f.config.Transport)
	switch f.config.Transport {
	case "kcp":
		remoteConn, err := kcp.DialWithOptions(f.config.ServerAddr, nil, 0, 0)
		if err != nil {
			logger.Errorf("Failed to dial kcp connection to %s: %v", f.config.ServerAddr, err)
			return nil, err
		}
		logger.Debugf("Successfully dialed to %s via kcp", f.config.ServerAddr)
		return tls.Client(remoteConn, f.tlsConfig), nil
	case "tcp":
		conn, err := tls.Dial("tcp", f.config.ServerAddr, f.tlsConfig)
		if err != nil {
			logger.Errorf("Failed to dial tcp connection to %s: %v", f.config.ServerAddr, err)
			return nil, err
		}
		logger.Debugf("Successfully dialed to %s via tcp", f.config.ServerAddr)
		return conn, nil
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", f.config.Transport)
	}
}

// ForwardTCP forwards TCP traffic through the proxy
func (f *ProxyForwarder) ForwardTCP(target string) (net.Conn, error) {
	logger.Debugf("Forwarding TCP traffic to %s through proxy", target)

	// Connect to the proxy server
	remoteConn, err := f.dial()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy server: %v", err)
	}

	// Wrap the remote connection with the obfuscator
	obfuscatedConn := f.cipher.Obfuscate(remoteConn)

	// Send the target address to the proxy server
	prefixedTarget := "tcp:" + target
	logger.Debugf("Sending target address %s to proxy", prefixedTarget)
	if err := obfuscatedConn.SetWriteDeadline(time.Now().Add(time.Duration(f.config.ReadWriteDeadline) * time.Second)); err != nil {
		obfuscatedConn.Close()
		logger.Errorf("Failed to set write deadline on remote connection: %v", err)
		return nil, fmt.Errorf("failed to set write deadline on remote connection: %v", err)
	}
	_, err = obfuscatedConn.Write([]byte(prefixedTarget + "\x00"))
	if err != nil {
		obfuscatedConn.Close()
		logger.Errorf("Failed to send target address to proxy server: %v", err)
		return nil, fmt.Errorf("failed to send target address to proxy server: %v", err)
	}
	if err := obfuscatedConn.SetWriteDeadline(time.Time{}); err != nil {
		obfuscatedConn.Close()
		logger.Errorf("Failed to reset write deadline on remote connection: %v", err)
		return nil, fmt.Errorf("failed to reset write deadline on remote connection: %v", err)
	}

	logger.Debugf("Successfully established TCP forward to %s", target)
	return obfuscatedConn, nil
}

// ForwardUDP forwards UDP traffic through the proxy
func (f *ProxyForwarder) ForwardUDP(target string) (net.PacketConn, error) {
	logger.Debugf("Forwarding UDP traffic to %s through proxy", target)

	// For UDP, we need to establish a connection and handle it differently
	// This is a simplified implementation - in practice you might want to use
	// a UDP relay or handle it through the existing transparent proxy mechanism

	remoteConn, err := f.dial()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy server for UDP: %v", err)
	}

	// Wrap the remote connection with the obfuscator
	obfuscatedConn := f.cipher.Obfuscate(remoteConn)

	// Send the target address to the proxy server
	prefixedTarget := "udp:" + target
	logger.Debugf("Sending target address %s to proxy", prefixedTarget)
	if err := obfuscatedConn.SetWriteDeadline(time.Now().Add(time.Duration(f.config.ReadWriteDeadline) * time.Second)); err != nil {
		obfuscatedConn.Close()
		logger.Errorf("Failed to set write deadline on remote connection: %v", err)
		return nil, fmt.Errorf("failed to set write deadline on remote connection: %v", err)
	}
	_, err = obfuscatedConn.Write([]byte(prefixedTarget + "\x00"))
	if err != nil {
		obfuscatedConn.Close()
		logger.Errorf("Failed to send UDP target address to proxy server: %v", err)
		return nil, fmt.Errorf("failed to send UDP target address to proxy server: %v", err)
	}
	if err := obfuscatedConn.SetWriteDeadline(time.Time{}); err != nil {
		obfuscatedConn.Close()
		logger.Errorf("Failed to reset write deadline on remote connection: %v", err)
		return nil, fmt.Errorf("failed to reset write deadline on remote connection: %v", err)
	}

	logger.Debugf("Successfully established UDP forward to %s", target)
	// Wrap the connection to implement PacketConn interface
	return &UDPConnWrapper{conn: obfuscatedConn}, nil
}

// UDPConnWrapper wraps a net.Conn to implement net.PacketConn for UDP forwarding
type UDPConnWrapper struct {
	conn net.Conn
}

func (u *UDPConnWrapper) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = u.conn.Read(p)
	if err != nil {
		return 0, nil, err
	}
	// For TUN interface, we don't have a specific source address from the remote
	// This is a limitation of tunneling UDP over TCP
	return n, &net.UDPAddr{IP: net.IPv4zero, Port: 0}, nil
}

func (u *UDPConnWrapper) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// For TUN interface, we ignore the destination address as it's already
	// established when creating the connection

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(p)))

	// Construct payload: length + data
	payload := append(lenBuf, p...)

	return u.conn.Write(payload)
}

func (u *UDPConnWrapper) Close() error {
	return u.conn.Close()
}

func (u *UDPConnWrapper) LocalAddr() net.Addr {
	return u.conn.LocalAddr()
}

func (u *UDPConnWrapper) SetDeadline(t time.Time) error {
	return u.conn.SetDeadline(t)
}

func (u *UDPConnWrapper) SetReadDeadline(t time.Time) error {
	return u.conn.SetReadDeadline(t)
}

func (u *UDPConnWrapper) SetWriteDeadline(t time.Time) error {
	return u.conn.SetWriteDeadline(t)
}
