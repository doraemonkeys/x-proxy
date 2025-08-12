//go:build !linux
package proxy

import (
	"fmt"
	"net"
	"x-proxy/pkg/logger"
)

func (c *Client) handleTransparent(localConn net.Conn) {
	logger.Warnf("Transparent proxy mode is only supported on Linux. Connection from %s will not be proxied.", localConn.RemoteAddr())
}

func (c *Client) handleTransparentUDP(localConn *net.UDPConn) {
	logger.Warnf("Transparent proxy mode for UDP is only supported on Linux.")
}

func getOriginalDst(conn net.Conn) (string, error) {
	return "", fmt.Errorf("getOriginalDst is only supported on Linux")
}

func listenTransparentUDP(network, address string) (*net.UDPConn, error) {
	return nil, fmt.Errorf("transparent UDP proxy is only supported on Linux")
}