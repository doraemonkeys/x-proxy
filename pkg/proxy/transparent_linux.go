//go:build linux

package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
	"x-proxy/pkg/logger"
	"x-proxy/pkg/stats"

	"golang.org/x/sys/unix"
)

// listenTransparentUDP creates a UDP listener that can accept TPROXY packets.
func listenTransparentUDP(network, address string) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}

	var family int
	var sa unix.Sockaddr
	if addr.IP.To4() != nil {
		family = unix.AF_INET
		var sa4 unix.SockaddrInet4
		sa4.Port = addr.Port
		copy(sa4.Addr[:], addr.IP.To4())
		sa = &sa4
	} else {
		family = unix.AF_INET6
		var sa6 unix.SockaddrInet6
		sa6.Port = addr.Port
		copy(sa6.Addr[:], addr.IP.To16())
		sa = &sa6
	}

	fd, err := unix.Socket(family, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %w", err)
	}

	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set IP_TRANSPARENT: %w", err)
	}
	// Try to set IPV6_TRANSPARENT, but don't fail if it's not supported
	if family == unix.AF_INET6 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("failed to set IPV6_TRANSPARENT: %w", err)
		}
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set SO_REUSEADDR: %w", err)
	}

	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to bind socket: %w", err)
	}

	file := os.NewFile(uintptr(fd), fmt.Sprintf("udp-tproxy-listener-%s", address))
	conn, err := net.FilePacketConn(file)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to convert file to packet conn: %w", err)
	}
	// The file must be closed, as FilePacketConn duplicates the file descriptor.
	file.Close()

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("failed to cast to *net.UDPConn")
	}

	return udpConn, nil
}

const (
	SO_ORIGINAL_DST      = 80
	IP6T_SO_ORIGINAL_DST = 80
)

// ntohs converts a 16-bit integer from network to host byte order.
func ntohs(n uint16) uint16 {
	return (n >> 8) | (n << 8)
}

func getOriginalDst(conn net.Conn) (string, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a TCP connection")
	}

	file, err := tcpConn.File()
	if err != nil {
		return "", err
	}
	defer file.Close()
	fd := file.Fd()

	// Try IPv4
	var addr4 syscall.RawSockaddrInet4
	size4 := uint32(unsafe.Sizeof(addr4))
	// Raw syscall to getsockopt
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_IP, SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&addr4)), uintptr(unsafe.Pointer(&size4)), 0)
	if errno == 0 {
		if addr4.Family == syscall.AF_INET {
			ip := net.IP(addr4.Addr[:]).String()
			// Use ntohs for port conversion, assuming Port is uint16
			port := ntohs(addr4.Port)
			return net.JoinHostPort(ip, strconv.Itoa(int(port))), nil
		}
	}

	// Try IPv6
	var addr6 syscall.RawSockaddrInet6
	size6 := uint32(unsafe.Sizeof(addr6))
	// Raw syscall to getsockopt
	_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&addr6)), uintptr(unsafe.Pointer(&size6)), 0)
	if errno == 0 {
		if addr6.Family == syscall.AF_INET6 {
			ip := net.IP(addr6.Addr[:]).String()
			// Use ntohs for port conversion, assuming Port is uint16
			port := ntohs(addr6.Port)
			return net.JoinHostPort(ip, strconv.Itoa(int(port))), nil
		}
	}

	return "", fmt.Errorf("failed to get original destination, errno: %v", errno)
}

func (c *Client) handleTransparent(localConn net.Conn) {
	logger.Debugf("Handling transparent request for %s", localConn.RemoteAddr())
	target, err := getOriginalDst(localConn)
	if err != nil {
		logger.Warnf("Failed to get original destination for %s: %v", localConn.RemoteAddr(), err)
		return
	}

	logger.Debugf("Transparently proxying for %s to %s", localConn.RemoteAddr(), target)

	// Add connection statistics
	connID := stats.GenerateConnectionID(localConn.RemoteAddr().String(), target)
	c.StatsManager.AddConnection(connID, stats.ConnTypeTCP, localConn.RemoteAddr().String(), target, "transparent")
	defer c.StatsManager.RemoveConnection(connID)

	remoteConn, err := c.dial()
	if err != nil {
		logger.Warnf("Failed to connect to remote server %s for client %s: %v", c.Config.ServerAddr, localConn.RemoteAddr(), err)
		return
	}
	defer remoteConn.Close()
	logger.Debugf("Connected to remote server %s for client %s", c.Config.ServerAddr, localConn.RemoteAddr())

	// Wrap the remote connection with the obfuscator
	obfuscatedRemoteConn := c.Cipher.Obfuscate(remoteConn)
	defer obfuscatedRemoteConn.Close()

	_, err = obfuscatedRemoteConn.Write([]byte("tcp:" + target + string(byte(0))))
	if err != nil {
		logger.Warnf("Failed to send target address to remote server: %v", err)
		return
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

func getOriginalDstFromOOB(oob []byte) (net.IP, int, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, 0, fmt.Errorf("parsing socket control message: %w", err)
	}

	for _, msg := range msgs {
		if msg.Header.Level == syscall.IPPROTO_IP && msg.Header.Type == syscall.IP_ORIGDSTADDR {
			ip := net.IP(msg.Data[4:8])
			port := int(binary.BigEndian.Uint16(msg.Data[2:4]))
			return ip, port, nil
		}
		if msg.Header.Level == syscall.IPPROTO_IPV6 && msg.Header.Type == unix.IPV6_ORIGDSTADDR {
			ip := net.IP(msg.Data[8:24])
			port := int(binary.BigEndian.Uint16(msg.Data[2:4]))
			return ip, port, nil
		}
	}

	return nil, 0, fmt.Errorf("cannot find original destination")
}

func (c *Client) handleTransparentUDP(localConn *net.UDPConn) {
	logger.Debugf("UDP: Handling transparent UDP request from %s", localConn.LocalAddr())
	defer localConn.Close()

	file, err := localConn.File()
	if err != nil {
		logger.Warnf("UDP: Failed to get file from conn: %v", err)
		return
	}
	defer file.Close()
	fd := int(file.Fd())

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_RECVORIGDSTADDR, 1); err != nil {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, unix.IPV6_RECVORIGDSTADDR, 1); err != nil {
			logger.Warnf("UDP: Failed to set IP_RECVORIGDSTADDR or IPV6_RECVORIGDSTADDR: %v", err)
			return
		}
	}
	logger.Debugf("UDP: Set socket options to receive original destination address")

	sessions := make(map[string]net.Conn)
	var mu sync.Mutex

	buf := make([]byte, 4096)
	oob := make([]byte, 4096)

	logger.Debugf("UDP: Listening for transparent proxy connections on %s", localConn.LocalAddr())

	for {
		n, oobn, _, raddr, err := localConn.ReadMsgUDP(buf, oob)
		if err != nil {
			logger.Warnf("UDP: Failed to read from conn: %v", err)
			continue
		}
		// Log the first 10 bytes of the received packet
		logBytes := n
		if logBytes > 10 {
			logBytes = 10
		}
		logger.Debugf("UDP: Received %d bytes from %s, first %d bytes: %x", n, raddr, logBytes, buf[:logBytes])

		originalDstIP, originalDstPort, err := getOriginalDstFromOOB(oob[:oobn])
		if err != nil {
			logger.Warnf("UDP: Failed to get original destination for %s: %v", raddr, err)
			continue
		}
		originalDst := net.JoinHostPort(originalDstIP.String(), strconv.Itoa(originalDstPort))
		logger.Debugf("UDP: Successfully retrieved original destination for %s: %s", raddr, originalDst)

		mu.Lock()
		remoteConn, ok := sessions[raddr.String()]
		mu.Unlock()

		if !ok {
			logger.Debugf("UDP: No session found for %s. Creating new session to %s", raddr, originalDst)
			newRemoteConn, err := c.dial()
			if err != nil {
				logger.Warnf("UDP: Failed to connect to remote server for %s: %v", raddr, err)
				continue
			}
			logger.Debugf("UDP: Successfully dialed remote server for %s", raddr)

			// Correctly create the obfuscated connection first
			obfuscatedRemoteConn := c.Cipher.Obfuscate(newRemoteConn)
			logger.Debugf("UDP: Created new obfuscated remote connection for %s", raddr)

			// Add UDP connection statistics
			connID := stats.GenerateConnectionID(raddr.String(), originalDst)
			c.StatsManager.AddConnection(connID, stats.ConnTypeUDP, raddr.String(), originalDst, "transparent")

			mu.Lock()
			sessions[raddr.String()] = obfuscatedRemoteConn
			mu.Unlock()

			go func(laddr *net.UDPAddr, rconn net.Conn, origIP net.IP, origPort int, connID string) {
				defer func() {
					mu.Lock()
					delete(sessions, laddr.String())
					mu.Unlock()
					rconn.Close()
					c.StatsManager.RemoveConnection(connID)
					logger.Debugf("UDP: Closed remote connection for %s", laddr)
				}()

				logger.Debugf("UDP: Starting goroutine to handle server -> client traffic for %s", laddr)
				buf := make([]byte, 4096)
				for {
					rconn.SetReadDeadline(time.Now().Add(time.Duration(c.Config.ReadWriteDeadline) * time.Second))
					n, err := rconn.Read(buf)
					if err != nil {
						if err != io.EOF {
							logger.Warnf("UDP: Error reading from remote for %s: %v", laddr, err)
						} else {
							logger.Debugf("UDP: Remote connection closed by peer for %s", laddr)
						}
						return
					}
					logger.Debugf("UDP: Read %d bytes from remote for %s, forwarding to local", n, laddr)

					// Create a new socket to send the reply with the correct source IP and port
					var sendFamily int
					if origIP.To4() != nil {
						sendFamily = unix.AF_INET
					} else {
						sendFamily = unix.AF_INET6
					}

					sendFd, err := unix.Socket(sendFamily, unix.SOCK_DGRAM, 0)
					if err != nil {
						logger.Warnf("UDP: Failed to create reply socket for %s: %v", laddr, err)
						return // Exit goroutine
					}

					if err := unix.SetsockoptInt(sendFd, unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1); err != nil {
						unix.Close(sendFd)
						logger.Warnf("UDP: Failed to set IP_TRANSPARENT on reply socket for %s: %v", laddr, err)
						return
					}

					var bindAddr unix.Sockaddr
					if origIP.To4() != nil {
						sa4 := &unix.SockaddrInet4{Port: origPort}
						copy(sa4.Addr[:], origIP.To4())
						bindAddr = sa4
					} else {
						sa6 := &unix.SockaddrInet6{Port: origPort}
						copy(sa6.Addr[:], origIP.To16())
						bindAddr = sa6
					}

					if err := unix.Bind(sendFd, bindAddr); err != nil {
						unix.Close(sendFd)
						logger.Warnf("UDP: Failed to bind reply socket to %s:%d for %s: %v", origIP, origPort, laddr, err)
						return
					}

					// Convert destination addr to sockaddr for sendto
					var destAddr unix.Sockaddr
					if laddr.IP.To4() != nil {
						sa4 := &unix.SockaddrInet4{Port: laddr.Port}
						copy(sa4.Addr[:], laddr.IP.To4())
						destAddr = sa4
					} else {
						sa6 := &unix.SockaddrInet6{Port: laddr.Port}
						copy(sa6.Addr[:], laddr.IP.To16())
						destAddr = sa6
					}

					if err := unix.Sendto(sendFd, buf[:n], 0, destAddr); err != nil {
						unix.Close(sendFd)
						logger.Warnf("UDP: Failed to sendto on reply socket for %s: %v", laddr, err)
						return
					}

					unix.Close(sendFd) // Close after sending
					logger.Debugf("UDP: Wrote %d bytes to local for %s (from %s:%d)", n, laddr, origIP, origPort)
				}
			}(raddr, obfuscatedRemoteConn, originalDstIP, originalDstPort, connID)

			// Update remoteConn to the correct obfuscated connection for the current write
			remoteConn = obfuscatedRemoteConn
		}

		header := []byte("udp:" + originalDst + string(byte(0)))
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(n))

		// Construct payload: header + length + data
		payload := append(header, lenBuf...)
		payload = append(payload, buf[:n]...)

		logger.Debugf("UDP: Forwarding %d bytes for %s to remote server (original destination: %s)", n, raddr, originalDst)
		wn, err := remoteConn.Write(payload)
		if err != nil {
			logger.Warnf("UDP: Failed to write to remote for %s: %v", raddr, err)
		} else {
			logger.Debugf("UDP: Successfully wrote %d bytes to remote for %s", wn, raddr)
		}
	}
}
