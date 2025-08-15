package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"x-proxy/pkg/logger"
)

const (
	// DefaultBufferSize is the default buffer size for copying data
	DefaultBufferSize = 32 * 1024
)

// Direction constants for type safety
type Direction string

const (
	DirectionLocalToRemote Direction = "local -> remote"
	DirectionRemoteToLocal Direction = "remote -> local"
)

// bufferPool reuses buffers to reduce GC pressure
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, DefaultBufferSize)
	},
}

// isConnectionClosed checks if the error indicates that the connection is already closed
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	// Check for common "connection closed" error patterns
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe") ||
		errors.Is(err, net.ErrClosed)
}

// isTimeout checks if the error is a timeout error
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	// Check for timeout using the net.Error interface
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	// Also check for wrapped timeout errors
	errStr := err.Error()
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "deadline exceeded")
}

// bufferedConn is a net.Conn that uses a bufio.Reader for its Read method.
// This is useful when you need to read some data from a connection and then
// pass the connection to a function that expects a net.Conn.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// copyWithTimeout copies data from src to dst, setting a deadline for each read and write operation.
// It's designed to be run in a goroutine.
func copyWithTimeout(
	ctx context.Context,
	dst, src net.Conn,
	timeout time.Duration,
	wg *sync.WaitGroup,
	direction Direction,
	clientAddr net.Addr,
	cancel context.CancelFunc,
) {
	defer wg.Done()
	defer func() {
		// Cancel context when this goroutine exits to signal the other goroutine to stop
		cancel()
		logger.Debugf("Cancelled context for %s direction %s", direction, clientAddr)
	}()

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	// Set initial deadlines once to reduce overhead
	if timeout > 0 {
		logger.Debugf(
			"Setting initial timeout: %s read/write deadlines for %s direction %s",
			timeout,
			direction,
			clientAddr,
		)
		deadline := time.Now().Add(timeout)
		if err := src.SetReadDeadline(deadline); err != nil {
			logger.Warnf("Failed to set initial read deadline on %s for %s: %v", direction, clientAddr, err)
			return
		}
		if err := dst.SetWriteDeadline(deadline); err != nil {
			logger.Warnf("Failed to set initial write deadline on %s for %s: %v", direction, clientAddr, err)
			return
		}
	}

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer func() {
			recover()
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if CheckTCPConnection(dst) {
					cancel()
					break
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			logger.Debugf("Context cancelled for %s direction %s", direction, clientAddr)
			return
		default:
		}

		n, err := src.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				logger.Debugf("Connection closed (%s read) for %s", direction, clientAddr)
			} else if isTimeout(err) {
				logger.Debugf("Read timeout (%s) for %s", direction, clientAddr)
			} else {
				logger.Warnf("Relay error (%s read) for %s: %v", direction, clientAddr, err)
			}
			return
		}

		_, err = dst.Write(buf[:n])
		if err != nil {
			logger.Warnf("Relay error (%s write) for %s: %v", direction, clientAddr, err)
			return
		}
	}
}

// CheckTCPConnection 使用文件描述符监测连接状态
func CheckTCPConnection(conn net.Conn) bool {
	if conn == nil {
		return true
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return true
	}

	file, err := tcpConn.File()
	if err != nil {
		return true
	}
	defer file.Close()

	fd := int(file.Fd())

	switch os := runtime.GOOS; os {
	case "linux", "darwin", "freebsd", "openbsd", "netbsd":
		return checkUnixConnection(fd)
	case "windows":
		return checkWindowsConnection(fd)
	default:
		return true
	}
}

func checkUnixConnection(fd int) bool {
	errCode, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
	if err != nil {
		return true
	}
	return errCode != 0
}

func checkWindowsConnection(fd int) bool {
	errCode, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
	if err != nil {
		return true
	}
	return errCode != 0
}

// relayWithTimeout performs a bidirectional copy between two connections, with timeouts on I/O operations.
func relayWithTimeout(localConn, remoteConn net.Conn, timeout time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var closeOnce sync.Once
	wg.Add(2)

	closeConnections := func() {
		logger.Debugf("Closing connections for %s <-> %s", localConn.RemoteAddr(), remoteConn.RemoteAddr())

		// Cancel context first to signal goroutines to stop
		cancel()

		// Close connections with proper error handling
		if err := localConn.Close(); err != nil && !isConnectionClosed(err) {
			logger.Debugf("Error closing local connection: %v", err)
		} else {
			logger.Debugf("Local connection closed successfully")
		}

		if err := remoteConn.Close(); err != nil && !isConnectionClosed(err) {
			logger.Debugf("Error closing remote connection: %v", err)
		} else {
			logger.Debugf("Remote connection closed successfully")
		}
	}

	go func() {
		defer closeOnce.Do(closeConnections)
		copyWithTimeout(
			ctx,
			remoteConn,
			localConn,
			timeout,
			&wg,
			DirectionLocalToRemote,
			localConn.RemoteAddr(),
			cancel,
		)
	}()

	go func() {
		defer closeOnce.Do(closeConnections)
		copyWithTimeout(
			ctx,
			localConn,
			remoteConn,
			timeout,
			&wg,
			DirectionRemoteToLocal,
			localConn.RemoteAddr(),
			cancel,
		)
	}()

	wg.Wait()
	logger.Debugf("Relay completed for %s <-> %s", localConn.RemoteAddr(), remoteConn.RemoteAddr())
}
