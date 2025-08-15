package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"x-proxy/pkg/logger"

	"github.com/doraemonkeys/doraemon"
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
	New: func() any {
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

// isTimeout is no longer used by copyWithTimeout, but we can keep it for general utility.
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

// copyWithTimeout copies data from src to dst. It no longer sets deadlines directly.
// Instead, it "pets" a watchdog on each successful data transfer to signal activity.
// It's designed to be run in a goroutine.
func copyWithTimeout(ctx context.Context, dst, src net.Conn, wg *sync.WaitGroup, direction Direction, clientAddr net.Addr, cancel context.CancelFunc, watchdog *doraemon.Watchdog) {
	defer wg.Done()
	defer func() {
		// Cancel context when this goroutine exits to signal the other goroutine to stop
		cancel()
		logger.Debugf("Cancelled context for %s direction %s", direction, clientAddr)
	}()

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf) //TODO: argument should be pointer-like to avoid allocations (SA6002)go-staticcheck

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
			} else if !isConnectionClosed(err) { // Log only if it's not a standard close error
				logger.Warnf("Relay error (%s read) for %s: %v", direction, clientAddr, err)
			}
			return
		}

		_, err = dst.Write(buf[:n])
		if err != nil {
			if !isConnectionClosed(err) {
				logger.Warnf("Relay error (%s write) for %s: %v", direction, clientAddr, err)
			}
			return
		}

		if watchdog != nil {
			watchdog.Pet()
		}
	}
}

// relayWithTimeout performs a bidirectional copy between two connections, using a Watchdog for idle timeouts.
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

	var watchdog *doraemon.Watchdog
	if timeout > 0 {
		watchdog = doraemon.NewWatchdog(
			doraemon.WatchdogWithCheckInterval(timeout),
			doraemon.WatchdogWithOnTimeout(func() {
				logger.Debugf("Watchdog timeout for %s <-> %s. No activity for %s.", localConn.RemoteAddr(), remoteConn.RemoteAddr(), timeout)
				closeOnce.Do(closeConnections)
			}),
			doraemon.WatchdogWithAutoStopOnTimeout(true),
		)
		watchdog.Start()
		defer watchdog.Stop()
	}

	closeAndCancel := func() {
		closeOnce.Do(closeConnections)
	}

	go func() {
		defer closeAndCancel()
		copyWithTimeout(ctx, remoteConn, localConn, &wg, DirectionLocalToRemote, localConn.RemoteAddr(), cancel, watchdog)
	}()

	go func() {
		defer closeAndCancel()
		copyWithTimeout(ctx, localConn, remoteConn, &wg, DirectionRemoteToLocal, localConn.RemoteAddr(), cancel, watchdog)
	}()

	wg.Wait()
	logger.Debugf("Relay completed for %s <-> %s", localConn.RemoteAddr(), remoteConn.RemoteAddr())
}
