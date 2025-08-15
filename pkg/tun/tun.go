package tun

import (
	"io"
	"x-proxy/pkg/logger"
)

type routeInfo struct {
	dest    string
	gateway string
}

// TunDevice is a platform-independent representation of a TUN device.
// The actual implementation is in the OS-specific files.
type TunDevice struct {
	Name   string
	File   io.ReadWriteCloser
	routes []routeInfo
}

// Read reads a packet from the TUN device
func (t *TunDevice) Read(buf []byte) (int, error) {
	n, err := t.File.Read(buf)
	if err != nil {
		logger.Errorf("Error reading from TUN device %s: %v", t.Name, err)
	} else {
		logger.Debugf("Read %d bytes from TUN device %s", n, t.Name)
	}
	return n, err
}

// Write writes a packet to the TUN device
func (t *TunDevice) Write(buf []byte) (int, error) {
	n, err := t.File.Write(buf)
	if err != nil {
		logger.Errorf("Error writing to TUN device %s: %v", t.Name, err)
	} else {
		logger.Debugf("Wrote %d bytes to TUN device %s", n, t.Name)
	}
	return n, err
}

// Close closes the TUN device and removes all added routes.
func (t *TunDevice) Close() error {
	logger.Infof("Closing TUN device %s and removing routes", t.Name)
	for _, r := range t.routes {
		if err := t.DeleteRoute(r.dest, r.gateway); err != nil {
			// Log the error but continue trying to remove other routes
			logger.Warnf("Failed to delete route '%s': %v", r.dest, err)
		}
	}
	return t.File.Close()
}
