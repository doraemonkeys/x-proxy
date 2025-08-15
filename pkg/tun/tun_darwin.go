//go:build darwin

package tun

import (
	"fmt"
	"os/exec"
	"x-proxy/pkg/logger"

	"github.com/songgao/water"
)

// NewTunDevice creates a new TUN device on macOS.
// The name parameter is ignored as macOS assigns it automatically.
func NewTunDevice(name string) (*TunDevice, error) {
	logger.Infof("Creating new TUN device on macOS")
	config := water.Config{
		DeviceType: water.TUN,
	}

	ifce, err := water.New(config)
	if err != nil {
		logger.Errorf("Failed to create utun device: %v", err)
		return nil, fmt.Errorf("failed to create utun device: %v", err)
	}

	logger.Infof("Successfully created TUN device: %s", ifce.Name())
	return &TunDevice{
		Name: ifce.Name(),
		File: ifce,
	}, nil
}

// SetIP configures the IP address for the TUN interface
func (t *TunDevice) SetIP(ip, netmask string) error {
	// Use external commands to configure the interface
	// On macOS, we use ifconfig. The destination address for point-to-point is often the same as the local address.
	cmd := fmt.Sprintf("ifconfig %s %s %s up", t.Name, ip, ip)
	logger.Debugf("Executing command: %s", cmd)
	err := exec.Command("sh", "-c", cmd).Run()
	if err != nil {
		logger.Errorf("Failed to set IP address for %s: %v", t.Name, err)
		return fmt.Errorf("failed to set IP address: %v", err)
	}

	logger.Infof("Successfully set IP address %s for TUN device %s", ip, t.Name)
	return nil
}

// AddRoute adds a route through the TUN interface
func (t *TunDevice) AddRoute(dest, gateway string) error {
	cmd := fmt.Sprintf("route add -net %s %s", dest, gateway)
	logger.Debugf("Executing command: %s", cmd)
	err := exec.Command("sh", "-c", cmd).Run()
	if err != nil {
		logger.Errorf("Failed to add route for %s: %v", t.Name, err)
		return fmt.Errorf("failed to add route: %v", err)
	}

	t.routes = append(t.routes, routeInfo{dest: dest, gateway: gateway})
	logger.Infof("Successfully added route: %s via %s for TUN device %s", dest, gateway, t.Name)
	return nil
}

// DeleteRoute removes a route that was added through the TUN interface.
func (t *TunDevice) DeleteRoute(dest, gateway string) error {
	cmd := fmt.Sprintf("route delete -net %s %s", dest, gateway)
	logger.Debugf("Executing command: %s", cmd)
	err := exec.Command("sh", "-c", cmd).Run()
	if err != nil {
		logger.Errorf("Failed to delete route for %s: %v", t.Name, err)
		return fmt.Errorf("failed to delete route: %v", err)
	}

	logger.Infof("Successfully deleted route: %s via %s for TUN device %s", dest, gateway, t.Name)
	return nil
}
