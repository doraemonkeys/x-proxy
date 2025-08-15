//go:build linux

package tun

import (
	"fmt"
	"os/exec"
	"x-proxy/pkg/logger"

	"github.com/songgao/water"
)

// NewTunDevice creates a new TUN device on Linux using songgao/water.
func NewTunDevice(name string) (*TunDevice, error) {
	logger.Infof("Creating new TUN device on Linux: %s", name)
	config := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: name,
		},
	}

	ifce, err := water.New(config)
	if err != nil {
		logger.Errorf("Failed to create TUN device %s: %v", name, err)
		return nil, fmt.Errorf("failed to create TUN device: %v", err)
	}

	logger.Infof("Successfully created TUN device: %s", ifce.Name())
	return &TunDevice{
		Name: ifce.Name(),
		File: ifce,
	}, nil
}

// SetIP configures the IP address for the TUN interface.
func (t *TunDevice) SetIP(ip, netmask string) error {
	// Use external commands to configure the interface
	cmd := fmt.Sprintf("ip addr add %s/%s dev %s", ip, netmask, t.Name)
	logger.Debugf("Executing command: %s", cmd)
	err := exec.Command("sh", "-c", cmd).Run()
	if err != nil {
		logger.Errorf("Failed to set IP address for %s: %v", t.Name, err)
		return fmt.Errorf("failed to set IP address: %v", err)
	}

	cmd = fmt.Sprintf("ip link set %s up", t.Name)
	logger.Debugf("Executing command: %s", cmd)
	err = exec.Command("sh", "-c", cmd).Run()
	if err != nil {
		logger.Errorf("Failed to bring interface %s up: %v", t.Name, err)
		return fmt.Errorf("failed to bring interface up: %v", err)
	}

	// Disable IPv6 on the interface
	cmd = fmt.Sprintf("sysctl -w net.ipv6.conf.%s.disable_ipv6=1", t.Name)
	logger.Debugf("Executing command: %s", cmd)
	err = exec.Command("sh", "-c", cmd).Run()
	if err != nil {
		// This is not a fatal error, just log a warning
		logger.Warnf("Failed to disable IPv6 on %s: %v", t.Name, err)
	}

	logger.Infof("Successfully set IP address %s/%s for TUN device %s", ip, netmask, t.Name)
	return nil
}

// AddRoute adds a route through the TUN interface.
func (t *TunDevice) AddRoute(dest, gateway string) error {
	cmd := fmt.Sprintf("ip route add %s via %s dev %s", dest, gateway, t.Name)
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
	cmd := fmt.Sprintf("ip route del %s via %s dev %s", dest, gateway, t.Name)
	logger.Debugf("Executing command: %s", cmd)
	err := exec.Command("sh", "-c", cmd).Run()
	if err != nil {
		logger.Errorf("Failed to delete route for %s: %v", t.Name, err)
		return fmt.Errorf("failed to delete route: %v", err)
	}

	logger.Infof("Successfully deleted route: %s via %s for TUN device %s", dest, gateway, t.Name)
	return nil
}
