//go:build windows

package tun

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"x-proxy/pkg/logger"

	"golang.zx2c4.com/wireguard/tun"
)

// wintunAdapter adapts the wintun Device interface to io.ReadWriteCloser
type wintunAdapter struct {
	device tun.Device
	bufs   [][]byte
	sizes  []int
}

func newWintunAdapter(device tun.Device) *wintunAdapter {
	return &wintunAdapter{
		device: device,
		bufs:   make([][]byte, 1),
		sizes:  make([]int, 1),
	}
}

func (w *wintunAdapter) Read(p []byte) (int, error) {
	w.bufs[0] = p
	n, err := w.device.Read(w.bufs, w.sizes, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return w.sizes[0], nil
}

func (w *wintunAdapter) Write(p []byte) (int, error) {
	w.bufs[0] = make([]byte, len(p))
	copy(w.bufs[0], p)
	w.sizes[0] = len(p)
	
	n, err := w.device.Write(w.bufs, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func (w *wintunAdapter) Close() error {
	return w.device.Close()
}

// NewTunDevice creates a new TUN device on Windows.
func NewTunDevice(name string) (*TunDevice, error) {
	logger.Infof("Creating new TUN device on Windows (requested name: %s)", name)
	
	// Create wintun device
	ifce, err := tun.CreateTUN(name, 1420) // MTU of 1420
	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		return nil, fmt.Errorf("failed to create TUN device: %v", err)
	}

	// Get the actual device name
	deviceName, err := ifce.Name()
	if err != nil {
		ifce.Close()
		logger.Errorf("Failed to get TUN device name: %v", err)
		return nil, fmt.Errorf("failed to get TUN device name: %v", err)
	}

	logger.Infof("Successfully created TUN device: %s", deviceName)
	return &TunDevice{
		Name: deviceName,
		File: newWintunAdapter(ifce),
	}, nil
}

// SetIP configures the IP address for the TUN interface.
func (t *TunDevice) SetIP(ip, netmask string) error {
	cmdStr := fmt.Sprintf("netsh interface ip set address name=\""+t.Name+"\" static %s %s", ip, netmask)
	cmd := exec.Command("cmd", "/C", cmdStr)
	logger.Debugf("Executing command: %s", cmd.String())
	err := cmd.Run()
	if err != nil {
		logger.Errorf("Failed to set IP address for %s: %v", t.Name, err)
		return fmt.Errorf("failed to set IP address: %v", err)
	}

	logger.Infof("Successfully set IP address %s for TUN device %s", ip, t.Name)
	return nil
}

// AddRoute adds a route through the TUN interface.
func (t *TunDevice) AddRoute(dest, gateway string) error {
	var destAddr, prefix string
	_, ipNet, err := net.ParseCIDR(dest)
	if err == nil {
		destAddr = ipNet.IP.String()
		ones, _ := ipNet.Mask.Size()
		prefix = fmt.Sprintf("%d", ones)
	} else {
		// Fallback for non-CIDR destinations, assuming it's a host
		destAddr = dest
		prefix = "32"
	}

	// Trick Windows by using the next IP as the gateway.
	gatewayIP := net.ParseIP(gateway)
	if gatewayIP == nil {
		return fmt.Errorf("invalid gateway IP: %s", gateway)
	}
	nextGatewayIP := incrementIP(gatewayIP.To4()) // Assuming IPv4

	cmdStr := fmt.Sprintf("netsh interface ip add route %s/%s interface=\"%s\" nexthop=%s", destAddr, prefix, t.Name, nextGatewayIP.String())
	cmd := exec.Command("cmd", "/C", cmdStr)
	logger.Debugf("Executing command: %s", cmd.String())
	err = cmd.Run()
	if err != nil {
		logger.Errorf("Failed to add route for %s: %v", t.Name, err)
		return fmt.Errorf("failed to add route: %v", err)
	}

	t.routes = append(t.routes, routeInfo{dest: dest, gateway: gateway})
	logger.Infof("Successfully added route: %s via %s (tricked to %s) for TUN device %s", dest, gateway, nextGatewayIP.String(), t.Name)
	return nil
}

// DeleteRoute removes a route that was added through the TUN interface.
func (t *TunDevice) DeleteRoute(dest, gateway string) error {
	var destAddr, prefix string
	_, ipNet, err := net.ParseCIDR(dest)
	if err == nil {
		destAddr = ipNet.IP.String()
		ones, _ := ipNet.Mask.Size()
		prefix = fmt.Sprintf("%d", ones)
	} else {
		destAddr = dest
		prefix = "32"
	}

	gatewayIP := net.ParseIP(gateway)
	if gatewayIP == nil {
		return fmt.Errorf("invalid gateway IP: %s", gateway)
	}
	nextGatewayIP := incrementIP(gatewayIP.To4())

	cmdStr := fmt.Sprintf("netsh interface ip delete route %s/%s interface=\"%s\" nexthop=%s", destAddr, prefix, t.Name, nextGatewayIP.String())
	cmd := exec.Command("cmd", "/C", cmdStr)

	logger.Debugf("Executing command: %s", cmd.String())
	err = cmd.Run()
	if err != nil {
		logger.Errorf("Failed to delete route for %s: %v", t.Name, err)
		return fmt.Errorf("failed to delete route: %v", err)
	}

	logger.Infof("Successfully deleted route: %s from TUN device %s", dest, t.Name)
	return nil
}

func incrementIP(ip net.IP) net.IP {
	incIP := make(net.IP, len(ip))
	copy(incIP, ip)
	for j := len(incIP) - 1; j >= 0; j-- {
		incIP[j]++
		if incIP[j] > 0 {
			break
		}
	}
	return incIP
}
