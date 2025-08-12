package stats

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
	
	"x-proxy/pkg/logger"
)

// ConnectionType represents the type of connection
type ConnectionType string

const (
	ConnTypeTCP ConnectionType = "tcp"
	ConnTypeUDP ConnectionType = "udp"
)

// ConnectionInfo holds detailed information about a connection
type ConnectionInfo struct {
	ID          string         `json:"id"`
	Type        ConnectionType `json:"type"`
	SourceAddr  string         `json:"source_addr"`
	TargetAddr  string         `json:"target_addr"`
	ProxyMode   string         `json:"proxy_mode,omitempty"`
	StartTime   time.Time      `json:"start_time"`
	BytesSent   int64          `json:"bytes_sent"`
	BytesRecv   int64          `json:"bytes_recv"`
}

// StatsManager manages connection statistics
type StatsManager struct {
	mu          sync.RWMutex
	enabled     bool
	connections map[string]*ConnectionInfo
	totalCount  int64
}

// NewStatsManager creates a new statistics manager
func NewStatsManager(enabled bool) *StatsManager {
	sm := &StatsManager{
		enabled:     enabled,
		connections: make(map[string]*ConnectionInfo),
	}
	
	if enabled {
		// Start periodic stats logging
		go sm.periodicLog()
	}
	
	return sm
}

// AddConnection adds a new connection to statistics
func (sm *StatsManager) AddConnection(id string, connType ConnectionType, sourceAddr, targetAddr, proxyMode string) {
	if !sm.enabled {
		return
	}
	
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	sm.connections[id] = &ConnectionInfo{
		ID:         id,
		Type:       connType,
		SourceAddr: sourceAddr,
		TargetAddr: targetAddr,
		ProxyMode:  proxyMode,
		StartTime:  time.Now(),
	}
	sm.totalCount++
	
	logger.Debugf("Stats: Added connection %s (%s) %s -> %s via %s", id, connType, sourceAddr, targetAddr, proxyMode)
}

// RemoveConnection removes a connection from statistics
func (sm *StatsManager) RemoveConnection(id string) {
	if !sm.enabled {
		return
	}
	
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	if conn, exists := sm.connections[id]; exists {
		duration := time.Since(conn.StartTime)
		logger.Debugf("Stats: Removed connection %s (%s) after %v, sent: %d bytes, recv: %d bytes", 
			id, conn.Type, duration, conn.BytesSent, conn.BytesRecv)
		delete(sm.connections, id)
	}
}

// UpdateBytes updates the bytes transferred for a connection
func (sm *StatsManager) UpdateBytes(id string, sent, recv int64) {
	if !sm.enabled {
		return
	}
	
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	if conn, exists := sm.connections[id]; exists {
		conn.BytesSent += sent
		conn.BytesRecv += recv
	}
}

// GetSimpleStats returns simple connection count statistics
func (sm *StatsManager) GetSimpleStats() map[string]interface{} {
	if !sm.enabled {
		return map[string]interface{}{
			"enabled": false,
		}
	}
	
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	tcpCount := 0
	udpCount := 0
	
	for _, conn := range sm.connections {
		switch conn.Type {
		case ConnTypeTCP:
			tcpCount++
		case ConnTypeUDP:
			udpCount++
		}
	}
	
	return map[string]interface{}{
		"enabled":           true,
		"total_connections": len(sm.connections),
		"tcp_connections":   tcpCount,
		"udp_connections":   udpCount,
		"total_processed":   sm.totalCount,
	}
}

// GetDetailedStats returns detailed connection information
func (sm *StatsManager) GetDetailedStats() map[string]interface{} {
	if !sm.enabled {
		return map[string]interface{}{
			"enabled": false,
		}
	}
	
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	connections := make([]ConnectionInfo, 0, len(sm.connections))
	for _, conn := range sm.connections {
		connections = append(connections, *conn)
	}
	
	simple := sm.GetSimpleStats()
	simple["connections"] = connections
	
	return simple
}

// LogStats logs current statistics
func (sm *StatsManager) LogStats() {
	if !sm.enabled {
		return
	}
	
	simple := sm.GetSimpleStats()
	logger.Infof("Connection Stats: Active=%d (TCP=%d, UDP=%d), Total Processed=%d",
		simple["total_connections"], simple["tcp_connections"], 
		simple["udp_connections"], simple["total_processed"])
}

// LogDetailedStats logs detailed statistics
func (sm *StatsManager) LogDetailedStats() {
	if !sm.enabled {
		return
	}
	
	detailed := sm.GetDetailedStats()
	jsonData, err := json.MarshalIndent(detailed, "", "  ")
	if err != nil {
		logger.Warnf("Failed to marshal detailed stats: %v", err)
		return
	}
	
	logger.Infof("Detailed Connection Stats:\n%s", string(jsonData))
}

// periodicLog logs statistics periodically
func (sm *StatsManager) periodicLog() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		sm.LogStats()
	}
}

// GenerateConnectionID generates a unique connection ID
func GenerateConnectionID(sourceAddr, targetAddr string) string {
	return fmt.Sprintf("%s_%s_%d", sourceAddr, targetAddr, time.Now().UnixNano())
}