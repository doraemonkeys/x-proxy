package config

import (
	"encoding/json"
	"os"
)

// TLSConfig holds the TLS configuration
type TLSConfig struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	CAFile   string `json:"ca_file"`
}

// ClientModeConfig holds the configuration for a single client proxy mode
type ClientModeConfig struct {
	Type       string `json:"type"` // http, https, socks5, transparent
	ListenAddr string `json:"listen_addr"`
}

// ClientConfig holds the configuration for the client
type ClientConfig struct {
	ServerAddr         string             `json:"server_addr"`
	Key                string             `json:"key"`
	DisableObfuscation bool               `json:"disable_obfuscation"`
	LogLevel           string             `json:"log_level"`
	Transport          string             `json:"transport"` // "tcp" or "kcp"
	TLS                TLSConfig          `json:"tls"`
	Modes              []ClientModeConfig `json:"modes"`
	ReadWriteDeadline  int                `json:"read_write_deadline"`
	Obfuscator         string             `json:"obfuscator"`
	EnableStats        bool               `json:"enable_stats"`
}

// ServerConfig holds the configuration for the server
type ServerConfig struct {
	ListenAddr         string    `json:"listen_addr"`
	Key                string    `json:"key"`
	DisableObfuscation bool      `json:"disable_obfuscation"`
	LogLevel           string    `json:"log_level"`
	Transport          string    `json:"transport"` // "tcp" or "kcp"
	TLS                TLSConfig `json:"tls"`
	ReadWriteDeadline  int       `json:"read_write_deadline"`
	Obfuscator         string    `json:"obfuscator"`
	EnableStats        bool      `json:"enable_stats"`
}

// LoadClientConfig loads the client configuration from a file
func LoadClientConfig(path string) (*ClientConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := &ClientConfig{}
	err = json.NewDecoder(file).Decode(cfg)
	return cfg, err
}

// LoadServerConfig loads the server configuration from a file
func LoadServerConfig(path string) (*ServerConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := &ServerConfig{}
	err = json.NewDecoder(file).Decode(cfg)
	return cfg, err
}
