package obfuscator

import (
	"net"
	"strings"
	"x-proxy/pkg/logger"
)

// Cipher is an interface for a cipher that can obfuscate a connection.
type Cipher interface {
	Obfuscate(conn net.Conn) net.Conn
}

func NewCipher(name, key string) Cipher {
	logger.Infof("Creating cipher: %s with key length %d", name, len(key))
	switch strings.ToLower(name) {
	case "chacha20":
		return NewChaCha20Cipher(key)
	case "xor-hardware":
		return NewXORHardwareCipher(key)
	case "xor", "xor-software":
		return NewXORSoftwareCipher(key)
	default:
		return NewXORSoftwareCipher(key) // default to software xor
	}
}
