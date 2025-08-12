package obfuscator

import (
	"net"
)

// NewXORSoftwareCipher creates a new XOR cipher.
func NewXORSoftwareCipher(key string) Cipher {
	if key == "" {
		return &noopCipher{}
	}
	return &xorCipher{
		key: []byte(key),
	}
}

type xorCipher struct {
	key []byte
}

func (c *xorCipher) Obfuscate(conn net.Conn) net.Conn {
	return &xorConn{
		Conn:     conn,
		key:      c.key,
		readPos:  0,
		writePos: 0,
	}
}

type xorConn struct {
	net.Conn
	key      []byte
	readPos  int
	writePos int
}

func (c *xorConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	if n > 0 && len(c.key) > 0 {
		buf := p[:n]
		for i := 0; i < len(buf); i++ {
			buf[i] ^= c.key[c.readPos%len(c.key)]
			c.readPos++
		}
	}
	return
}

func (c *xorConn) Write(p []byte) (n int, err error) {
	if len(c.key) == 0 {
		return c.Conn.Write(p)
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	for i := 0; i < len(buf); i++ {
		buf[i] ^= c.key[c.writePos%len(c.key)]
		c.writePos++
	}
	return c.Conn.Write(buf)
}

// noopCipher is a cipher that does nothing, for when the key is empty.
type noopCipher struct{}

func (c *noopCipher) Obfuscate(conn net.Conn) net.Conn {
	return conn
}
