package obfuscator

import (
	"net"

	"github.com/templexxx/xor"
)

// NewXORHardwareCipher creates a new XOR cipher.
func NewXORHardwareCipher(key string) Cipher {
	if key == "" {
		return &noopCipher{}
	}
	return &xorHardwareCipher{
		key: []byte(key),
	}
}

type xorHardwareCipher struct {
	key []byte
}

func (c *xorHardwareCipher) Obfuscate(conn net.Conn) net.Conn {
	return &xorHardwareConn{
		Conn: conn,
		key:  c.key,
	}
}

type xorHardwareConn struct {
	net.Conn
	key      []byte
	readPos  int
	writePos int
}

func (c *xorHardwareConn) Read(p []byte) (n int, err error) {

	n, err = c.Conn.Read(p)
	if n > 0 && len(c.key) > 0 {
		buf := p[:n]
		key := c.key
		keyLen := len(key)
		processed := 0
		for processed < n {
			keyStart := c.readPos % keyLen
			chunkSize := keyLen - keyStart
			if processed+chunkSize > n {
				chunkSize = n - processed
			}

			dataChunk := buf[processed : processed+chunkSize]
			keyChunk := key[keyStart : keyStart+chunkSize]

			xor.Bytes(dataChunk, dataChunk, keyChunk)

			c.readPos += chunkSize
			processed += chunkSize
		}
	}
	return
}

func (c *xorHardwareConn) Write(p []byte) (n int, err error) {

	if len(c.key) == 0 {
		return c.Conn.Write(p)
	}
	buf := make([]byte, len(p))
	copy(buf, p)

	key := c.key
	keyLen := len(key)
	processed := 0
	for processed < len(buf) {
		keyStart := c.writePos % keyLen
		chunkSize := keyLen - keyStart
		if processed+chunkSize > len(buf) {
			chunkSize = len(buf) - processed
		}

		dataChunk := buf[processed : processed+chunkSize]
		keyChunk := key[keyStart : keyStart+chunkSize]

		xor.Bytes(dataChunk, dataChunk, keyChunk)

		c.writePos += chunkSize
		processed += chunkSize
	}

	return c.Conn.Write(buf)
}

func (c *xorHardwareConn) Close() (err error) {
	return c.Conn.Close()
}
