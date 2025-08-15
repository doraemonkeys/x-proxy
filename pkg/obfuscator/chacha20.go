package obfuscator

import (
	"crypto/rand"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/chacha20"
)

// readFullWithTimeout reads exactly len(buf) bytes from conn with a timeout
func readFullWithTimeout(conn net.Conn, buf []byte, timeout time.Duration) error {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	_, err := io.ReadFull(conn, buf)
	return err
}

// NewChaCha20Cipher creates a new ChaCha20 cipher.
func NewChaCha20Cipher(key string) Cipher {
	if key == "" {
		return &noopCipher{}
	}
	keyBytes := []byte(key)
	if len(keyBytes) > chacha20.KeySize {
		keyBytes = keyBytes[:chacha20.KeySize]
	} else {
		for len(keyBytes) < chacha20.KeySize {
			keyBytes = append(keyBytes, 0)
		}
	}

	return &chaCha20Cipher{
		key: keyBytes,
	}
}

type chaCha20Cipher struct {
	key []byte
}

func (c *chaCha20Cipher) Obfuscate(conn net.Conn) net.Conn {
	return &chaCha20Conn{
		Conn: conn,
		key:  c.key,
	}
}

type chaCha20Conn struct {
	net.Conn
	key         []byte
	writeCipher *chacha20.Cipher
	readCipher  *chacha20.Cipher
}

func (c *chaCha20Conn) Write(p []byte) (n int, err error) {
	if c.writeCipher == nil {
		nonce := make([]byte, chacha20.NonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return 0, err
		}

		c.writeCipher, err = chacha20.NewUnauthenticatedCipher(c.key, nonce)
		if err != nil {
			return 0, err
		}

		if _, err := c.Conn.Write(nonce); err != nil {
			return 0, err
		}
	}

	buf := make([]byte, len(p))
	c.writeCipher.XORKeyStream(buf, p)
	return c.Conn.Write(buf)
}

func (c *chaCha20Conn) Read(p []byte) (n int, err error) {
	if c.readCipher == nil {
		nonce := make([]byte, chacha20.NonceSize)
		if err := readFullWithTimeout(c.Conn, nonce, 5*time.Second); err != nil {
			return 0, err
		}

		c.readCipher, err = chacha20.NewUnauthenticatedCipher(c.key, nonce)
		if err != nil {
			return 0, err
		}
	}

	n, err = c.Conn.Read(p)
	if n > 0 {
		c.readCipher.XORKeyStream(p[:n], p[:n])
	}
	return
}

func (c *chaCha20Conn) Close() (err error) {
	return c.Conn.Close()
}
