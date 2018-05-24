// Package ipcipher implements the ipcipher specification.
// See: https://github.com/PowerDNS/ipcipher
package ipcipher

import (
	"crypto/aes"
	"crypto/sha1"
	"crypto/subtle"
	"errors"
	"io"
	"net"

	"golang.org/x/crypto/pbkdf2"
)

// Salt is the salt used for key derivation.
const Salt = "ipcipheripcipher"

// Key represents a key used for encrypting and decrypting IP addresses.
type Key = [16]byte

// GenerateKey generates a completely random key.
func GenerateKey(rand io.Reader) (k *Key) {
	k = new(Key)
	_, err := rand.Read(k[:])
	if err != nil {
		panic(err)
	}
	return
}

// GenerateKeyFromPassword derives a key from a password.
// TODO: look into doing this without copy
func GenerateKeyFromPassword(p string) (k *Key) {
	k = new(Key)
	b := pbkdf2.Key([]byte(p), []byte(Salt), 50000, 16, sha1.New)
	subtle.ConstantTimeCopy(1, k[:], b[:])
	return
}

// Encrypt an IP address.
func Encrypt(key *Key, dst, src net.IP) error {
	if ip4 := src.To4(); ip4 != nil {
		EncryptIPv4(key, dst.To4(), ip4)
		return nil
	}
	if src.To16() != nil {
		EncryptIPv6(key, dst, src)
		return nil
	}
	return errors.New("encrypt: invalid IP address")
}

// Decrypt an IP address.
func Decrypt(key *Key, dst, src net.IP) error {
	if ip4 := src.To4(); ip4 != nil {
		DecryptIPv4(key, dst.To4(), ip4)
		return nil
	}
	if src.To16() != nil {
		DecryptIPv6(key, dst, src)
		return nil
	}
	return errors.New("decrypt: invalid IP address")
}

// EncryptIPv6 encrypts an IPv6 address.
func EncryptIPv6(key *Key, dst, src net.IP) (err error) {
	c, _ := aes.NewCipher(key[:])
	c.Encrypt(dst, src)
	return nil
}

// DecryptIPv6 decrypts an IPv6 address.
func DecryptIPv6(key *Key, dst, src net.IP) (err error) {
	c, _ := aes.NewCipher(key[:])
	c.Decrypt(dst, src)
	return nil
}
