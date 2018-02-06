// Package ipcipher implements the ipcipher specification.
// See: https://github.com/PowerDNS/ipcipher
package ipcipher

import (
	"crypto/rand"
	"net"
	"crypto/aes"
	"crypto/sha1"
	"crypto/subtle"
	"errors"

	"github.com/silkeh/ipcipher/ipcrypt"
	"golang.org/x/crypto/pbkdf2"
)

// Salt is the salt used for key derivation.
const Salt = "ipcipheripcipher"

// Key represents a key used for encrypting and decrypting IP addresses.
type Key [16]byte

// NewKey generates a completely random key.
func NewKey() (k *Key) {
	k = new(Key)
	_, err := rand.Read(k[:])
	if err != nil {
		panic(err)
	}
	return
}

// NewKeyFromPassword derives a key from a password.
// TODO: look into doing this without copy
// TODO: zero original byte slice
func NewKeyFromPassword(p string) (k *Key) {
	k = new(Key)
	b := pbkdf2.Key([]byte(p), []byte(Salt), 50000, 16, sha1.New)
	subtle.ConstantTimeCopy(1, k[:], b[:])
	return
}

// Encrypt an IP address.
func Encrypt(key *Key, ip net.IP) (net.IP, error) {
	if ip.To4() != nil {
		return EncryptIPv4(key, ip)
	}
	if ip.To16() != nil {
		return EncryptIPv6(key, ip)
	}
	return nil, errors.New("invalid IP address")
}

// Decrypt an IP address.
func Decrypt(key *Key, ip net.IP) (net.IP, error) {
	if ip.To4() != nil {
		return DecryptIPv4(key, ip)
	}
	if ip.To16() != nil {
		return DecryptIPv6(key, ip)
	}
	return nil, errors.New("invalid IP address")
}

// EncryptIPv4 encrypts an IPv4 address.
func EncryptIPv4(key *Key, ip net.IP) (net.IP, error) {
	a, err := ipcrypt.Encrypt(*key, ip.String())
	if err != nil {
		return nil, err
	}
	return net.ParseIP(a), nil
}

// DecryptIPv4 encrypts an IPv4 address.
func DecryptIPv4(key *Key, ip net.IP) (net.IP, error) {
	a, err := ipcrypt.Decrypt(*key, ip.String())
	if err != nil {
		return nil, err
	}
	return net.ParseIP(a), nil
}

// EncryptIPv6 encrypts an IPv6 address.
func EncryptIPv6(key *Key, ip net.IP) (out net.IP, err error) {
	c, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	o := net.IPv6unspecified
	c.Encrypt(o, ip)
	return o, nil
}

// DecryptIPv6 decrypts an IPv6 address.
func DecryptIPv6(key *Key, ip net.IP) (out net.IP, err error) {
	c, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	o := net.IPv6unspecified
	c.Decrypt(o, ip)
	return o, nil
}
