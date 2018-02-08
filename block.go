package ipcipher

import (
	"crypto/aes"
	"crypto/cipher"
	"net"
)

// ipCipher is an instance of ipcipher encryption for a particular key.
type ipCipher struct {
	key *Key
	aes cipher.Block
}

// New creates and returns a new cipher.Block for IPcipher.
func New(key *Key) cipher.Block {
	c, _ := aes.NewCipher(key[:])
	return &ipCipher{key, c}
}

// BlockSize returns 0, because the block size is 32 and 128 at the same time.
func (i *ipCipher) BlockSize() int {
	return 0
}

// Encrypt encrypts a net.IP compatible byte slice src into dst.
// Dst and src may point at the same memory.
func (i *ipCipher) Encrypt(dst, src []byte) {
	if ip4 := net.IP(src).To4(); ip4 != nil {
		EncryptIPv4(i.key, net.IP(dst).To4(), ip4)
	} else if net.IP(src).To16() != nil {
		i.aes.Encrypt(dst, src)
	} else {
		panic("Invalid IP address")
	}
}

// Decrypt decrypts a net.IP compatible byte slice src into dst.
// Dst and src may point at the same memory.
func (i *ipCipher) Decrypt(dst, src []byte) {
	if ip4 := net.IP(src).To4(); ip4 != nil {
		DecryptIPv4(i.key, net.IP(dst).To4(), ip4)
	} else if net.IP(src).To16() != nil {
		i.aes.Decrypt(dst, src)
	} else {
		panic("Invalid IP address")
	}
}
