package ipcipher

// This file is based on the ipcrypt program by JP Aumasson.
// See: https://github.com/veorq/ipcrypt

import (
	"net"
)

func rotl(x, c byte) byte {
	return (x << c) | (x >> (8 - c))
}

func permuteFwd(state []byte) {
	a := state[0]
	b := state[1]
	c := state[2]
	d := state[3]
	a += b
	c += d
	b = rotl(b, 2)
	d = rotl(d, 5)
	b ^= a
	d ^= c
	a = rotl(a, 4)
	a += d
	c += b
	b = rotl(b, 3)
	d = rotl(d, 7)
	b ^= c
	d ^= a
	c = rotl(c, 4)
	state[0] = a
	state[1] = b
	state[2] = c
	state[3] = d
}

func permuteBwd(state []byte) {
	a := state[0]
	b := state[1]
	c := state[2]
	d := state[3]
	c = rotl(c, 4)
	b ^= c
	d ^= a
	b = rotl(b, 5)
	d = rotl(d, 1)
	a -= d
	c -= b
	a = rotl(a, 4)
	b ^= a
	d ^= c
	b = rotl(b, 6)
	d = rotl(d, 3)
	a -= b
	c -= d
	state[0] = a
	state[1] = b
	state[2] = c
	state[3] = d
}

func xor4(d, x, y []byte) {
	d[0] = x[0] ^ y[0]
	d[1] = x[1] ^ y[1]
	d[2] = x[2] ^ y[2]
	d[3] = x[3] ^ y[3]
}

// EncryptIPv4 encrypts an IPv4 address with a 16 byte key using the ipcrypt cipher.
// The IP address is not validated or converted with net.IP.To4() beforehand.
// Dst and src may point at the same memory for in-place encryption.
func EncryptIPv4(k *Key, dst, src net.IP) {
	xor4(dst, src, k[:4])
	permuteFwd(dst)
	xor4(dst, dst, k[4:8])
	permuteFwd(dst)
	xor4(dst, dst, k[8:12])
	permuteFwd(dst)
	xor4(dst, dst, k[12:16])
}

// DecryptIPv4 decrypts an IPv4 address with a 16 byte key using the ipcrypt cipher.
// The IP address is not validated or converted with net.IP.To4() beforehand.
// Dst and src may point at the same memory for in-place decryption.
func DecryptIPv4(k *Key, dst, src net.IP) {
	xor4(dst, src, k[12:16])
	permuteBwd(dst)
	xor4(dst, dst, k[8:12])
	permuteBwd(dst)
	xor4(dst, dst, k[4:8])
	permuteBwd(dst)
	xor4(dst, dst, k[:4])
}
