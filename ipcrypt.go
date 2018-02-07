// This file is based on the ipcrypt program by JP Aumasson.
// See: https://github.com/veorq/ipcrypt
package ipcipher

import (
	"net"
)

func rotl(x, c byte) byte {
	return (x << c) | (x >> (8 - c))
}

func permuteFwd(state *[4]byte) {
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

func permuteBwd(state *[4]byte) {
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

func xor4(x *[4]byte, y []byte) {
	for i := range x {
		x[i] ^= y[i]
	}
}

// EncryptIPv4 encrypts an IPv4 address with a 16 byte key using the ipcrypt cipher.
// The IP address is not validated beforehand.
func EncryptIPv4(k *Key, ip net.IP) net.IP {
	state := new([4]byte)
	copy(state[:], ip.To4())

	xor4(state, k[:4])
	permuteFwd(state)
	xor4(state, k[4:8])
	permuteFwd(state)
	xor4(state, k[8:12])
	permuteFwd(state)
	xor4(state, k[12:16])

	return state[:]
}

// DecryptIPv4 decrypts an IPv4 address with a 16 byte key using the ipcrypt cipher.
// The IP address is not validated beforehand.
func DecryptIPv4(k *Key, ip net.IP) net.IP {
	state := new([4]byte)
	copy(state[:], ip.To4())

	xor4(state, k[12:16])
	permuteBwd(state)
	xor4(state, k[8:12])
	permuteBwd(state)
	xor4(state, k[4:8])
	permuteBwd(state)
	xor4(state, k[:4])

	return state[:]
}
