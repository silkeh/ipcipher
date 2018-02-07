// Package ipcrypt is based on the ipcrypt program by JP Aumasson.
// See: https://github.com/veorq/ipcrypt
package ipcrypt

// see also https://github.com/dgryski/go-ipcrypt/

import (
	"errors"
	"net"
)

func rotl(x, c byte) byte {
	return (x << c) | (x >> (8 - c))
}

func permute_fwd(state *[4]byte) *[4]byte {
	a := state[0]
	b := state[1]
	c := state[2]
	d := state[3]
	a += b
	c += d
	a &= 0xff
	c &= 0xff
	b = rotl(b, 2)
	d = rotl(d, 5)
	b ^= a
	d ^= c
	a = rotl(a, 4)
	a += d
	c += b
	a &= 0xff
	c &= 0xff
	b = rotl(b, 3)
	d = rotl(d, 7)
	b ^= c
	d ^= a
	c = rotl(c, 4)
	return &[4]byte{a, b, c, d}
}

func permute_bwd(state *[4]byte) *[4]byte {
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
	a &= 0xff
	c &= 0xff
	a = rotl(a, 4)
	b ^= a
	d ^= c
	b = rotl(b, 6)
	d = rotl(d, 3)
	a -= b
	c -= d
	a &= 0xff
	c &= 0xff
	return &[4]byte{a, b, c, d}
}

func xor4(x *[4]byte, y []byte) *[4]byte {
	return &[4]byte{x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]}
}

func Encrypt(k *[16]byte, ip net.IP) (net.IP, error) {
	p := ip.To4()
	if p == nil {
		return nil, errors.New("encrypt: invalid IPv4 address")
	}
	state := &[4]byte{p[0], p[1], p[2], p[3]}

	state = xor4(state, k[:4])
	state = permute_fwd(state)
	state = xor4(state, k[4:8])
	state = permute_fwd(state)
	state = xor4(state, k[8:12])
	state = permute_fwd(state)
	state = xor4(state, k[12:16])

	return state[:], nil
}

func Decrypt(k *[16]byte, ip net.IP) (net.IP, error) {
	p := ip.To4()
	if p == nil {
		return nil, errors.New("decrypt: invalid IPv4 address")
	}
	state := &[4]byte{p[0], p[1], p[2], p[3]}

	state = xor4(state, k[12:16])
	state = permute_bwd(state)
	state = xor4(state, k[8:12])
	state = permute_bwd(state)
	state = xor4(state, k[4:8])
	state = permute_bwd(state)
	state = xor4(state, k[:4])

	return state[:], nil
}
