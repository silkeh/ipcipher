package ipcrypt

import (
	"net"
	"testing"
)

var (
	ip  = net.IPv4zero
	key = new([16]byte)
)

func BenchmarkEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ip = Encrypt(key, ip)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ip = Decrypt(key, ip)
	}
}
