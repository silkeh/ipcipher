package ipcipher

import (
	"net"
	"testing"
)

func BenchmarkEncryptIPv4(b *testing.B) {
	ip := net.IPv4zero
	key := new(Key)
	for i := 0; i < b.N; i++ {
		EncryptIPv4(key, ip, ip)
	}
}

func BenchmarkDecryptIPv4(b *testing.B) {
	ip := net.IPv4zero
	key := new(Key)
	for i := 0; i < b.N; i++ {
		DecryptIPv4(key, ip, ip)
	}
}
