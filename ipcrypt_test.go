package ipcipher

import (
	"net"
	"testing"
)

var (
	ip  = net.IPv4zero
	key = new(Key)
)

func BenchmarkEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ip = EncryptIPv4(key, ip)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ip = DecryptIPv4(key, ip)
	}
}
