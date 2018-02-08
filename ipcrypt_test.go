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
		EncryptIPv4(key, ip, ip)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		DecryptIPv4(key, ip, ip)
	}
}
