package ipcipher

import (
	"net"
	"testing"
)

func BenchmarkEncryptIPv6(b *testing.B) {
	ip := net.IPv6zero
	key := new(Key)
	for i := 0; i < b.N; i++ {
		EncryptIPv6(key, ip, ip)
	}
}

func BenchmarkDecryptIPv6(b *testing.B) {
	ip := net.IPv6zero
	key := new(Key)
	for i := 0; i < b.N; i++ {
		DecryptIPv6(key, ip, ip)
	}
}

func BenchmarkEncryptForIPv4(b *testing.B) {
	ip := net.IPv4zero
	key := new(Key)
	for i := 0; i < b.N; i++ {
		_ = Encrypt(key, ip, ip)
	}
}

func BenchmarkDecryptForIPv4(b *testing.B) {
	ip := net.IPv4zero
	key := new(Key)
	for i := 0; i < b.N; i++ {
		_ = Decrypt(key, ip, ip)
	}
}

func BenchmarkEncryptForIPv6(b *testing.B) {
	ip := net.IPv6zero
	key := new(Key)
	for i := 0; i < b.N; i++ {
		_ = Encrypt(key, ip, ip)
	}
}

func BenchmarkDecryptForIPv6(b *testing.B) {
	ip := net.IPv6zero
	key := new(Key)
	for i := 0; i < b.N; i++ {
		_ = Decrypt(key, ip, ip)
	}
}
