package ipcipher

import (
	"net"
	"testing"
)

var c = New(key)

func TestIpCipher_BlockSize(t *testing.T) {
	if c.BlockSize() != 0 {
		t.Error("Block size is not 0")
	}
}

func TestEncryptBlock(t *testing.T) {
	for key, ips := range testVectors {
		c := New(key)
		for in, out := range ips {
			o := net.ParseIP(in)
			c.Encrypt(o, o)
			if !net.ParseIP(out).Equal(o) {
				t.Errorf("Invalid IP conversion for key %x, ip %s, expected: %s, got %s", key[:], in, out, o)
			}
		}
	}
}

func TestDecryptBlock(t *testing.T) {
	for key, ips := range testVectors {
		c := New(key)
		for out, in := range ips {
			o := net.ParseIP(in)
			c.Decrypt(o, o)
			if !net.ParseIP(out).Equal(o) {
				t.Errorf("Invalid IP conversion for key %x, ip %s, expected: %s, got %s", key[:], in, out, o)
			}
		}
	}
}

func TestEncryptBlockMega(t *testing.T) {
	for key, ips := range megaTestVectors {
		c := New(key)
		for in, out := range ips {
			o := net.ParseIP(in)
			for i := 0; i < 100000000; i++ {
				c.Encrypt(o, o)
			}
			if !net.ParseIP(out).Equal(o) {
				t.Fatalf("Encryption failed for key % x; ip %s; expected %s; got %s", key[:], in, out, o)
			}
		}
	}
}

func TestDecryptBlockMega(t *testing.T) {
	for key, ips := range megaTestVectors {
		c := New(key)
		for out, in := range ips {
			o := net.ParseIP(in)
			for i := 0; i < 100000000; i++ {
				c.Decrypt(o, o)
			}
			if !net.ParseIP(out).Equal(o) {
				t.Fatalf("Encryption failed for key % x; ip %s; expected %s; got %s", key[:], in, out, o)
			}
		}
	}
}
