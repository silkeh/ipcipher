package ipcipher

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
)

var keyTestVectors = map[string][]byte{
	"":                     {0xbb, 0x8d, 0xcd, 0x7b, 0xe9, 0xa6, 0xf4, 0x3b, 0x33, 0x04, 0xc6, 0x40, 0xd7, 0xd7, 0x10, 0x3c},
	"3.141592653589793":    {0x37, 0x05, 0xbd, 0x6c, 0x0e, 0x26, 0xa1, 0xa8, 0x39, 0x89, 0x8f, 0x1f, 0xa0, 0x16, 0xa3, 0x74},
	"crypto is not a coin": {0x06, 0xc4, 0xba, 0xd2, 0x3a, 0x38, 0xb9, 0xe0, 0xad, 0x9d, 0x05, 0x90, 0xb0, 0xa3, 0xd9, 0x3a},
}

var testVectors = map[*Key]map[string]string{
	{'s', 'o', 'm', 'e', ' ', '1', '6', '-', 'b', 'y', 't', 'e', ' ', 'k', 'e', 'y'}: {
		"127.0.0.1": "114.62.227.59",
		"8.8.8.8":   "46.48.51.50",
		"1.2.3.4":   "171.238.15.199",
		"::1":       "3718:8853:1723:6c88:7e5f:2e60:c79a:2bf",
		"2001:503:ba3e::2:30": "64d2:883d:ffb5:dd79:24b:943c:22aa:4ae7",
		"2001:DB8::":          "ce7e:7e39:d282:e7b1:1d6d:5ca1:d4de:246f",
	},
	GenerateKeyFromPassword("crypto is not a coin"): {
		"198.41.0.4":    "139.111.117.167",
		"130.161.180.1": "66.235.221.231",
		"0.0.0.0":       "203.253.152.187",
		"::1":           "a551:9cb0:c9b:f6e1:6112:58a:af29:3a6c",
		"2001:503:ba3e::2:30": "6e60:2674:2fac:d383:f9d5:dcfe:fc53:328e",
		"2001:DB8::":          "a8f5:16c8:e2ea:23b9:748d:67a2:4107:9d2e",
	},
}

var megaTestVectors = map[*Key]map[string]string{
	{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}: {
		"192.168.69.42": "93.155.197.186",
	},
}

func TestNewKey(t *testing.T) {
	z := make([]byte, 16)
	n := GenerateKey(rand.Reader)
	if bytes.Equal(z, n[:]) {
		t.Errorf("Generated random key is zero")
	}
}

func TestNewKeyFromPassword(t *testing.T) {
	for str, key := range keyTestVectors {
		k := GenerateKeyFromPassword(str)
		if !bytes.Equal(k[:], key) {
			t.Errorf("Invalid key for string %q, got:\n% x, expected:\n% x", str, k[:], key)
		}
	}
}

func TestInvalidIPAddress(t *testing.T) {
	ip := make([]byte, 3)
	key := new(Key)
	if err := Encrypt(key, ip, ip); err == nil {
		t.Errorf("Expected encrypt error for invalid IP address %x", ip)
	}
	if err := Decrypt(key, ip, ip); err == nil {
		t.Errorf("Expected decrypt error for invalid IP address %x", ip)
	}
}

func TestEncrypt(t *testing.T) {
	for key, ips := range testVectors {
		for in, out := range ips {
			o := net.ParseIP(in)
			Encrypt(key, o, o)
			if !net.ParseIP(out).Equal(o) {
				t.Errorf("Invalid IP conversion for key %x, ip %s, expected: %s, got %s", key[:], in, out, o)
			}
		}
	}
}

func TestDecrypt(t *testing.T) {
	for key, ips := range testVectors {
		for out, in := range ips {
			o := net.ParseIP(in)
			Decrypt(key, o, o)
			if !net.ParseIP(out).Equal(o) {
				t.Errorf("Invalid IP conversion for key %x, ip %s, expected: %s, got %s", key[:], in, out, o)
			}
		}
	}
}

func TestEncryptMega(t *testing.T) {
	for key, ips := range megaTestVectors {
		for in, out := range ips {
			o := net.ParseIP(in)
			for i := 0; i < 100000000; i++ {
				Encrypt(key, o, o)
			}
			if !net.ParseIP(out).Equal(o) {
				t.Fatalf("Encryption failed for key % x; ip %s; expected %s; got %s", key[:], in, out, o)
			}
		}
	}
}

func TestDecryptMega(t *testing.T) {
	for key, ips := range megaTestVectors {
		for out, in := range ips {
			o := net.ParseIP(in)
			for i := 0; i < 100000000; i++ {
				Decrypt(key, o, o)
			}
			if !net.ParseIP(out).Equal(o) {
				t.Fatalf("Encryption failed for key % x; ip %s; expected %s; got %s", key[:], in, out, o)
			}
		}
	}
}
