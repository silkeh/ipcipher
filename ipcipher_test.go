package ipcipher

import (
	"bytes"
	"net"
	"testing"
)

var keyTestVectors = map[string][]byte{
	"":                     {0x99, 0xbe, 0x12, 0x3a, 0xc5, 0xf8, 0x67, 0xdb, 0x37, 0x19, 0x3d, 0xb7, 0xae, 0xe6, 0x7e, 0x73},
	"3.141592653589793":    {0x23, 0x07, 0x23, 0x58, 0xad, 0xcb, 0x9b, 0x23, 0x05, 0x57, 0x4e, 0x23, 0x29, 0x1b, 0x40, 0xad},
	"crypto is not a coin": {0xc8, 0x18, 0x0e, 0x56, 0x05, 0x6d, 0x3e, 0xcb, 0xf8, 0x50, 0x50, 0x0b, 0xfd, 0x84, 0x19, 0x3d},
}

var ipv4TestVectors = map[*Key]map[string]string{
	&Key{'s', 'o', 'm', 'e', ' ', '1', '6', '-', 'b', 'y', 't', 'e', ' ', 'k', 'e', 'y'}: {
		"127.0.0.1": "114.62.227.59",
		"8.8.8.8":   "46.48.51.50",
		"1.2.3.4":   "171.238.15.199",
		"::1":       "3718:8853:1723:6c88:7e5f:2e60:c79a:2bf",
		"2001:503:ba3e::2:30": "64d2:883d:ffb5:dd79:24b:943c:22aa:4ae7",
		"2001:DB8::":          "ce7e:7e39:d282:e7b1:1d6d:5ca1:d4de:246f",
	},
	NewKeyFromPassword("crypto is not a coin"): {
		"198.41.0.4":    "78.178.254.81",
		"130.161.180.1": "207.193.250.137",
		"0.0.0.0":       "134.197.67.89",
		"::1":           "2ec1:fa64:6771:a68b:dcb:6cca:8422:5c1c",
		"2001:503:ba3e::2:30": "d8a9:27d7:b9d1:492f:670e:6ffc:e427:fe49",
		"2001:DB8::":          "6709:bdb1:cd1e:354f:ebfb:5775:fb51:8e64",
	},
}

var ipv4MegaTestVectors = map[*Key]map[string]string{
	&Key{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16}: {
		"192.168.69.42": "93.155.197.186",
	},
}

func TestKeyGeneration(t *testing.T) {
	for str, key := range keyTestVectors {
		k := NewKeyFromPassword(str)
		if !bytes.Equal(k[:], key) {
			t.Fatalf("Invalid key for string %q, got:\n% x, expected:\n% x", str, k[:], key)
		}
	}
}

func TestEncrypt(t *testing.T) {
	for key, ips := range ipv4TestVectors {
		for in, out := range ips {
			o, _ := Encrypt(key, net.ParseIP(in))
			if !bytes.Equal(o, net.ParseIP(out)) {
				t.Fatalf("Invalid IP conversion for key %x, ip %s, expected: %s, got %s", key[:], in, out, o)
			}
		}
	}
}

func TestDecrypt(t *testing.T) {
	for key, ips := range ipv4TestVectors {
		for out, in := range ips {
			o, _ := Decrypt(key, net.ParseIP(in))
			if !bytes.Equal(o, net.ParseIP(out)) {
				t.Fatalf("Invalid IP conversion for key %x, ip %s, expected: %s, got %s", key[:], in, out, o)
			}
		}
	}
}

func TestEncryptIPv4Mega(t *testing.T) {
	for key, ips := range ipv4MegaTestVectors {
		for in, out := range ips {
			o := net.ParseIP(in)
			for i := 0; i < 100000000; i++ {
				o, _ = EncryptIPv4(key, o)
			}
			if !bytes.Equal(o, net.ParseIP(out)) {
				t.Fatalf("Encryption failed for key % x; ip %s; expected %s; got %s", key[:], in, out, o)
			}
		}
	}
}
