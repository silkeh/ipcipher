package ipcipher_test

import (
	"fmt"
	"net"

	"github.com/silkeh/ipcipher"
)

func ExampleNew_encrypt() {
	key := ipcipher.GenerateKeyFromPassword("ipcipher")
	c := ipcipher.New(key)
	ip := net.ParseIP("2001:db8::")

	for i := 0; i < 1000000; i++ {
		c.Encrypt(ip, ip)
	}

	fmt.Printf("Encrypted to %s\n", ip)
	// output: Encrypted to fa7d:c4fa:1826:380e:7c88:59cb:9172:f991
}
