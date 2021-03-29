package ipcipher_test

import (
	"fmt"
	"net"

	"github.com/silkeh/ipcipher"
)

func ExampleEncrypt() {
	key := ipcipher.GenerateKeyFromPassword("ipcipher")
	src := net.ParseIP("127.0.0.1")
	dst := net.IPv4zero
	ipcipher.Encrypt(key, dst, src)
	fmt.Printf("%s encrypted to %s\n", src, dst)
	// Output: 127.0.0.1 encrypted to 215.184.24.73
}
