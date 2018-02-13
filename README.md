Package ipcipher
================

[![godoc](https://godoc.org/github.com/silkeh/ipcipher?status.svg)](https://godoc.org/github.com/silkeh/ipcipher)
[![build status](https://travis-ci.org/silkeh/ipcipher.svg?branch=master)](https://travis-ci.org/silkeh/ipcipher)
[![goreportcard](https://goreportcard.com/badge/github.com/silkeh/ipcipher)](https://goreportcard.com/report/github.com/silkeh/ipcipher)
[![gocover](http://gocover.io/_badge/github.com/silkeh/ipcipher)](http://gocover.io/github.com/silkeh/ipcipher)

Package ipcipher implements the [ipcipher specification][spec],
which can be used for encrypting and decrypting IP addresses.

The package provides simple Encrypt and Decrypt functions, as well as a `block.Cipher`.

[spec]: https://powerdns.org/ipcipher/ipcipher.md.html

Examples
--------

Basic usage:

```Go
package main

import (
	"fmt"
	"net"

	"github.com/silkeh/ipcipher"
)

func main() {
	key := ipcipher.GenerateKeyFromPassword("ipcipher")
	src := net.ParseIP("127.0.0.1")
	dst := net.IPv6unspecified
	ipcipher.Encrypt(key, dst, src)
	fmt.Printf("%s encrypted to %s\n", src, dst)
}
```

Using `cipher.Block` significantly speeds up encryption of IPv6 addresses:

```Go
package main

import (
	"fmt"
	"net"

	"github.com/silkeh/ipcipher"
)

func main() {
	key := ipcipher.GenerateKeyFromPassword("ipcipher")
	c := ipcipher.New(key)
	ip := net.ParseIP("2001:db8::")

	for i := 0; i < 1000000; i++ {
		c.Encrypt(ip, ip)
	}

	fmt.Printf("Encrypted to %s\n", ip)
}
```
