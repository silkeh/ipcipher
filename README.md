Package ipcipher
================

[![Go Reference](https://pkg.go.dev/badge/github.com/silkeh/ipcipher.svg)](https://pkg.go.dev/github.com/silkeh/ipcipher)
[![build status](https://travis-ci.org/silkeh/ipcipher.svg?branch=master)](https://travis-ci.org/silkeh/ipcipher)
[![goreportcard](https://goreportcard.com/badge/github.com/silkeh/ipcipher)](https://goreportcard.com/report/github.com/silkeh/ipcipher)
[![gocover](http://gocover.io/_badge/github.com/silkeh/ipcipher)](http://gocover.io/github.com/silkeh/ipcipher)

Package ipcipher implements the [ipcipher specification][],
which can be used for encrypting and decrypting IP addresses.

The package provides simple Encrypt and Decrypt functions, as well as a `block.Cipher`.

See the [documentation][] for examples.

[ipcipher specification]: https://powerdns.org/ipcipher/ipcipher.md.html
[documentation]: https://pkg.go.dev/github.com/silkeh/ipcipher
