package jwt

import (
	"golang.org/x/crypto/ed25519"
)

var privateKey ed25519.PrivateKey
var setup = false

// Setup initializes the package for encoding by setting the public and private key
func Setup(key ed25519.PrivateKey) {
	privateKey = key
	setup = true
}
