package jwt

import (
	"errors"

	"golang.org/x/crypto/ed25519"
)

// Valid returns whether the JWT matches the hash
func (jwt *JWT) Valid(key ed25519.PublicKey) (bool, error) {
	if jwt.Header.Alg != "ed25519" {
		return false, errors.New("could not validate JWT - algorithm not supported")
	}

	// Encode header and content
	header, err := encode(jwt.Header)
	if err != nil {
		return false, err
	}
	content, err := encode(jwt.Content)
	if err != nil {
		return false, err
	}
	data := join(header, content)

	// Check the hash using the public key
	if !ed25519.Verify(key, data, jwt.Hash) {
		return false, errors.New("hash does not match content")
	}
	return true, nil
}
