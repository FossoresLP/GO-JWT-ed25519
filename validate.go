package jwt

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ed25519"
)

// Validate returns an error when the hash does not match the content
func (jwt *JWT) Validate(key ed25519.PublicKey) error {
	if jwt.Header.Alg != "ed25519" {
		return fmt.Errorf("could not validate JWT - algorithm %s not supported", jwt.Header.Alg)
	}

	// Encode header and content
	header, err := encode(jwt.Header)
	if err != nil {
		return err
	}
	content, err := encode(jwt.Content)
	if err != nil {
		return err
	}
	data := join(header, content)

	// Check the hash using the public key
	if !ed25519.Verify(key, data, jwt.Hash) {
		return errors.New("hash does not match content")
	}
	return nil
}
