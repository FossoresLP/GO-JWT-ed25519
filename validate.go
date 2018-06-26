package jwt

import (
	"time"
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

	// Validate expiry and not before if they exist
	m := jwt.Content.(map[string]interface{})
	if exp, ok := m["exp"].(int64); ok {
		if time.Unix(exp, 0).Before(time.Now()) {
			return errors.New("jwt has expired")
		}
	}
	if nbf, ok := m["nbf"].(int64); ok {
		if time.Unix(nbf, 0).After(time.Now()) {
			return errors.New("jwt is not valid, yet")
		}
	}

	return nil
}
