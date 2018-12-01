package jwt

import (
	"errors"
	"fmt"
	"math"
	"time"

	"golang.org/x/crypto/ed25519"
)

// Validate returns an error when the hash does not match the content
func (jwt *JWT) Validate(key ed25519.PublicKey) error {
	// Make sure the key is actually valid
	if len(key) != ed25519.PublicKeySize {
		return errors.New("key is not a valid public key")
	}
	// Check token type and algorithm
	if jwt.Header.Typ != "JWT" {
		return errors.New("header indicates token is not JWT")
	}
	if jwt.Header.Alg != "EdDSA" {
		return fmt.Errorf("could not validate JWT - algorithm %s not supported", jwt.Header.Alg)
	}

	// Encode header and content
	header := encodeHeader(jwt.Header)
	content, err := encode(jwt.Content)
	if err != nil {
		return err
	}
	data := join(header, content)

	// Check the hash using the public key
	if jwt.Hash != nil && !ed25519.Verify(key, data, jwt.Hash) {
		return errors.New("hash does not match content")
	}

	// Validate expiry and not before if they exist
	if m, ok := jwt.Content.(map[string]interface{}); ok {
		if exp, ok := m["exp"].(float64); ok {
			if time.Unix(int64(math.Round(exp)), 0).Before(time.Now().UTC()) {
				return errors.New("jwt has expired")
			}
		}
		if nbf, ok := m["nbf"].(float64); ok {
			if time.Unix(int64(math.Round(nbf)), 0).After(time.Now().UTC()) {
				return errors.New("jwt is not valid, yet")
			}
		}
	}

	return nil
}
