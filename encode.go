package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/ed25519"
)

// New returns a new JWT containing content
func New(content interface{}) JWT {
	return JWT{Header{Alg: "ed25519", Typ: "JWT"}, content, nil}
}

// NewWithKeyID returns a new JWT containing content with key ID inserted into the header
func NewWithKeyID(content interface{}, keyID string) (out JWT) {
	out = New(content)
	out.Header.Kid = keyID
	return
}

// NewWithKeyIDAndKeyURL returns a new JWT containing content with key ID and key URL inserted into the header
func NewWithKeyIDAndKeyURL(content interface{}, keyID, keyURL string) (out JWT) {
	out = New(content)
	out.Header.Kid = keyID
	out.Header.Jku = keyURL
	return
}

// Encode a JWT to a byte slice
func (t *JWT) Encode() (result []byte, err error) {
	if !setup {
		return nil, errors.New("call setup with private key first")
	}
	content, err := encode(&t.Content)
	if err != nil {
		return
	}
	header, err := encode(&t.Header)
	if err != nil {
		return
	}
	hash := b64encode(ed25519.Sign(privateKey, join(header, content)))
	result = join(header, content, hash)
	return
}

func b64encode(data []byte) []byte {
	out := make([]byte, base64.RawURLEncoding.EncodedLen(len(data)))
	base64.RawURLEncoding.Encode(out, data)
	return out
}

func encode(data interface{}) (out []byte, err error) {
	json, err := json.Marshal(data)
	if err != nil {
		return
	}
	out = b64encode(json)
	return
}

func join(b ...[]byte) (result []byte) {
	if len(b) <= 0 {
		return
	}
	result = b[0]
	if len(b) == 1 {
		return
	}
	for i := range b {
		if i > 0 {
			result = append(result, '.')
			result = append(result, b[i]...)
		}
	}
	return
}
