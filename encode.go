package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"

	"golang.org/x/crypto/ed25519"
)

// New returns a new JWT containing content
// Content has to be either a struct or a map with string keys
func New(content interface{}) (JWT, error) {
	if (reflect.TypeOf(content).Kind() != reflect.Struct && reflect.TypeOf(content).Kind() != reflect.Map) || (reflect.TypeOf(content).Kind() == reflect.Map && reflect.TypeOf(content).Key().Kind() != reflect.String) {
		return JWT{}, errors.New("content has to be map[string] or a struct")
	}
	return JWT{Header{Alg: "EdDSA", Typ: "JWT"}, content, nil}, nil
}

// NewWithKeyID returns a new JWT containing content with key ID inserted into the header
func NewWithKeyID(content interface{}, keyID string) (out JWT, err error) {
	if keyID == "" {
		return out, errors.New("empty key IDs are not supported")
	}
	out, err = New(content)
	if err != nil {
		return
	}
	out.Header.Kid = keyID
	return
}

// NewWithKeyIDAndKeyURL returns a new JWT containing content with key ID and key URL inserted into the header
func NewWithKeyIDAndKeyURL(content interface{}, keyID, keyURL string) (out JWT, err error) {
	if keyID == "" {
		return out, errors.New("empty key IDs are not supported")
	}
	if len(keyURL) < 13 || keyURL[:8] != "https://" {
		return out, errors.New("valid URL with HTTPS required")
	}
	out, err = New(content)
	if err != nil {
		return
	}
	out.Header.Jku = keyURL
	out.Header.Kid = keyID
	return
}

// Encode a JWT to a byte slice
func (t *JWT) Encode() (result []byte, err error) {
	if !setup {
		return nil, errors.New("call setup with private key first")
	}
	content, err := encode(t.Content)
	if err != nil {
		return
	}
	header := encodeHeader(t.Header)
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

func encodeHeader(h Header) []byte {
	enc, _ := encode(h) // Error is safe to ignore as encoding a struct containing only strings can't fail
	return enc
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
