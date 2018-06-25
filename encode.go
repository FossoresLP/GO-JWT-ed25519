package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/ed25519"
)

// New JWT for the subject
func New(content interface{}) (data JWT, err error) {
	data.Header = Header{Alg: "ed25519", Typ: "JWT"}
	data.Content = content
	return
}

// Encode a JWT to a byte slice
func (t *JWT) Encode() (result []byte, err error) {
	if !setup {
		return nil, errors.New("Initialize with public and private key before encoding")
	}
	content, err := encode(&t.Content)
	if err != nil {
		return
	}
	header, err := encode(&t.Header)
	if err != nil {
		return
	}
	hash, err := b64encode(ed25519.Sign(privateKey, join(header, content)))
	if err != nil {
		return
	}
	result = join(header, content, hash)
	return
}

func b64encode(data []byte) (out []byte, err error) {
	encodedData := &bytes.Buffer{}
	encoder := base64.NewEncoder(base64.URLEncoding.WithPadding(base64.NoPadding), encodedData)
	_, err = encoder.Write(data)
	if err != nil {
		return
	}
	encoder.Close()
	out = encodedData.Bytes()
	return
}

func encode(data interface{}) (out []byte, err error) {
	json, err := json.Marshal(data)
	if err != nil {
		return
	}
	out, err = b64encode(json)
	if err != nil {
		return
	}
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
