package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/ed25519"
)

// FromString decodes a string to a JWT and checks it for validity
func FromString(token string) (data JWT, err error) {
	// Split the JWT into it's sections (header, content, hash)
	sections := strings.Split(token, ".")
	if len(sections) != 3 {
		err = errors.New("jwt: Invalid token")
		return
	}
	// Decode the sections individually using base64
	header, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(sections[0])
	if err != nil {
		return
	}
	content, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(sections[1])
	if err != nil {
		return
	}
	hash, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(sections[2])
	if err != nil {
		return
	}
	// Create variables for header and content data
	var (
		headerStruct  Header
		contentStruct Content
	)
	// Decode header and content into structs
	err = json.Unmarshal(header, &headerStruct)
	if err != nil {
		return
	}
	err = json.Unmarshal(content, &contentStruct)
	if err != nil {
		return
	}
	// Validate content of header and content
	data.Header = headerStruct
	data.Content = contentStruct
	data.Valid = true
	if !hashValid(sections[0], sections[1], hash) {
		data.Problem += "hash"
		data.Valid = false
	}
	if valid, problem := contentValid(contentStruct); !valid {
		data.Problem += problem
		data.Valid = false
	}
	return
}

// Validate the data contained in the header and content of the JWT using the hash and public key
func hashValid(header string, content string, hash []byte) (valid bool) {
	// Combine header and string in base64 encoding with a dot in between
	data := []byte(strings.Join([]string{header, content}, "."))
	// Check the hash using the public key
	valid = ed25519.Verify(keys.PublicKey, data, hash)
	return
}

// Validate the actual content of the JWT by checking issuer, expiry date, ...
func contentValid(content Content) (valid bool, problem string) {
	// Parse expiry date
	exp := time.Unix(content.Exp, 0)
	// Check if token expired
	if exp.Before(time.Now()) {
		valid = false
		return
	}
	// Parse not before
	nbf := time.Unix(content.Nbf, 0)
	// Check if token is already valid
	if nbf.After(time.Now()) {
		valid = false
		return
	}
	valid = true
	return
}
