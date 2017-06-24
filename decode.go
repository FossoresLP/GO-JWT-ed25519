package jwt

import (
	"errors"
	"strings"
	"time"
	"encoding/base64"
	"encoding/json"
	"golang.org/x/crypto/ed25519"
)

// Decode a JWT and provide it's contents along with data about it's validity
func Decode(token string) (data JWT, err error) {
	// Split the JWT into it's sections (header, content, hash)
	sections := strings.Split(token, ".")
	if (len(sections) != 3) {
		err = errors.New("jwt: Invalid token")
		return
	}
	// Decode the sections individually using base64
	header, err := base64.URLEncoding.DecodeString(sections[0])
	if (err != nil) {
		return
	}
	content, err := base64.URLEncoding.DecodeString(sections[1])
	if (err != nil) {
		return
	}
	hash, err := base64.URLEncoding.DecodeString(sections[2])
	if (err != nil) {
		return
	}
	// Create variables for header and content data
	var (
		headerStruct JWTHeader
		contentStruct JWTContent
	)
	// Decode header and content into structs
	json.Unmarshal(header, &headerStruct)
	json.Unmarshal(content, &contentStruct)
	// Validate content of header and content
	if (validateData(sections[0], sections[1], hash) && validateContent(contentStruct)) {
		data.Valid = true
	} else {
		data.Valid = false
	}
	data.Header = headerStruct
	data.Content = contentStruct
	data.Invalid[0] = validateData(sections[0], sections[1], hash)
	data.Invalid[1] = validateContent(contentStruct)
	return
}

// Validate the data contained in the header and content of the JWT using the hash and public key
func validateData(header string, content string, hash []byte) (valid bool) {
	// Combine header and string in base64 encoding with a dot in between
	data := []byte(strings.Join([]string{header, content}, "."))
	// Check the hash using the public key
	valid = ed25519.Verify(keys.PublicKey, data, hash)
	return
}

// Validate the actual content of the JWT by checking issuer, expiry date, ...
func validateContent(content JWTContent) (valid bool) {
	// Parse expiry date
	exp := time.Unix(content.Exp, 0)
	// Check if token expired
	if (exp.Before(time.Now())) {
		valid = false
		return
	}
	// Parse not before
	nbf := time.Unix(content.Nbf, 0)
	// Check if token is already valid
	if (nbf.After(time.Now())) {
		valid = false
		return
	}
	// Check if we issued the token
	if (content.Iss != "BtS") {
		valid = false
		return
	}
	// Parse Issued At
	iat := time.Unix(content.Iat, 0)
	// Check if the token was issued within the last 7 days
	if (time.Since(iat).Seconds() > 604800.0) {
		valid = false
		return
	}
	// Check if the token is on our blacklist
	if (content.Jti == "blacklist") {
		valid = false
		return
	}
	valid = true
	return
}
