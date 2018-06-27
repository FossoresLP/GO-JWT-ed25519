package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// Decode decodes a string to a JWT and checks it for validity
func Decode(token string) (data JWT, err error) {
	// Split the JWT into it's sections (header, content, hash)
	sections := strings.Split(token, ".")
	if len(sections) != 3 {
		err = errors.New("invalid token")
		return
	}

	// Decode first section to header
	headerData, err := base64.RawURLEncoding.DecodeString(sections[0])
	if err != nil {
		return
	}
	err = json.Unmarshal(headerData, &data.Header)
	if err != nil {
		return
	}

	// Decode second section to content
	contentData, err := base64.RawURLEncoding.DecodeString(sections[1])
	if err != nil {
		return
	}
	err = json.Unmarshal(contentData, &data.Content)
	if err != nil {
		return
	}

	// Decode third section to hash
	data.Hash, err = base64.RawURLEncoding.DecodeString(sections[2])
	if err != nil {
		return
	}

	return
}
