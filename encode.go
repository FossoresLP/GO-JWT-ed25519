package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/satori/go.uuid"
	"golang.org/x/crypto/ed25519"
)

// Encode a struct of type JWTContent to a JSON web token string
func Encode(content Content) (token string) {
	var data JWT
	data.Header = Header{Alg: "ed25519", Typ: "JWT"}
	content.Iss = "BtS"
	content.Iat = time.Now().Unix()
	content.Jti = uuid.NewV4().String()
	content.Aud = "ChatClient"
	content.Exp = time.Now().Add(time.Duration(604800) * time.Second).Unix()
	content.Nbf = time.Now().Unix()
	data.Content = content
	header, err := json.Marshal(&data.Header)
	var b64header string
	if err == nil {
		b64header = base64.URLEncoding.EncodeToString(header)
	}
	jsonContent, err := json.Marshal(&data.Content)
	var b64content string
	if err == nil {
		b64content = base64.URLEncoding.EncodeToString(jsonContent)
	}
	if b64header != "" && b64content != "" {
		tokenData := strings.Join([]string{b64header, b64content}, ".")
		hash := ed25519.Sign(keys.PrivateKey, []byte(tokenData))
		b64hash := base64.URLEncoding.EncodeToString(hash)
		token = strings.Join([]string{b64header, b64content, b64hash}, ".")
	}
	return
}
