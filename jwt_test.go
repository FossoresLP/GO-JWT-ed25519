package jwt

import (
	"testing"

	"golang.org/x/crypto/ed25519"
)

var token []byte
var decoded JWT
var publicKey ed25519.PublicKey

func TestEnc(t *testing.T) {
	public, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate keys for testing: %s", err.Error())
	}
	publicKey = public
	Setup(priv)
	jwt, err := New("hello world")
	if err != nil {
		t.Fatalf("Failed to create new JWT: %s", err.Error())
	}
	enc, err := jwt.Encode()
	if err != nil {
		t.Fatalf("Failed to encode JWT: %s", err.Error())
	}
	t.Log("Encoded JWT: " + string(enc) + "\n")
	token = enc
}

func TestDec(t *testing.T) {
	dec, err := Decode(string(token))
	if err != nil {
		t.Fatalf("Failed to decode JWT: %s", err.Error())
	}
	decoded = dec
	if decoded.Content != "hello world" {
		t.Fatal("Decoded content does not match original token")
	}
}

func TestValidation(t *testing.T) {
	err := decoded.Validate(publicKey)
	if err != nil {
		t.Fatalf("Failed to validate JWT: %s", err.Error())
	}
}
