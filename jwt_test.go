package jwt

import (
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"
)

var token []byte
var decoded JWT
var publicKey ed25519.PublicKey
var content map[string]interface{}

func TestSetup(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate keys for testing: %s", err.Error())
	}
	Setup(key)

	if !reflect.DeepEqual(privateKey, key) {
		t.Fatalf("Private key was not set by setup")
	}
	if !setup {
		t.Fatalf("Setup was not set to true by setup")
	}
	privateKey = nil
	setup = false
}

func TestEnc(t *testing.T) {
	content = make(map[string]interface{})
	content["test1"] = "Hello world"
	content["test2"] = "Testing"
	content["exp"] = time.Now().Add(10 * time.Minute)
	content["nbf"] = time.Now()
	jwt := New(content)
	_, err := jwt.Encode()
	if err == nil || err.Error() != "call setup with private key first" {
		t.Fatalf("Encode should fail due to missing private key")
	}
	public, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate keys for testing: %s", err.Error())
	}
	publicKey = public
	Setup(priv)
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
	m := decoded.Content.(map[string]interface{})
	if m["test1"] != content["test1"] {
		t.Fatal("Decoded content does not match original token")
	}
	dec, err = Decode("A.B")
	if err == nil || err.Error() != "invalid token" {
		t.Fatalf("Token with wrong section count was accepted")
	}
	dec, err = Decode("A")
	if err == nil || err.Error() != "invalid token" {
		t.Fatalf("Token with wrong section count was accepted")
	}
	dec, err = Decode("A.B.C.D")
	if err == nil || err.Error() != "invalid token" {
		t.Fatalf("Token with wrong section count was accepted")
	}
	dec, err = Decode("A._._")
	if err == nil {
		t.Fatalf("Invalid base64 data accepted when decoding header")
	}
	dec, err = Decode("YQ._._")
	if err == nil {
		t.Fatalf("Invalid JSON accepted when decoding header")
	}
	dec, err = Decode("eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJlZDI1NTE5In0.A._")
	if err == nil {
		t.Fatalf("Invalid base64 data accepted when decoding content")
	}
	dec, err = Decode("eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJlZDI1NTE5In0.YQ._")
	if err == nil {
		t.Fatalf("Invalid JSON accepted when decoding content")
	}
	dec, err = Decode("eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJlZDI1NTE5In0.IkhlbGxvIHdvcmxkISI.A")
	if err == nil {
		t.Fatalf("Invalid base64 data accepted when decoding hash")
	}
}

func TestValidation(t *testing.T) {
	// Validate test JWT (should always be valid)
	err := decoded.Validate(publicKey)
	if err != nil {
		t.Fatalf("Failed to validate JWT: %s", err.Error())
	}

	// Check that validation fails if token is not JWT
	token := JWT{Header{"token", "none"}, nil, nil}
	err = token.Validate(publicKey)
	if err == nil || err.Error() != "header indicates token is not JWT" {
		t.Fatalf("Failed to detect token is not JWT")
	}

	// Check that validation fails for unsupported algorithms
	token = JWT{Header{"JWT", "none"}, nil, nil}
	err = token.Validate(publicKey)
	if err == nil {
		t.Fatalf("Failed to detect unsupported algorithm")
	}

	// Check that validation fails with wrong public key
	wrongKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key for testing: %s", err.Error())
	}
	err = decoded.Validate(wrongKey)
	if err == nil {
		t.Fatalf("Validating succeded with invalid public key")
	}

	// Check validation of expiry
	expired := make(map[string]interface{})
	expired["exp"] = time.Now().Add(-10 * time.Minute).UTC().Unix()
	expiredToken := New(expired)
	enc, err := expiredToken.Encode()
	if err != nil {
		t.Fatalf("Failed to encode token to validate expiry: %s", err.Error())
	}
	dec, err := Decode(string(enc))
	if err != nil {
		t.Fatalf("Failed to decode token to validate expiry: %s", err.Error())
	}
	err = dec.Validate(publicKey)
	if err == nil || err.Error() != "jwt has expired" {
		t.Fatalf("Expired token not detected by validate")
	}

	// Check validation of not before
	nbf := make(map[string]interface{})
	nbf["nbf"] = time.Now().Add(10 * time.Minute).UTC().Unix()
	nbfToken := New(nbf)
	enc, err = nbfToken.Encode()
	if err != nil {
		t.Fatalf("Failed to encode token to validate not before: %s", err.Error())
	}
	dec, err = Decode(string(enc))
	if err != nil {
		t.Fatalf("Failed to decode token to validate not before: %s", err.Error())
	}
	err = dec.Validate(publicKey)
	if err == nil || err.Error() != "jwt is not valid, yet" {
		t.Fatalf("Validate missed that token is not valid, yet")
	}
}
