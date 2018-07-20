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
	jwt := JWT{Header{Typ: "JWT", Alg: "EdDSA"}, map[string]interface{}{"test1": "Hello world", "test2": "Testing", "exp": time.Now().Add(10 * time.Minute), "nbf": time.Now()}, nil}
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
	jwt = JWT{Header{Typ: "JWT", Alg: "EdDSA"}, func(test int) bool {
		return test == 20
	}, nil}
	_, err = jwt.Encode()
	if err == nil {
		t.Fatal("JSON encoder accepted function")
	}
}

func TestDec(t *testing.T) {
	dec, err := Decode(string(token))
	if err != nil {
		t.Fatalf("Failed to decode JWT: %s", err.Error())
	}
	decoded = dec
	m := decoded.Content.(map[string]interface{})
	if m["test1"] != "Hello world" {
		t.Fatal("Decoded content does not match original token")
	}
}

func TestValidation(t *testing.T) {
	// Validate test JWT (should always be valid)
	err := decoded.Validate(publicKey)
	if err != nil {
		t.Fatalf("Failed to validate JWT: %s", err.Error())
	}

	// Check that an invalid public key does not cause a panic
	token := JWT{Header{}, nil, nil}
	err = token.Validate([]byte("Hello world!"))
	if err == nil || err.Error() != "key is not a valid public key" {
		t.Fatalf("Failed to detect public key is not valid")
	}

	// Check that validation fails if token is not JWT
	token = JWT{Header{Typ: "token", Alg: "none"}, nil, nil}
	err = token.Validate(publicKey)
	if err == nil || err.Error() != "header indicates token is not JWT" {
		t.Fatalf("Failed to detect token is not JWT")
	}

	// Check that validation fails for unsupported algorithms
	token = JWT{Header{Typ: "JWT", Alg: "none"}, nil, nil}
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

	// Check that validation succeeds with unsupported content
	token = JWT{Header{Typ: "JWT", Alg: "EdDSA"}, "Hello world!", nil}
	err = token.Validate(publicKey)
	if err != nil {
		t.Fatalf("Validation with unsupported content failed instead of ignoring content: %s", err.Error())
	}
	token = JWT{Header{Typ: "JWT", Alg: "EdDSA"}, 1234567890, nil}
	err = token.Validate(publicKey)
	if err != nil {
		t.Fatalf("Validation with unsupported content failed instead of ignoring content: %s", err.Error())
	}

	// Check validation of expiry
	expiredToken := JWT{Header{Typ: "JWT", Alg: "EdDSA"}, map[string]interface{}{"exp": time.Now().Add(-10 * time.Minute).UTC().Unix()}, nil}
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
	nbfToken := JWT{Header{Typ: "JWT", Alg: "EdDSA"}, map[string]interface{}{"nbf": time.Now().Add(10 * time.Minute).UTC().Unix()}, nil}
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

	// Check error handling for function as content
	functionToken := JWT{Header{Typ: "JWT", Alg: "EdDSA"}, func(test int) bool {
		return test == 20
	}, nil}
	err = functionToken.Validate(publicKey)
	if err == nil {
		t.Fatal("JSON encoder accepted function")
	}
}
