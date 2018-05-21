package jwt

import (
	"testing"

	"github.com/fossoreslp/go-uuid-v4"
)

var token []byte

func TestEnc(t *testing.T) {
	id, err := uuid.New()
	if err != nil {
		t.Errorf("UUID generation failed. This is not a fatal error. Cause: %s\n", err.Error())
	}
	jwt, err := New(id)
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
	data, err := FromString(string(token))
	if err != nil {
		t.Fatalf("Failed to decode JWT: %s", err.Error())
	}
	t.Logf("Decoded JWT: %+v\n", data)
}

func TestKeymanagement(t *testing.T) {
	data, err := FromString("eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5In0.eyJzdWIiOiIxOWQ1MmIyZS05ZWU3LTRmYmEtYjVkMS1kOWQzZmU0MzVkYmYiLCJleHAiOjE1MjcwMDIwNDYsIm5iZiI6MTUyNjkxNTU4NiwianRpIjoiYjMxYjFkMDQtMDhlYi00ZDNjLWE3ZTktYTJkYTA2YjE2NGVmIn0.LfLO6DPTCJC6RGk0Ar3ufnx_wdmVr_Bub3ZhwsS9YASC6CDxX-3i43efhMy9QUt86rLCX75JSIH1h23GBr-nBw")
	if err != nil {
		t.Errorf("Key management not working: %s\n", err.Error())
	}
	t.Logf("Decoded JWT hardcoded into test: %+v\n", data)
}
