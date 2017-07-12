package jwt

import (
	"fmt"
	"testing"

	"github.com/satori/go.uuid"
)

var token []byte

func TestEnc(t *testing.T) {
	jwt := New(uuid.NewV4().String())
	enc, err := jwt.Encode()
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
	fmt.Println(string(enc))
	token = enc
}

func TestDec(t *testing.T) {
	data, err := FromString(string(token))
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
	fmt.Println(data)
}

func TestKeymgmt(t *testing.T) {
	data, err := FromString("eyJUeXAiOiJKV1QiLCJBbGciOiJlZDI1NTE5In0=.eyJJc3MiOiJCdFMiLCJTdWIiOiI2Mzc1YWNhNy00YWI0LTQ3YTUtYmU0ZC03YThlMGE0ZDZkYTAiLCJBdWQiOiJDaGF0Q2xpZW50IiwiRXhwIjoxNDk4MzExNDg3LCJOYmYiOjE0OTc3MDY2ODcsIklhdCI6MTQ5NzcwNjY4NywiSnRpIjoiNDUyMTViNDQtMzZiMi00OGIzLTg0NzItNWU3NmZjNjU0M2NlIn0=.VlD_PHeUm6xJvk-lCP4QUIhNrw5YlR3rz13zodO7-fiAIs6mUwRnxRteTbTTlsWXDE0tKtvBI8xm-_vzPqSvCQ==")
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
	fmt.Println(data)
}
