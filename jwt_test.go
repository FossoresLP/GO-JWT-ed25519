package jwt

import (
	"fmt"
	"testing"
	"github.com/satori/go.uuid"
)

var token string

func TestEnc(t *testing.T) {
	content := JWTContent{Sub: uuid.NewV4().String()}
	if(Encode(content) == "") {
		t.FailNow()
	} else {
		token = Encode(content)
		fmt.Println(token)
	}
}

func TestDec(t *testing.T) {
	data, err := Decode(token)
	if (err != nil) {
		t.FailNow()
	}
	fmt.Println(data)
}

func TestKeymgmt(t *testing.T) {
	data, err := Decode("eyJUeXAiOiJKV1QiLCJBbGciOiJlZDI1NTE5In0=.eyJJc3MiOiJCdFMiLCJTdWIiOiI2Mzc1YWNhNy00YWI0LTQ3YTUtYmU0ZC03YThlMGE0ZDZkYTAiLCJBdWQiOiJDaGF0Q2xpZW50IiwiRXhwIjoxNDk4MzExNDg3LCJOYmYiOjE0OTc3MDY2ODcsIklhdCI6MTQ5NzcwNjY4NywiSnRpIjoiNDUyMTViNDQtMzZiMi00OGIzLTg0NzItNWU3NmZjNjU0M2NlIn0=.VlD_PHeUm6xJvk-lCP4QUIhNrw5YlR3rz13zodO7-fiAIs6mUwRnxRteTbTTlsWXDE0tKtvBI8xm-_vzPqSvCQ==")
	if (err != nil) {
		t.FailNow()
	}
	fmt.Println(data)
}
