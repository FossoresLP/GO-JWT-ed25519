package jwt

import (
	"reflect"
	"testing"
)

func TestDecode(t *testing.T) {
	type args struct {
		token string
	}
	tests := []struct {
		name     string
		args     args
		wantData JWT
		wantErr  bool
	}{
		{"Normal", args{"eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ.T-hYNlqUtE8KJvyX2JNWXYazh6Srn9w3wb2C7e-1Y9pGwxc4Ym3nUaPGRibt5XaAyJq9BJ5Usg86Nk2zdIM1Ag"}, JWT{Header{Typ: "JWT", Alg: "EdDSA"}, map[string]interface{}{"name": "test", "use": "testing"}, []byte{0x4f, 0xe8, 0x58, 0x36, 0x5a, 0x94, 0xb4, 0x4f, 0xa, 0x26, 0xfc, 0x97, 0xd8, 0x93, 0x56, 0x5d, 0x86, 0xb3, 0x87, 0xa4, 0xab, 0x9f, 0xdc, 0x37, 0xc1, 0xbd, 0x82, 0xed, 0xef, 0xb5, 0x63, 0xda, 0x46, 0xc3, 0x17, 0x38, 0x62, 0x6d, 0xe7, 0x51, 0xa3, 0xc6, 0x46, 0x26, 0xed, 0xe5, 0x76, 0x80, 0xc8, 0x9a, 0xbd, 0x4, 0x9e, 0x54, 0xb2, 0xf, 0x3a, 0x36, 0x4d, 0xb3, 0x74, 0x83, 0x35, 0x2}}, false},
		{"TwoSections", args{"A.B"}, JWT{}, true},
		{"OneSection", args{"A"}, JWT{}, true},
		{"FourSections", args{"A.B.C.D"}, JWT{}, true},
		{"HeaderInvalidBase64", args{"A._._"}, JWT{}, true},
		{"HeaderInvalidJSON", args{"YQ._._"}, JWT{}, true},
		{"TokenNotJWT", args{"eyJ0eXAiOiJub25lIiwiYWxnIjoibm9uZSJ9._._"}, JWT{}, true},
		{"ContentInvalidBase64", args{"eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJlZDI1NTE5In0.A._"}, JWT{}, true},
		{"ContentInvalidJSON", args{"eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJlZDI1NTE5In0.YQ._"}, JWT{}, true},
		{"HashInvalidBase64", args{"eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJlZDI1NTE5In0.IkhlbGxvIHdvcmxkISI.A"}, JWT{}, true},
		{"HashEmpty", args{"eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJlZDI1NTE5In0.IkhlbGxvIHdvcmxkISI."}, JWT{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotData, err := Decode(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(gotData, tt.wantData) {
				t.Errorf("Decode() = %v, want %v", gotData, tt.wantData)
			}
		})
	}
}
