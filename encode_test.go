package jwt

import (
	"reflect"
	"testing"
)

func Test_encode(t *testing.T) {
	type args struct {
		data interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantOut []byte
		wantErr bool
	}{
		{"String", args{"Hello world!"}, []byte("IkhlbGxvIHdvcmxkISI"), false},
		{"Map", args{map[string]string{"name": "test", "use": "testing"}}, []byte("eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ"), false},
		{"ShouldFail", args{func(test int) bool {
			return test == 20
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOut, err := encode(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotOut, tt.wantOut) {
				t.Errorf("encode() = %v, want %v", gotOut, tt.wantOut)
			}
		})
	}
}

func Test_join(t *testing.T) {
	type args struct {
		b [][]byte
	}
	tests := []struct {
		name       string
		args       args
		wantResult []byte
	}{
		{"Zero", args{nil}, nil},
		{"Single", args{[][]byte{[]byte("test")}}, []byte("test")},
		{"Two", args{[][]byte{[]byte("test1"), []byte("test2")}}, []byte("test1.test2")},
		{"Three", args{[][]byte{[]byte("test1"), []byte("test2"), []byte("test3")}}, []byte("test1.test2.test3")},
		{"Empty", args{[][]byte{[]byte("test1"), []byte(""), []byte("test3")}}, []byte("test1..test3")},
		{"Empty_Beginning", args{[][]byte{[]byte(""), []byte("test2"), []byte("test3")}}, []byte(".test2.test3")},
		{"Empty_End", args{[][]byte{[]byte("test1"), []byte("test2"), []byte("")}}, []byte("test1.test2.")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotResult := join(tt.args.b...); !reflect.DeepEqual(gotResult, tt.wantResult) {
				t.Errorf("join() = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}

func Test_b64encode(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		wantOut []byte
	}{
		{"Data", args{[]byte("{\"testing\": \"JSON\", \"with\": 3.0, \"elements\": true}")}, []byte("eyJ0ZXN0aW5nIjogIkpTT04iLCAid2l0aCI6IDMuMCwgImVsZW1lbnRzIjogdHJ1ZX0")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotOut := b64encode(tt.args.data); !reflect.DeepEqual(gotOut, tt.wantOut) {
				t.Errorf("b64encode() = %v, want %v", gotOut, tt.wantOut)
			}
		})
	}
}

func TestNew(t *testing.T) {
	type args struct {
		content interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    JWT
		wantErr bool
	}{
		{"Normal", args{map[string]interface{}{"test": "normal"}}, JWT{Header{Typ: "JWT", Alg: "EdDSA"}, map[string]interface{}{"test": "normal"}, nil}, false},
		{"ContentString", args{"test"}, JWT{}, true},
		{"ContentInt", args{123456789}, JWT{}, true},
		{"ContentIntMap", args{map[int]string{123: "test"}}, JWT{}, true},
		{"ContentStringMapOfStrings", args{map[string]string{"test": "normal"}}, JWT{Header{Typ: "JWT", Alg: "EdDSA"}, map[string]string{"test": "normal"}, nil}, false},
		{"ContentStruct", args{Header{Typ: "none", Alg: "none"}}, JWT{Header{Typ: "JWT", Alg: "EdDSA"}, Header{Typ: "none", Alg: "none"}, nil}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewWithKeyID(t *testing.T) {
	type args struct {
		content interface{}
		keyID   string
	}
	tests := []struct {
		name    string
		args    args
		wantOut JWT
		wantErr bool
	}{
		{"Normal", args{map[string]interface{}{"test": "normal"}, "unique_key_id"}, JWT{Header{Typ: "JWT", Alg: "EdDSA", Kid: "unique_key_id"}, map[string]interface{}{"test": "normal"}, nil}, false},
		{"InvalidContent", args{"test", "unique_key_id"}, JWT{}, true},
		{"InvalidKeyID", args{map[string]interface{}{"test": "normal"}, ""}, JWT{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOut, err := NewWithKeyID(tt.args.content, tt.args.keyID)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewWithKeyID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotOut, tt.wantOut) {
				t.Errorf("NewWithKeyID() = %v, want %v", gotOut, tt.wantOut)
			}
		})
	}
}

func TestNewWithKeyIDAndKeyURL(t *testing.T) {
	type args struct {
		content interface{}
		keyID   string
		keyURL  string
	}
	tests := []struct {
		name    string
		args    args
		wantOut JWT
		wantErr bool
	}{
		{"Normal", args{map[string]interface{}{"test": "normal"}, "unique_key_id", "https://example.com/get_keys"}, JWT{Header{Typ: "JWT", Alg: "EdDSA", Kid: "unique_key_id", Jku: "https://example.com/get_keys"}, map[string]interface{}{"test": "normal"}, nil}, false},
		{"ContentInvalid", args{"test", "unique_key_id", "https://example.com/get_keys"}, JWT{}, true},
		{"EmptyKeyIDNotAllowed", args{map[string]interface{}{"test": "normal"}, "", "https://example.com/get_keys"}, JWT{}, true},
		{"KeyURLTooShort", args{map[string]interface{}{"test": "normal"}, "unique_key_id", "https://a.b"}, JWT{}, true},
		{"KeyURLMustBeHTTPS", args{map[string]interface{}{"test": "normal"}, "unique_key_id", "ftps://example.com/get_keys"}, JWT{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOut, err := NewWithKeyIDAndKeyURL(tt.args.content, tt.args.keyID, tt.args.keyURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewWithKeyIDAndKeyURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotOut, tt.wantOut) {
				t.Errorf("NewWithKeyIDAndKeyURL() = %v, want %v", gotOut, tt.wantOut)
			}
		})
	}
}
