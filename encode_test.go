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
		//{"ShouldFail", args{nil}, nil, true}, //Find something that could make the JSON encoder fail
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
