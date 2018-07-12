package jwt

import (
	"reflect"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestJWT_MarshalText(t *testing.T) {
	k := ed25519.PrivateKey{0xf3, 0xff, 0x8e, 0x19, 0xd3, 0xb7, 0x15, 0xf0, 0x23, 0xb3, 0xf7, 0x6a, 0x30, 0xbe, 0x5d, 0xc2, 0xea, 0x2, 0xab, 0xa0, 0xdb, 0xf8, 0xe5, 0xda, 0x6, 0xa8, 0xae, 0x9d, 0xf6, 0x74, 0xa0, 0x57, 0xa0, 0x2, 0xd6, 0xd7, 0xf9, 0x55, 0xe7, 0x4, 0x3f, 0x97, 0xf4, 0x9c, 0xe3, 0xb2, 0x85, 0x69, 0x7b, 0x31, 0xf9, 0x49, 0xb4, 0x3b, 0x78, 0x18, 0x40, 0x38, 0xa2, 0xea, 0x88, 0x1b, 0x1e, 0x56}
	Setup(k)
	tests := []struct {
		name    string
		jwt     JWT
		want    []byte
		wantErr bool
	}{
		{"Normal", JWT{Header{Typ: "JWT", Alg: "EdDSA"}, map[string]string{"name": "test", "use": "testing"}, nil}, []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5In0.eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ.JPlhN2BUxUsOWV0uwUI03CgVTiQHhDcHQ26ivtJeLWtn_I8dCA2CRZbkuSg_mg-pl-OEyK1OXurQ8PcUGtB5BQ"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.jwt.MarshalText()
			if (err != nil) != tt.wantErr {
				t.Errorf("JWT.MarshalText() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("JWT.MarshalText() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJWT_UnmarshalText(t *testing.T) {
	type args struct {
		in []byte
	}
	tests := []struct {
		name    string
		jwt     *JWT
		args    args
		wantErr bool
	}{
		{"Normal", &JWT{}, args{[]byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5In0.eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ.JPlhN2BUxUsOWV0uwUI03CgVTiQHhDcHQ26ivtJeLWtn_I8dCA2CRZbkuSg_mg-pl-OEyK1OXurQ8PcUGtB5BQ")}, false},
		{"InvalidToken", &JWT{}, args{[]byte("test")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.jwt.UnmarshalText(tt.args.in); (err != nil) != tt.wantErr {
				t.Errorf("JWT.UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(tt.jwt, &JWT{Header{Typ: "JWT", Alg: "EdDSA"}, map[string]interface{}{"name": "test", "use": "testing"}, []byte{0x24, 0xf9, 0x61, 0x37, 0x60, 0x54, 0xc5, 0x4b, 0xe, 0x59, 0x5d, 0x2e, 0xc1, 0x42, 0x34, 0xdc, 0x28, 0x15, 0x4e, 0x24, 0x7, 0x84, 0x37, 0x7, 0x43, 0x6e, 0xa2, 0xbe, 0xd2, 0x5e, 0x2d, 0x6b, 0x67, 0xfc, 0x8f, 0x1d, 0x8, 0xd, 0x82, 0x45, 0x96, 0xe4, 0xb9, 0x28, 0x3f, 0x9a, 0xf, 0xa9, 0x97, 0xe3, 0x84, 0xc8, 0xad, 0x4e, 0x5e, 0xea, 0xd0, 0xf0, 0xf7, 0x14, 0x1a, 0xd0, 0x79, 0x5}}) {
				t.Errorf("JWT.UnmarshalText() = %+v, want %+v", tt.jwt, &JWT{Header{Typ: "JWT", Alg: "EdDSA"}, map[string]interface{}{"name": "test", "use": "testing"}, []byte{0x24, 0xf9, 0x61, 0x37, 0x60, 0x54, 0xc5, 0x4b, 0xe, 0x59, 0x5d, 0x2e, 0xc1, 0x42, 0x34, 0xdc, 0x28, 0x15, 0x4e, 0x24, 0x7, 0x84, 0x37, 0x7, 0x43, 0x6e, 0xa2, 0xbe, 0xd2, 0x5e, 0x2d, 0x6b, 0x67, 0xfc, 0x8f, 0x1d, 0x8, 0xd, 0x82, 0x45, 0x96, 0xe4, 0xb9, 0x28, 0x3f, 0x9a, 0xf, 0xa9, 0x97, 0xe3, 0x84, 0xc8, 0xad, 0x4e, 0x5e, 0xea, 0xd0, 0xf0, 0xf7, 0x14, 0x1a, 0xd0, 0x79, 0x5}})
			}
		})
	}
}

func TestJWT_MarshalBinary(t *testing.T) {
	k := ed25519.PrivateKey{0xf3, 0xff, 0x8e, 0x19, 0xd3, 0xb7, 0x15, 0xf0, 0x23, 0xb3, 0xf7, 0x6a, 0x30, 0xbe, 0x5d, 0xc2, 0xea, 0x2, 0xab, 0xa0, 0xdb, 0xf8, 0xe5, 0xda, 0x6, 0xa8, 0xae, 0x9d, 0xf6, 0x74, 0xa0, 0x57, 0xa0, 0x2, 0xd6, 0xd7, 0xf9, 0x55, 0xe7, 0x4, 0x3f, 0x97, 0xf4, 0x9c, 0xe3, 0xb2, 0x85, 0x69, 0x7b, 0x31, 0xf9, 0x49, 0xb4, 0x3b, 0x78, 0x18, 0x40, 0x38, 0xa2, 0xea, 0x88, 0x1b, 0x1e, 0x56}
	Setup(k)
	tests := []struct {
		name    string
		jwt     JWT
		want    []byte
		wantErr bool
	}{
		{"Normal", JWT{Header{Typ: "JWT", Alg: "EdDSA"}, map[string]string{"name": "test", "use": "testing"}, nil}, []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5In0.eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ.JPlhN2BUxUsOWV0uwUI03CgVTiQHhDcHQ26ivtJeLWtn_I8dCA2CRZbkuSg_mg-pl-OEyK1OXurQ8PcUGtB5BQ"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.jwt.MarshalBinary()
			if (err != nil) != tt.wantErr {
				t.Errorf("JWT.MarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("JWT.MarshalBinary() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJWT_UnmarshalBinary(t *testing.T) {
	type args struct {
		in []byte
	}
	tests := []struct {
		name    string
		jwt     *JWT
		args    args
		wantErr bool
	}{
		{"Normal", &JWT{}, args{[]byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5In0.eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ.JPlhN2BUxUsOWV0uwUI03CgVTiQHhDcHQ26ivtJeLWtn_I8dCA2CRZbkuSg_mg-pl-OEyK1OXurQ8PcUGtB5BQ")}, false},
		{"InvalidToken", &JWT{}, args{[]byte("test")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.jwt.UnmarshalBinary(tt.args.in); (err != nil) != tt.wantErr {
				t.Errorf("JWT.UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(tt.jwt, &JWT{Header{Typ: "JWT", Alg: "EdDSA"}, map[string]interface{}{"name": "test", "use": "testing"}, []byte{0x24, 0xf9, 0x61, 0x37, 0x60, 0x54, 0xc5, 0x4b, 0xe, 0x59, 0x5d, 0x2e, 0xc1, 0x42, 0x34, 0xdc, 0x28, 0x15, 0x4e, 0x24, 0x7, 0x84, 0x37, 0x7, 0x43, 0x6e, 0xa2, 0xbe, 0xd2, 0x5e, 0x2d, 0x6b, 0x67, 0xfc, 0x8f, 0x1d, 0x8, 0xd, 0x82, 0x45, 0x96, 0xe4, 0xb9, 0x28, 0x3f, 0x9a, 0xf, 0xa9, 0x97, 0xe3, 0x84, 0xc8, 0xad, 0x4e, 0x5e, 0xea, 0xd0, 0xf0, 0xf7, 0x14, 0x1a, 0xd0, 0x79, 0x5}}) {
				t.Errorf("JWT.UnmarshalText() = %+v, want %+v", tt.jwt, &JWT{Header{Typ: "JWT", Alg: "EdDSA"}, map[string]interface{}{"name": "test", "use": "testing"}, []byte{0x24, 0xf9, 0x61, 0x37, 0x60, 0x54, 0xc5, 0x4b, 0xe, 0x59, 0x5d, 0x2e, 0xc1, 0x42, 0x34, 0xdc, 0x28, 0x15, 0x4e, 0x24, 0x7, 0x84, 0x37, 0x7, 0x43, 0x6e, 0xa2, 0xbe, 0xd2, 0x5e, 0x2d, 0x6b, 0x67, 0xfc, 0x8f, 0x1d, 0x8, 0xd, 0x82, 0x45, 0x96, 0xe4, 0xb9, 0x28, 0x3f, 0x9a, 0xf, 0xa9, 0x97, 0xe3, 0x84, 0xc8, 0xad, 0x4e, 0x5e, 0xea, 0xd0, 0xf0, 0xf7, 0x14, 0x1a, 0xd0, 0x79, 0x5}})
			}
		})
	}
}
