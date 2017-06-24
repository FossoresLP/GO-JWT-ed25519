package jwt

type JWTHeader struct {
	Typ string
	Alg string
}

type JWTContent struct {
	Iss string
	Sub string
	Aud string
	Exp int64
	Nbf int64
	Iat int64
	Jti string
}

type JWT struct {
	Header JWTHeader
	Content JWTContent
	Valid bool
	Invalid [2]bool
}
