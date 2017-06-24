package jwt

// Header contains the header data of a JSON web token
type Header struct {
	Typ string
	Alg string
}

// Content contains the main content of a JSON web token
type Content struct {
	Iss string
	Sub string
	Aud string
	Exp int64
	Nbf int64
	Iat int64
	Jti string
}

// JWT contains the header and content of a JSON web token as well booleans indicating the validity of the token
type JWT struct {
	Header  Header
	Content Content
	Valid   bool
	Invalid [2]bool
}
