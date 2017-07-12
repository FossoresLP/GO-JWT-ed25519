package jwt

// Header contains the header data of a JSON web token
type Header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

// Content contains the main content of a JSON web token
type Content struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
	Nbf int64  `json:"nbf"`
	Jti string `json:"jti"`
}

// JWT contains the header and content of a JSON web token as well booleans indicating the validity of the token
type JWT struct {
	Header  Header
	Content Content
	Valid   bool
	Problem string
}
