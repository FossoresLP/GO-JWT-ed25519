package jwt

// Header contains the header data of a JSON web token
type Header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

// JWT contains the header and content of a JSON web token as well booleans indicating the validity of the token
type JWT struct {
	Header  Header
	Content interface{}
	Hash    []byte
}
