package jwt

// Header contains the header data of a JSON web token
type Header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Jku string `json:"jku,omitempty"`
}

// JWT contains the header and content of a JSON web token as well as the decoded hash
type JWT struct {
	Header  Header
	Content interface{}
	Hash    []byte
}
