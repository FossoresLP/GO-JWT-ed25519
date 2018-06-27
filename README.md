GO JSON Web Token using ed25519
===============================

[![CircleCI branch](https://img.shields.io/circleci/project/github/FossoresLP/GO-JWT-ed25519/master.svg?style=flat-square)](https://circleci.com/gh/FossoresLP/GO-JWT-ed25519)

This packages implements JSON Web Token as defined in [RFC 7519](https://tools.ietf.org/html/rfc7519) in Go using [ed25519](golang.org/x/crypto/ed25519)

Data structures
---------------

JWTs are stored as a struct with the following layout

```go
type JWT struct {
	Header struct {
		Typ string
		Alg string
	}
	Content interface{}
	Hash []byte
}
```

While all values are accessible, you most likely will only need to worry about the content. This package will take care of the other ones for you.

Usage
-----

### Generating a new JWT

Creating a JWT is quite easy. You just have to supply your content and this package will generate a JWT for you.

```go
jwt.New(content Interface) (JWT, error)
```

### Encoding a JWT

To actually use a JWT you will have to encode it. This is done by simply calling `Encode` on the JWT you created. You will need to provide a private key using `Setup` beforehand.

```go
jwt.Setup(key ed25519.PrivateKey)
yourjwt.Encode() (string, error)
```

### Decoding a JWT

To validate a JWT you will first have to decode it. Just supply it to the `Decode` function.

```go
jwt.Decode(yourencodedjwt) (JWT, error)
```

### Validating the hash

When decoding a JWT, it is not automatically validated. You will have to call `Validate` on it manually.

```go
yourjwt.Validate(key ed25519.PublicKey) (error)
```

Keep in mind that this function only validates the hash and checks if the token is valid an the current point in time if `exp` and/or `nbf` are set.