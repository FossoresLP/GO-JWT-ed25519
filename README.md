EdDSA JWT using Ed25519 in Golang
=================================

[![CircleCI](https://img.shields.io/circleci/project/github/FossoresLP/GO-JWT-ed25519/master.svg?style=flat-square)](https://circleci.com/gh/FossoresLP/GO-JWT-ed25519)
[![Coveralls](https://img.shields.io/coveralls/github/FossoresLP/GO-JWT-ed25519/master.svg?style=flat-square)](https://coveralls.io/github/FossoresLP/GO-JWT-ed25519)
[![Codacy](https://img.shields.io/codacy/grade/943c64e6d6ae481887224e6fe106a6a2.svg?style=flat-square)](https://www.codacy.com/app/FossoresLP/GO-JWT-ed25519)
[![Licensed under: Boost Software License](https://img.shields.io/badge/style-BSL--1.0-red.svg?longCache=true&style=flat-square&label=License)](https://github.com/FossoresLP/GO-JWT-ed25519/blob/master/LICENSE.md)
[![GoDoc](https://img.shields.io/badge/style-reference-blue.svg?longCache=true&style=flat-square&label=GoDoc)](https://godoc.org/github.com/FossoresLP/GO-JWT-ed25519)

This packages implements JSON Web Token as defined in [RFC 7519](https://tools.ietf.org/html/rfc7519) in Go using [Ed25519](golang.org/x/crypto/ed25519)

Important: This package is not fully compliant with RFC 7519 (JWT) and RFC 7515 (JWS) due to not implementing default signature algorithms. It is able to decode all JWTs that adhere to the standard but can only validate tokens using EdDSA with Ed25519 keys

Data structures
---------------

JWTs are stored as a struct with the following layout

```go
type JWT struct {
	Header struct {
		Typ string // Type of the token, has to be a JWT.
		Alg string // Algorithm used to sign the token (this package signs using EdDSA).
		Kid string // Key ID of the key used to sign the token.
		Jku string // URL presenting public key necessary for validation.
	}
	Content interface{} // Should be either a map with strings as keys or a struct to adhere to the standard.
	Hash []byte // A byte slice containing the hash/signature of the token. Will only be set when decoding a token.
}
```

While all values are accessible, you most likely will only need to worry about the content. This package will take care of the other ones for you.

Usage
-----

### Generating a new JWT

Creating a JWT is quite easy. You just have to supply your content and this package will generate a JWT for you. New will return an error when an unsupported content type is used. Supported content types are structs and maps with strings as keys.

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