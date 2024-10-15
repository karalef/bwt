// Binary WEB Token
package bwt

import (
	"encoding/base64"

	"github.com/vmihailenco/msgpack/v5"
)

// Type is "BWT"
const Type = "BWT"

// New creates a new Token.
func New(alg Algorithm, claims Claims) *Token {
	return &Token{
		Algorithm: alg,
		Claims:    claims,
	}
}

// Token represents a BWT token.
type Token struct {
	Algorithm Algorithm
	Claims    Claims
	Tag       []byte
}

// Authenticate creates an authentication tag and returns the encoded token.
func (t *Token) Authenticate(key PrivateKey) (string, error) {
	body, err := t.Body()
	if err != nil {
		return "", err
	}

	prefix := t.Prefix()
	t.Tag, err = t.Algorithm.Auth(prefix, body, key)
	if err != nil {
		return "", err
	}

	return prefix + "." + Encode(body) + "." + Encode(t.Tag), nil
}

// Prefix returns the token prefix.
func (t Token) Prefix() string {
	return Type + "_" + t.Algorithm.Name()
}

// Body returns the token body bytes.
func (t Token) Body() ([]byte, error) {
	return msgpack.Marshal(t.Claims)
}

// Encode encodes a byte array into a base64url encoded string.
func Encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// Decode decodes a base64url encoded string into a byte array.
func Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
