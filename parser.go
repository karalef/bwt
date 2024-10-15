package bwt

import (
	"errors"
	"strings"

	"github.com/vmihailenco/msgpack/v5"
)

// Parser is used to parse, validate, and verify BWTs.
type Parser struct {
	validator *Validator
}

// NewParser creates a new Parser with the specified validator.
func NewParser(v ...*Validator) *Parser {
	p := new(Parser)
	if len(v) > 0 {
		p.validator = v[0]
	} else {
		p.validator = NewValidator()
	}
	return p
}

// Keyfunc is a callback function to supply the key for verification.
// The function receives the parsed, but unverified Token.
type Keyfunc func(*Token) (Key, error)

// KeyfuncFrom returns a Keyfunc that always returns the same key.
func KeyfuncFrom(key Key) Keyfunc {
	return func(t *Token) (Key, error) {
		return key, nil
	}
}

// Parse parses, validates, verifies the tag and returns the parsed token.
// keyFunc will receive the parsed token and should return the key for validating.
func (p *Parser) Parse(tokenString string, keyFunc Keyfunc) (*Token, error) {
	return p.ParseWithClaims(tokenString, new(ClaimsMap), keyFunc)
}

// ParseWithClaims parses, validates, and verifies like Parse but using the given claims.
// Claims must be pointer.
func (p *Parser) ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc) (*Token, error) {
	token, raw, err := ParseUnverified(tokenString, claims)
	if err != nil {
		return token, err
	}

	// parse tag
	token.Tag, err = Decode(raw.Parts[2])
	if err != nil {
		return token, errors.Join(ErrTokenMalformed, err)
	}

	// verify tag
	if keyFunc == nil {
		return token, errors.Join(errors.New("no keyfunc was provided"), ErrTokenUnverifiable)
	}
	key, err := keyFunc(token)
	if err != nil {
		return token, errors.Join(ErrTokenUnverifiable, err)
	}
	err = token.Algorithm.Verify(token.Prefix(), raw.Claims, key, token.Tag)
	if err != nil {
		return token, errors.Join(ErrTokenTagInvalid, err)
	}

	// validate
	if p.validator != nil {
		if err := p.validator.Validate(token.Claims); err != nil {
			return token, errors.Join(ErrTokenInvalidClaims, err)
		}
	}

	return token, nil
}

// Raw is the raw token data after unverified parsing.
type Raw struct {
	Parts  []string
	Claims []byte
}

// ParseUnverified parses the token but doesn't verify the tag.
func ParseUnverified(tokenString string, claims Claims) (token *Token, raw Raw, err error) {
	raw.Parts = strings.Split(tokenString, ".")
	if len(raw.Parts) != 3 {
		return nil, raw, ErrTokenMalformed
	}

	token = new(Token)

	// parse prefix
	typ, alg, ok := strings.Cut(raw.Parts[0], "_")
	if !ok || typ != Type || alg == "" {
		return nil, raw, ErrTokenMalformed
	}
	if token.Algorithm = GetAlgorithm(alg); token.Algorithm == nil {
		return token, raw, ErrTokenUnverifiable
	}

	// parse claims
	raw.Claims, err = Decode(raw.Parts[1])
	if err != nil {
		return token, raw, errors.Join(ErrTokenMalformed, err)
	}
	err = msgpack.Unmarshal(raw.Claims, claims)
	if err != nil {
		return token, raw, errors.Join(ErrTokenMalformed, err)
	}
	token.Claims = claims

	return token, raw, nil
}

// Parse is a shortcut for NewParser().Parse().
func Parse(tokenString string, keyFunc Keyfunc, v ...*Validator) (*Token, error) {
	return NewParser(v...).Parse(tokenString, keyFunc)
}

// ParseWithClaims is a shortcut for NewParser().ParseWithClaims().
func ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc, v ...*Validator) (*Token, error) {
	return NewParser(v...).ParseWithClaims(tokenString, claims, keyFunc)
}

var (
	ErrTokenMalformed     = errors.New("token is malformed")
	ErrTokenUnverifiable  = errors.New("token is unverifiable")
	ErrTokenTagInvalid    = errors.New("token tag is invalid")
	ErrTokenInvalidClaims = errors.New("token has invalid claims")
)
