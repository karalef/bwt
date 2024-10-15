package bwt

import "time"

// Claims represents the token claims.
// Must be msgpack de/encodable and be pointer.
type Claims interface {
	GetKeyID() string
	GetExpirationTime() time.Time
	GetIssuedAt() time.Time
	GetNotBefore() time.Time
	GetIssuer() string
	GetSubject() string
	GetAudience() []string
}

// well-known claim keys
const (
	ClaimsKeyKeyID          = "kid"
	ClaimsKeyExpirationTime = "exp"
	ClaimsKeyIssuedAt       = "iat"
	ClaimsKeyNotBefore      = "nbf"
	ClaimsKeyIssuer         = "iss"
	ClaimsKeySubject        = "sub"
	ClaimsKeyAudience       = "aud"
)

var _ Claims = RegisteredClaims{}

// RegisteredClaims contains well-known claims.
type RegisteredClaims struct {
	KeyID          string    `msgpack:"kid,omitempty"`
	ExpirationTime time.Time `msgpack:"exp,omitempty"`
	IssuedAt       time.Time `msgpack:"iat,omitempty"`
	NotBefore      time.Time `msgpack:"nbf,omitempty"`
	Issuer         string    `msgpack:"iss,omitempty"`
	Subject        string    `msgpack:"sub,omitempty"`
	Audience       []string  `msgpack:"aud,omitempty"`
}

func (c RegisteredClaims) GetKeyID() string             { return c.KeyID }
func (c RegisteredClaims) GetExpirationTime() time.Time { return c.ExpirationTime }
func (c RegisteredClaims) GetIssuedAt() time.Time       { return c.IssuedAt }
func (c RegisteredClaims) GetNotBefore() time.Time      { return c.NotBefore }
func (c RegisteredClaims) GetIssuer() string            { return c.Issuer }
func (c RegisteredClaims) GetSubject() string           { return c.Subject }
func (c RegisteredClaims) GetAudience() []string        { return c.Audience }

// ClaimsAsMap returns the Claims as a ClaimsMap dereferencing the pointer if needed.
func ClaimsAsMap(c Claims) ClaimsMap {
	if cm, ok := c.(ClaimsMap); ok {
		return cm
	}
	if cm, ok := c.(*ClaimsMap); ok && cm != nil {
		return *cm
	}
	return nil
}

var _ Claims = ClaimsMap{}

// ClaimsMap is a map of claims.
type ClaimsMap map[string]any

func MapValue[V any](m map[string]any, key string) (empty V) {
	v, ok := m[key]
	if !ok {
		return empty
	}
	return v.(V)
}

// Time returns the time associated with the key.
func (c ClaimsMap) Time(key string) time.Time {
	return MapValue[time.Time](c, key)
}

// Str returns the string associated with the key.
func (c ClaimsMap) Str(key string) string {
	return MapValue[string](c, key)
}

// Strs returns the string slice associated with the key.
func (c ClaimsMap) Strs(key string) []string {
	return MapValue[[]string](c, key)
}

func (c ClaimsMap) GetKeyID() string             { return c.Str(ClaimsKeyKeyID) }
func (c ClaimsMap) GetExpirationTime() time.Time { return c.Time(ClaimsKeyExpirationTime) }
func (c ClaimsMap) GetIssuedAt() time.Time       { return c.Time(ClaimsKeyIssuedAt) }
func (c ClaimsMap) GetNotBefore() time.Time      { return c.Time(ClaimsKeyNotBefore) }
func (c ClaimsMap) GetIssuer() string            { return c.Str(ClaimsKeyIssuer) }
func (c ClaimsMap) GetSubject() string           { return c.Str(ClaimsKeySubject) }
func (c ClaimsMap) GetAudience() []string        { return c.Strs(ClaimsKeyAudience) }
