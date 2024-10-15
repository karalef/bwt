package bwt

import (
	"crypto"
	"errors"
	"strings"
	"sync"

	"golang.org/x/crypto/sha3"
)

// Algorithm represents a signing/authentication algorithm.
type Algorithm interface {
	Name() string
	Auth(prefix string, body []byte, key PrivateKey) ([]byte, error)
	Verify(prefix string, body []byte, key Key, tag []byte) error
}

// KeyID computes the KeyID for the given algorithm and public key material
// and returns the base64 encoded string.
func KeyID(alg string, publicKeyMaterial []byte) string {
	h := sha3.New256()
	h.Write([]byte(alg))
	h.Write(publicKeyMaterial)
	return Encode(h.Sum(nil))
}

// Key represents a public or secret key for verifying a token's signature or authentication.
type Key interface {
	crypto.PublicKey | []byte
}

// PrivateKey represents a private or secret key for signing or authenticating a token.
type PrivateKey interface {
	crypto.PrivateKey | []byte
}

// KeyAs returns the given key as the given type.
func KeyAs[T any](key any) (T, error) {
	v, ok := key.(T)
	if !ok {
		return v, ErrInvalidKeyType
	}
	return v, nil
}

var (
	ErrInvalidKeyType = errors.New("key is of invalid type")
	ErrInvalidKey     = errors.New("invalid key")
	ErrTagInvalid     = errors.New("auth tag is invalid")
	ErrWrongTag       = errors.New("auth tag is wrong")
)

var registeredAlgs = make(map[string]Algorithm)
var registeredAlgsMut sync.RWMutex

func RegisterAlgorithm(alg Algorithm) {
	registeredAlgsMut.Lock()
	registeredAlgs[strings.ToUpper(alg.Name())] = alg
	registeredAlgsMut.Unlock()
}

// GetAlgorithm retrieves an auth algorithm from an "alg" string.
func GetAlgorithm(alg string) Algorithm {
	registeredAlgsMut.RLock()
	defer registeredAlgsMut.RUnlock()
	return registeredAlgs[strings.ToUpper(alg)]
}

// ListAlgorithms returns a list of registered algorithm names.
func ListAlgorithms() []string {
	registeredAlgsMut.RLock()
	defer registeredAlgsMut.RUnlock()

	algs := make([]string, 0, len(registeredAlgs))
	for alg := range registeredAlgs {
		algs = append(algs, alg)
	}
	return algs
}
