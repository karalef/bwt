package bwt

import (
	"crypto"
	"crypto/hmac"
	"errors"

	_ "golang.org/x/crypto/sha3"
)

// SHA3 based
var (
	HS256 *hmacAlgo
	HS384 *hmacAlgo
	HS512 *hmacAlgo
)

func init() {
	HS256 = &hmacAlgo{"HS256", crypto.SHA3_256}
	RegisterAlgorithm(HS256)

	HS384 = &hmacAlgo{"HS384", crypto.SHA3_384}
	RegisterAlgorithm(HS384)

	HS512 = &hmacAlgo{"HS512", crypto.SHA3_512}
	RegisterAlgorithm(HS512)
}

type hmacAlgo struct {
	alg  string
	hash crypto.Hash
}

func (h *hmacAlgo) Name() string { return h.alg }

// Verify implements token verification.
// Key must be []byte.
func (h *hmacAlgo) Verify(prefix string, body []byte, key Key, tag []byte) error {
	if !h.hash.Available() {
		return ErrHashUnavailable
	}
	keyBytes, err := KeyAs[[]byte](key)
	if err != nil {
		return err
	}
	if len(tag) != h.hash.Size() {
		return ErrTagInvalid
	}

	hasher := hmac.New(h.hash.New, keyBytes)
	hasher.Write([]byte(prefix))
	hasher.Write(body)
	if !hmac.Equal(tag, hasher.Sum(nil)) {
		return ErrWrongTag
	}
	return nil
}

// Auth implements token authentication.
// Key must be []byte.
func (h *hmacAlgo) Auth(prefix string, body []byte, key PrivateKey) ([]byte, error) {
	if !h.hash.Available() {
		return nil, ErrHashUnavailable
	}
	keyBytes, err := KeyAs[[]byte](key)
	if err != nil {
		return nil, err
	}

	hasher := hmac.New(h.hash.New, keyBytes)
	hasher.Write([]byte(prefix))
	hasher.Write(body)
	return hasher.Sum(nil), nil
}

// HashUnavailable returns true if the requested hash function is unavailable.
var ErrHashUnavailable = errors.New("the requested hash function is unavailable")
