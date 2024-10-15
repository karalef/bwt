package bwt

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
)

// EdDSA algorithm.
// Expects ed25519.PrivateKey for authentication and ed25519.PublicKey for verification.
var EdDSA *algoEd25519

func init() {
	EdDSA = new(algoEd25519)
	RegisterAlgorithm(EdDSA)
}

type algoEd25519 struct{}

func (*algoEd25519) Name() string { return "EDDSA" }

// Verify implements token verification.
// Key must be an ed25519.PublicKey.
func (a *algoEd25519) Verify(prefix string, body []byte, key Key, tag []byte) error {
	ed25519Key, err := KeyAs[ed25519.PublicKey](key)
	if err != nil {
		return err
	}
	if len(ed25519Key) != ed25519.PublicKeySize {
		return ErrInvalidKey
	}
	if len(tag) != ed25519.SignatureSize {
		return ErrTagInvalid
	}

	if !ed25519.Verify(ed25519Key, append([]byte(prefix), body...), tag) {
		return ErrWrongTag
	}
	return nil
}

// Auth implements token authentication.
// Key must be an ed25519.PrivateKey.
func (a *algoEd25519) Auth(prefix string, body []byte, key PrivateKey) ([]byte, error) {
	ed25519Key, err := KeyAs[ed25519.PrivateKey](key)
	if err != nil {
		return nil, err
	}
	if len(ed25519Key) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKey
	}
	return ed25519Key.Sign(rand.Reader, append([]byte(prefix), body...), crypto.Hash(0))
}
