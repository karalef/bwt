package bwt_test

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/karalef/bwt"
)

func TestBWT(t *testing.T) {
	token := bwt.New(bwt.HS256, bwt.ClaimsMap{
		bwt.ClaimsKeySubject:  "1234567890",
		"name":                "John Doe",
		bwt.ClaimsKeyIssuedAt: time.Unix(1516239022, 0),
	})
	secret := make([]byte, 32)
	//nolint:errcheck
	rand.Read(secret)
	t.Log(bwt.KeyID(bwt.HS256.Name(), secret))

	signed, err := token.Authenticate(secret)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(signed)

	token2, err := bwt.Parse(signed, bwt.KeyfuncFrom(secret), bwt.NewValidator(
		bwt.WithVerifySubject(true, "1234567890"),
		bwt.WithVerifyIssuedAt(true),
		bwt.WithValidator(func(v *bwt.Validator, c bwt.Claims) error {
			cm := bwt.ClaimsAsMap(c)
			if cm == nil {
				return errors.New("invalid claims")
			}
			if cm.Str("name") != "John Doe" {
				return errors.New("invalid name")
			}
			return nil
		})))

	if err != nil {
		t.Fatal(err)
	}

	t.Log(token2.Claims)
}
