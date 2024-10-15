package bwt

import (
	"crypto/subtle"
	"errors"
	"time"
)

// ClaimsValidator is an interface that can be implemented by custom claims to
// perform custom validation.
type ClaimsValidator interface {
	Claims
	Validate() error
}

// Validator is a validator that can be used to validate already parsed claims.
type Validator struct {
	leeway   time.Duration
	timeFunc func() time.Time
	now      time.Time

	validators []ValidatorFunc
}

// Now returns the current time.
func (v *Validator) Now() time.Time {
	if !v.now.IsZero() {
		return v.now
	}
	if v.timeFunc == nil {
		v.timeFunc = time.Now
	}
	v.now = v.timeFunc()
	return v.now
}

// PTime returns the current time minus the leeway.
func (v *Validator) PTime() time.Time { return v.Now().Add(-v.leeway) }

// FTime returns the current time plus the leeway.
func (v *Validator) FTime() time.Time { return v.Now().Add(+v.leeway) }

// ValidatorOption is a functional option that can be used to configure the [Validator].
type ValidatorOption func(*Validator)

// ValidatorFunc is a function to validate claims.
type ValidatorFunc func(*Validator, Claims) error

// NewValidator can be used to create a validator with the supplied options.
// This validator can then be used to validate already parsed claims.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{}

	for _, apply := range opts {
		apply(v)
	}
	return v
}

// WithLeeway returns the ValidatorOption for specifying the leeway window.
func WithLeeway(leeway time.Duration) ValidatorOption {
	return func(v *Validator) {
		v.leeway = leeway
	}
}

// WithTimeFunc returns the ValidatorOption for specifying the time func.
func WithTimeFunc(f func() time.Time) ValidatorOption {
	return func(v *Validator) {
		v.timeFunc = f
	}
}

// WithValidator returns the ValidatorOption to add the validator func.
func WithValidator(f ValidatorFunc) ValidatorOption {
	return func(v *Validator) {
		v.validators = append(v.validators, f)
	}
}

// Validate validates the given claims. It will also perform any custom
// validation if claims implements the [ClaimsValidator] interface.
func (v *Validator) Validate(claims Claims) (err error) {
	errs := make([]error, 0, len(v.validators))
	for _, validate := range v.validators {
		if err := validate(v, claims); err != nil {
			errs = append(errs, err)
		}
	}

	if cvt, ok := claims.(ClaimsValidator); ok {
		if err := cvt.Validate(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// WithVerifyExpiration returns the ValidatorOption for specifying the
// verification of the expiration time.
func WithVerifyExpiration(required bool) ValidatorOption {
	return WithValidator(func(v *Validator, claims Claims) error {
		exp := claims.GetExpirationTime()
		if exp.IsZero() {
			return errorIfRequired(required, ClaimsKeyExpirationTime)
		}
		return errorIfFalse(v.PTime().Before(exp), ErrTokenExpired)
	})
}

// WithVerifyIssuedAt returns the ValidatorOption for specifying the
// verification of the issued at time.
func WithVerifyIssuedAt(required bool) ValidatorOption {
	return WithValidator(func(v *Validator, claims Claims) error {
		iat := claims.GetIssuedAt()
		if iat.IsZero() {
			return errorIfRequired(required, ClaimsKeyIssuedAt)
		}

		return errorIfFalse(!v.FTime().Before(iat), ErrTokenUsedBeforeIssued)
	})
}

// WithVerifyNotBefore returns the ValidatorOption for specifying the
// verification of the not before time.
func WithVerifyNotBefore(required bool) ValidatorOption {
	return WithValidator(func(v *Validator, claims Claims) error {
		nbf := claims.GetNotBefore()
		if nbf.IsZero() {
			return errorIfRequired(required, ClaimsKeyNotBefore)
		}

		return errorIfFalse(!v.FTime().Before(nbf), ErrTokenNotValidYet)
	})
}

// WithRequireAudience returns the ValidatorOption for specifying the
// verification of the audience.
func WithRequireAudience(required bool, audience string) ValidatorOption {
	return WithValidator(func(v *Validator, claims Claims) error {
		aud := claims.GetAudience()
		if len(aud) == 0 {
			return errorIfRequired(required, ClaimsKeyAudience)
		}

		result := false
		nonEmpty := false
		for _, a := range aud {
			if subtle.ConstantTimeCompare([]byte(a), []byte(audience)) != 0 {
				result = true
			}
			nonEmpty = nonEmpty || a != ""
		}

		if !nonEmpty {
			return errorIfRequired(required, ClaimsKeyAudience)
		}

		return errorIfFalse(result, ErrTokenInvalidAudience)
	})
}

// WithVerifyIssuer returns the ValidatorOption for specifying the
// verification of the issuer.
func WithVerifyIssuer(required bool, issuer string) ValidatorOption {
	return WithValidator(func(v *Validator, claims Claims) error {
		iss := claims.GetIssuer()
		if iss == "" {
			return errorIfRequired(required, ClaimsKeyIssuer)
		}

		return errorIfFalse(iss == issuer, ErrTokenInvalidIssuer)
	})
}

// WithVerifySubject returns the ValidatorOption for specifying the
// verification of the subject.
func WithVerifySubject(required bool, subject string) ValidatorOption {
	return WithValidator(func(v *Validator, claims Claims) error {
		sub := claims.GetSubject()
		if sub == "" {
			return errorIfRequired(required, ClaimsKeySubject)
		}

		return errorIfFalse(sub == subject, ErrTokenInvalidSubject)
	})
}

func errorIfFalse(value bool, err error) error {
	if value {
		return nil
	}
	return err
}

func errorIfRequired(required bool, claim string) error {
	if required {
		return errors.Join(errors.New(claim+" claim is required"), ErrTokenRequiredClaimMissing)
	}
	return nil
}

var (
	ErrTokenRequiredClaimMissing = errors.New("token is missing required claim")
	ErrTokenInvalidAudience      = errors.New("token has invalid audience")
	ErrTokenExpired              = errors.New("token is expired")
	ErrTokenUsedBeforeIssued     = errors.New("token used before issued")
	ErrTokenInvalidIssuer        = errors.New("token has invalid issuer")
	ErrTokenInvalidSubject       = errors.New("token has invalid subject")
	ErrTokenNotValidYet          = errors.New("token is not valid yet")
)
