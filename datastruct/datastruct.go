package datastruct

import (
	"context"
	"errors"
	"strings"
	"time"
)

type (
	// UserInformation represent user inside business logic
	UserInformation struct {
		UserID      uint32    `json:"user_id,omitempty"`
		Username    string    `json:"username"`
		Email       string    `json:"email"`
		Firstname   string    `json:"firstname,omitempty"`
		Lastname    string    `json:"lastname,omitempty"`
		Phonenumber string    `json:"phonenumber,omitempty"`
		Password    string    `json:"password"`
		CreatedBy   string    `json:"created_by,omitempty"`
		CreatedDate time.Time `json:"created_date,omitempty"`
		UpdatedBy   string    `json:"updated_by,omitempty"`
		UpdatedDate time.Time `json:"updated_date,omitempty"`
		TokenHash   string    `json:"token_hash"`
	}

	// UserRepository is an interface for the storage implementation of the usermgmt service
	UserRepository interface {
		Signup(ctx context.Context, user UserInformation) (string, error)
		Login(ctx context.Context, identity string, password string) (map[string]string, error)
		UsernameAvailability(ctx context.Context, identity string) (bool, error)
		EmailAvailability(ctx context.Context, identity string) (bool, error)
		VerifyPasswordReset(ctx context.Context, identity, code string) (bool, error)
		GetResetPasswordCode(ctx context.Context, identity string) (bool, error)
		RefreshToken(ctx context.Context, identity string) (string, error)
	}

	// VerificationDataType ...
	VerificationDataType int

	// VerificationData ...
	VerificationData struct {
		Email     string               `json:"email" validate:"required" sql:"email"`
		Code      string               `json:"code" validate:"required" sql:"code"`
		ExpiresAt time.Time            `json:"expires_at" sql:"expires_at"`
		Type      VerificationDataType `json:"type" sql:"type"`
	}
)

// Validate ...
func (user *UserInformation) Validate() error {
	user.Firstname = strings.TrimSpace(user.Firstname)
	user.Lastname = strings.TrimSpace(user.Lastname)

	user.Email = strings.TrimSpace(strings.ToLower(user.Email))
	if user.Email == "" {
		// return util.NewBadRequestError("invalid email address")
		return errors.New("invalid email address")
	}

	user.Password = strings.TrimSpace(user.Password)
	if user.Password == "" {
		// return util.NewBadRequestError("invalid password")
		return errors.New("invalid passwword")
	}
	return nil
}
