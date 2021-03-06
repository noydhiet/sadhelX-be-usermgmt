package datastruct

import (
	"context"
	"errors"
	"shadelx-be-usermgmt/util"
	"strings"
	"time"
)

type (
	// UserInformation represent user inside business logic
	UserInformation struct {
		UserID        uint32    `json:"user_id,omitempty"`
		Username      string    `json:"username" validate:"required,username,min=6,max=20"`
		Email         string    `json:"email" validate:"required,email"`
		Firstname     string    `json:"firstname,omitempty"`
		Lastname      string    `json:"lastname,omitempty"`
		Phonenumber   string    `json:"phonenumber,omitempty"`
		Password      string    `json:"password" validate:"required,min=6"`
		CreatedBy     string    `json:"created_by,omitempty"`
		CreatedDate   time.Time `json:"created_date,omitempty"`
		UpdatedBy     string    `json:"updated_by,omitempty"`
		UpdatedDate   time.Time `json:"updated_date,omitempty"`
		TokenHash     string    `json:"token_hash"`
		EmailVerified bool      `json:"email_verified,omitempty"`
		ImageFile     string    `json:"image_file,omitempty"`
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

	// DBRepository list all db operartion for those entity
	DBRepository interface {
		CreateUser(ctx context.Context, user *UserInformation) error
		GetUserByEmail(ctx context.Context, email string) (*UserInformation, error)
		GetUserByUsername(ctx context.Context, username string) (*UserInformation, error)
		UpdateUserPassword(ctx context.Context, email string, password string, tokenHash string) error
		EmailIsExist(ctx context.Context, email string) (bool, error)
		UsernameIsExist(ctx context.Context, username string) (bool, error)
		UpdateUserAvatar(ctx context.Context, user *UserInformation) error
		UpdateEmailVerified(ctx context.Context, user *UserInformation) error

		CreateVerificationData(ctx context.Context, data *VerificationData) error
		GetVerificationData(ctx context.Context, email string, verificationDataType int) (*VerificationData, error)
		DeleteVerificationData(ctx context.Context, verificationData *VerificationData) error
	}
)

// Validate ...
func (user *UserInformation) Validate() error {
	user.Firstname = strings.TrimSpace(user.Firstname)
	user.Lastname = strings.TrimSpace(user.Lastname)

	user.Email = strings.TrimSpace(strings.ToLower(user.Email))
	if user.Email == "" {
		// return util.NewBadRequestError("invalid email address")
		return errors.New(util.ErrBadRequest)
	}

	user.Password = strings.TrimSpace(user.Password)
	if user.Password == "" {
		// return util.NewBadRequestError("invalid password")
		return errors.New(util.ErrBadRequest)
	}
	return nil
}
