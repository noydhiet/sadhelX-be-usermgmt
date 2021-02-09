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
		UserID      uint32 `json:"user_id"`
		Username    string `json:"username"`
		Email       string `json:"email"`
		Firstname   string `json:"firstname,omitempty"`
		Lastname    string `json:"lastname,omitempty"`
		Phonenumber string `json:"phonenumber"`
		Password    string `json:"password"`
		CreatedBy   string `json:"created_by,omitempty"`
		// CreatedDate sql.NullTime `json:"created_date,omitempty"`
		CreatedDate time.Time `json:"created_date,omitempty"`
		UpdatedBy   string    `json:"updated_by,omitempty"`
		// UpdatedDate sql.NullTime `json:"updated_date,omitempty"`
		UpdatedDate time.Time `json:"updated_date,omitempty"`
		TokenHash   string    `json:"token_hash"`
	}

	// UserRepository is an interface for the storage implementation of the usermgmt service
	UserRepository interface {
		Signup(ctx context.Context, user UserInformation) (string, error)
		Login(ctx context.Context, email string, password string) (map[string]string, error)
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
