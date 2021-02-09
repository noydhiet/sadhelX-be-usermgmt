package auth

import (
	"context"
	"errors"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"shadelx-be-usermgmt/datastruct"
	"shadelx-be-usermgmt/util"
)

type (
	// Service define action that
	// will be exposed to transport layer
	Service interface {
		Signup(ctx context.Context, user datastruct.UserInformation) (string, error)
		Login(ctx context.Context, usernmae string, password string) (map[string]string, error)
	}

	service struct {
		repository datastruct.UserRepository
		logger     log.Logger
	}
)

// NewService ...
func NewService(repo datastruct.UserRepository, logger log.Logger) Service {
	return &service{
		repository: repo,
		logger:     log.With(logger, "repo", "auth"),
	}
}

func (s *service) Signup(ctx context.Context, user datastruct.UserInformation) (string, error) {

	if err := user.Validate(); err != nil {
		return "", err
	}

	uuid, err := util.GenerateUUID()
	if err != nil {
		return "", errors.New("failed generate uuid")
	}

	hashedPass, err := util.PasswordHashing(user.Password)
	if err != nil {
		level.Error(s.logger).Log("msg", "failed hashing password", "err", err)
		return "", err
	}

	tokenHash := util.GenerateRandomString(15)

	user.UserID = uuid
	user.Password = hashedPass
	user.TokenHash = tokenHash
	user.CreatedBy = "sadhelx.auth.service"
	user.CreatedDate = util.GetNow()
	user.UpdatedBy = "sadhelx.auth.service"
	user.UpdatedDate = util.GetNow()

	res, err := s.repository.Signup(ctx, user)
	if err != nil {
		level.Error(s.logger).Log("msg", "failed signup", "err", err)
		return "", errors.New("failed to signup, please retry later")
	}

	return res, nil
}

func (s *service) Login(ctx context.Context, email string, password string) (map[string]string, error) {

	token, err := s.repository.Login(ctx, email, password)
	if err != nil {
		level.Error(s.logger).Log("msg", "failed login", "err", err)
		return nil, errors.New("failed to login, please retry later")
	}

	return token, nil
}
