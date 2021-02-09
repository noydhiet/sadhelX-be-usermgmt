package repository

import (
	"context"
	"errors"
	"shadelx-be-usermgmt/datastruct"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

type repo struct {
	dbRepo   PostgresRepository
	authRepo AuthRepository
	logger   log.Logger
}

// NewRepo ...
func NewRepo(dbRepo PostgresRepository, authRepo AuthRepository, logger log.Logger) datastruct.UserRepository {
	return &repo{
		dbRepo:   dbRepo,
		authRepo: authRepo,
		logger:   logger,
	}
}

func (r *repo) Signup(ctx context.Context, user datastruct.UserInformation) (string, error) {

	if err := user.Validate(); err != nil {
		return "", err
	}

	if emailExists := r.dbRepo.EmailIsExist(ctx, user.Email); emailExists {
		return "", errors.New("Email has been taken")
	}

	if usernameExists := r.dbRepo.UsernameIsExist(ctx, user.Username); usernameExists {
		return "", errors.New("Username has been taken")
	}

	if err := r.dbRepo.Create(ctx, &user); err != nil {
		level.Error(r.logger).Log("msg", "failed creating user", "err", err)
		return "", err
	}

	return "success creating user", nil
}

func (r *repo) Login(ctx context.Context, email string, password string) (map[string]string, error) {
	user, err := r.dbRepo.GetUserByEmail(ctx, email)
	if err != nil {
		level.Error(r.logger).Log("err", err)
		return nil, err
	}

	accessToken, err := r.authRepo.GenerateAccessToken(user)
	// level.Debug(r.logger).Log("msg", accessToken)
	if err != nil {
		level.Error(r.logger).Log("msg", "unable to generate access token", "err", err)
		return nil, err
	}

	refreshToken, err := r.authRepo.GenerateRefreshToken(user)
	if err != nil {
		level.Error(r.logger).Log("msg", "unable to generate refresh token", "err", err)
		return nil, err
	}

	token := make(map[string]string)
	token["access_token"] = accessToken
	token["refresh_token"] = refreshToken

	return token, nil
}
