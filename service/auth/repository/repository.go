package repository

import (
	"context"
	"errors"
	"shadelx-be-usermgmt/datastruct"
	"shadelx-be-usermgmt/util"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

type MailType int

// List of Mail Types we are going to send.
const (
	MailConfirmation MailType = iota + 1
	PassReset
)

// MailData represents the data to be sent to the template of the mail.
type MailDataTemplate struct {
	Username string
	Code     string
}

// Mail represents a email request
// type Mail struct {
// 	from    string
// 	to      []string
// 	subject string
// 	body    string
// 	mtype   MailType
// 	data    *MailData
// }

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
		return "", errors.New("Email has already been taken")
	}

	if usernameExists := r.dbRepo.UsernameIsExist(ctx, user.Username); usernameExists {
		return "", errors.New("Username has already been taken")
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

func (r *repo) UsernameAvailability(ctx context.Context, identity string) (bool, error) {
	if isExist := r.dbRepo.UsernameIsExist(ctx, identity); isExist {
		return false, errors.New("Username has already been taken")
	}
	return true, nil
}

func (r *repo) EmailAvailability(ctx context.Context, identity string) (bool, error) {
	if isExist := r.dbRepo.EmailIsExist(ctx, identity); isExist {
		return false, errors.New("Email has already been taken")
	}
	return true, nil
}

func (r *repo) VerifyPasswordReset(ctx context.Context, identity, code string) (bool, error) {

	var user *datastruct.UserInformation
	var actualVerificationData *datastruct.VerificationData
	var verificationData *datastruct.VerificationData

	var err error
	if strings.Contains(identity, "@") {
		user, err = r.dbRepo.GetUserByEmail(ctx, identity)
		if err != nil {
			level.Error(r.logger).Log("err", err)
			return false, err
		}
	} else {
		user, err = r.dbRepo.GetUserByUsername(ctx, identity)
		if err != nil {
			level.Error(r.logger).Log("err", err)
			return false, err
		}
	}

	verificationData.Code = code
	verificationData.Email = user.Email
	verificationData.Type = datastruct.VerificationDataType(PassReset)

	actualVerificationData, err = r.dbRepo.GetVerificationData(ctx, user.Email, 2)
	if err != nil {
		level.Error(r.logger).Log("err", err)
		return false, err
	}
	return false, nil

	_, err = r.authRepo.VerifyCode(actualVerificationData, verificationData)
	if err != nil {
		level.Error(r.logger).Log("err", err)
		return false, err
	}

	if err = r.dbRepo.DeleteVerificationData(ctx, actualVerificationData); err != nil {
		level.Error(r.logger).Log("err", err)
		return false, err
	}

	return true, nil

}

func (r *repo) GetResetPasswordCode(ctx context.Context, identity string) (bool, error) {

	var user *datastruct.UserInformation
	var err error
	if strings.Contains(identity, "@") {
		user, err = r.dbRepo.GetUserByEmail(ctx, identity)
		if err != nil {
			level.Error(r.logger).Log("err", err)
			return false, err
		}
	} else {
		user, err = r.dbRepo.GetUserByUsername(ctx, identity)
		if err != nil {
			level.Error(r.logger).Log("err", err)
			return false, err
		}
	}

	mailData := &MailDataTemplate{
		Username: user.Username,
		Code:     strings.ToUpper(util.GenerateRandomString(4)),
	}
	verificationData := &datastruct.VerificationData{
		Email:     user.Email,
		Code:      mailData.Code,
		Type:      datastruct.VerificationDataType(PassReset),
		ExpiresAt: time.Now().Add(time.Minute * time.Duration(30)),
	}

	_, err = r.authRepo.SendEmailVerification(mailData, user, PassReset)
	if err != nil {
		return false, errors.New("cannot send email verification")
	}

	if err = r.dbRepo.StoreVerificationData(ctx, verificationData); err != nil {
		return false, errors.New("db error")
	}
	return false, nil
}
func (r *repo) RefreshToken(ctx context.Context, identity string) (string, error) {
	user, err := r.dbRepo.GetUserByUsername(ctx, identity)
	if err != nil {
		return "", err
	}

	token, err := r.authRepo.GenerateAccessToken(user)
	if err != nil {
		return "", err
	}

	return token, nil
}
