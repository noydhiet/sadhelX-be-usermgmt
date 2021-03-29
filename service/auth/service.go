package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"os"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"google.golang.org/api/idtoken"

	"shadelx-be-usermgmt/datastruct"
	"shadelx-be-usermgmt/service/auth/pkg/jwt"
	"shadelx-be-usermgmt/service/auth/pkg/mailer"
	"shadelx-be-usermgmt/util"
)

type (
	// Service define action that
	// will be exposed to transport layer
	Service interface {
		Signup(ctx context.Context, user datastruct.UserInformation) (*datastruct.UserInformation, error)
		Login(ctx context.Context, usernmae string, password string) (*datastruct.UserInformation, map[string]string, error)
		// GoogleSignIn(ctx context.Context, idToken string) (*oauth2.Tokeninfo, error)
		GoogleSignIn(ctx context.Context, idToken string) (*datastruct.UserInformation, map[string]string, error)
		UsernameAvailability(ctx context.Context, identity string) (string, error)
		EmailAvailability(ctx context.Context, identity string) (string, error)
		ResetPassword(ctx context.Context, identity, code, password, passwordRe string) error
		VerifyPasswordReset(ctx context.Context, identity, code string) (bool, string, error)
		VerifyUserEmail(ctx context.Context, identity, code string) (bool, error)
		GetResetPasswordCode(ctx context.Context, identity string) (bool, error)
		RefreshToken(ctx context.Context, identity, customKey string) (string, error)
		AddUserAvatar(ctx context.Context, identity string, file multipart.File, fileHeader *multipart.FileHeader) (string, error)
	}

	service struct {
		repository datastruct.DBRepository
		mailer     mailer.Service
		configs    *util.Configurations
		logger     log.Logger
	}

	// MailType 1 for email verification
	// 2 for passwor reset
	MailType int

	// MailDataTemplate represents the data to be sent to the template of the mail.
	MailDataTemplate struct {
		Username string
		Code     string
	}

	GoogleSignInPayloadClaims struct {
		Aud           string `json:"aud"`
		AtHash        string `json:"at_hash"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		FamilyName    string `json:"family_name"`
		GivenName     string `json:"given_name"`
		Picture       string `json:"picture"`
	}
)

const (
	// MailConfirmation ...
	MailConfirmation MailType = iota + 1
	// PassReset ...
	PassReset
)

// NewService ...
func NewService(ms mailer.Service, repo datastruct.DBRepository, configs *util.Configurations, logger log.Logger) Service {
	return &service{
		mailer:     ms,
		repository: repo,
		configs:    configs,
		logger:     log.With(logger, "repo", "service"),
	}
}

func (s *service) Signup(ctx context.Context, user datastruct.UserInformation) (*datastruct.UserInformation, error) {

	if err := user.Validate(); err != nil {

		level.Error(s.logger).Log("err", err.Error())

		return nil, errors.New(util.ErrBadRequest)
	}

	emailExists, err := s.repository.EmailIsExist(ctx, user.Email)
	if err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return nil, errors.New(util.ErrDBPostgre)
	}
	if emailExists && err == nil {
		level.Error(s.logger).Log("EmailIsExist", emailExists)
		return nil, errors.New(util.ErrEmailAvailability)
	}
	level.Debug(s.logger).Log("emailExists", emailExists)

	usernameExists, err := s.repository.UsernameIsExist(ctx, user.Username)
	if err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return nil, errors.New(util.ErrDBPostgre)
	}

	if usernameExists && err == nil {
		level.Error(s.logger).Log("usernameExists", usernameExists)
		return nil, errors.New(util.ErrUsernameAvailability)
	}

	uuid, err := util.GenerateUUID()
	if err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return nil, errors.New(util.ErrInternalServerError)
	}

	hashedPass, err := util.PasswordHashing(user.Password)
	if err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return nil, errors.New(util.ErrInternalServerError)
	}

	tokenHash := util.GenerateRandomString(15)

	user.UserID = uuid
	user.Password = hashedPass
	user.TokenHash = tokenHash
	user.CreatedBy = "sadhelx.auth.service"
	user.CreatedDate = util.GetNow()
	user.UpdatedBy = "sadhelx.auth.service"
	user.UpdatedDate = util.GetNow()
	user.EmailVerified = false

	if err := s.repository.CreateUser(ctx, &user); err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return nil, errors.New(util.ErrUserCreation)
	}

	code, err := util.GenerateRandom6Digits()
	if err != nil {
		return nil, errors.New(util.ErrGenerateOTP)
	}

	// Send verification mail
	from := "sandbox.repoerna@gmail.com"
	to := []string{user.Email}
	subject := "Email Verification for Bookite"
	mailType := mailer.MailConfirmation
	mailData := &mailer.MailData{
		Username: user.Username,
		// Code:     strings.ToUpper(util.GenerateRandomString(4)),
		Code: fmt.Sprint(code),
	}
	// mailData := &mailer.MailData{
	// 	Username: user.Username,
	// 	Code:     fmt.Sprint(code),
	// }

	mailReq := s.mailer.NewMail(from, to, subject, mailType, mailData)
	if err = s.mailer.SendMail(mailReq); err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return nil, errors.New("can't send verification email")
		// return nil, errors.New(util.ErrInternalServerError)

	}

	// _, err = sendEmailVerification(mailData, MailConfirmation, &user, s.configs)
	// if err != nil {
	// 	level.Error(s.logger).Log("err", err.Error())
	// 	return nil, errors.New(util.ErrEmailSend)
	// }

	verificationData := &datastruct.VerificationData{
		Email:     user.Email,
		Code:      mailData.Code,
		Type:      datastruct.VerificationDataType(MailConfirmation),
		ExpiresAt: time.Now().Add(time.Minute * time.Duration(30)),
	}
	if err = s.repository.CreateVerificationData(ctx, verificationData); err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return nil, errors.New(util.ErrDBPostgre)
	}

	return &user, nil
}

func (s *service) GoogleSignIn(ctx context.Context, idToken string) (*datastruct.UserInformation, map[string]string, error) {

	// payload, err := idtoken.Validate(ctx, idToken, "79256613338-felpgs5vq0a2bv9jam75mulpuv0a1j3f.apps.googleusercontent.com")
	payload, err := idtoken.Validate(ctx, idToken, "79256613338-bmt5o1c36gs1es0kj9fbtj2otsdoocvf.apps.googleusercontent.com")

	// fmt.Println(payload)
	// fmt.Println(err.Error())

	if err != nil {
		if err.Error() == "idtoken: token expired" {
			return nil, nil, errors.New(util.ErrInvalidToken)
		}
		return nil, nil, err
	}

	if payload.Issuer != "https://accounts.google.com" {
		return nil, nil, errors.New(util.ErrBadRequest)
	}

	if payload.Audience != "79256613338-bmt5o1c36gs1es0kj9fbtj2otsdoocvf.apps.googleusercontent.com" {
		return nil, nil, errors.New(util.ErrBadRequest)
	}

	var claims GoogleSignInPayloadClaims
	jsonString, err := json.Marshal(payload.Claims)
	if err = json.Unmarshal(jsonString, &claims); err != nil {
		fmt.Println(err.Error())
		return nil, nil, errors.New(util.ErrInternalServerError)
	}

	if claims.Aud != "79256613338-bmt5o1c36gs1es0kj9fbtj2otsdoocvf.apps.googleusercontent.com" {
		return nil, nil, errors.New(util.ErrBadRequest)
	}

	isEmailExist, err := s.repository.EmailIsExist(ctx, claims.Email)
	if err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return nil, nil, errors.New(util.ErrDBPostgre)
	}

	if isEmailExist && err == nil {
		fmt.Println("email exist")

		fmt.Println("2")

		user, err := s.repository.GetUserByEmail(ctx, claims.Email)
		if err != nil && err == sql.ErrNoRows {
			return nil, nil, errors.New(util.ErrInvalidUsernameEmail)
		}
		if err != nil {
			level.Error(s.logger).Log("err", err)
			return nil, nil, err
		}

		accessToken, err := jwt.GenerateAccessToken(fmt.Sprint(user.UserID), int64(s.configs.JwtExpiration), s.configs.JwtSecret)
		if err != nil {
			level.Error(s.logger).Log("msg", "unable to generate access token", "err", err)
			return nil, nil, errors.New(util.ErrLoginToken)
		}

		custKey := jwt.CreateCustomKey(user.TokenHash, fmt.Sprint(user.UserID))

		refreshToken, err := jwt.GenerateRefreshToken(fmt.Sprint(user.UserID), custKey, s.configs.JwtSecret)
		if err != nil {
			level.Error(s.logger).Log("msg", "unable to generate refresh token", "err", err)
			return nil, nil, errors.New(util.ErrLoginToken)
		}

		token := make(map[string]string)
		token["access_token"] = accessToken
		token["refresh_token"] = refreshToken

		return user, token, nil

	}
	if !isEmailExist {
		// register & login
		uuid, err := util.GenerateUUID()
		if err != nil {
			level.Error(s.logger).Log("err", err.Error())
			return nil, nil, errors.New(util.ErrInternalServerError)
		}

		hashedPass, err := util.PasswordHashing(util.GeneratePassword())
		if err != nil {
			level.Error(s.logger).Log("err", err.Error())
			return nil, nil, errors.New(util.ErrInternalServerError)
		}

		tokenHash := util.GenerateRandomString(15)

		var user datastruct.UserInformation
		user.UserID = uuid
		user.Email = claims.Email
		user.Firstname = claims.GivenName
		user.Lastname = claims.FamilyName
		user.Password = hashedPass
		user.ImageFile = claims.Picture
		user.TokenHash = tokenHash
		user.CreatedBy = "sadhelx.auth.service"
		user.CreatedDate = util.GetNow()
		user.UpdatedBy = "sadhelx.auth.service"
		user.UpdatedDate = util.GetNow()
		user.EmailVerified = true

		if err := s.repository.CreateUser(ctx, &user); err != nil {
			level.Error(s.logger).Log("err", err.Error())
			return nil, nil, errors.New(util.ErrUserCreation)
		}

		accessToken, err := jwt.GenerateAccessToken(fmt.Sprint(user.UserID), int64(s.configs.JwtExpiration), s.configs.JwtSecret)
		if err != nil {
			level.Error(s.logger).Log("msg", "unable to generate access token", "err", err)
			return nil, nil, errors.New(util.ErrLoginToken)
		}

		custKey := jwt.CreateCustomKey(user.TokenHash, fmt.Sprint(user.UserID))

		refreshToken, err := jwt.GenerateRefreshToken(fmt.Sprint(user.UserID), custKey, s.configs.JwtSecret)
		if err != nil {
			level.Error(s.logger).Log("msg", "unable to generate refresh token", "err", err)
			return nil, nil, errors.New(util.ErrLoginToken)
		}

		token := make(map[string]string)
		token["access_token"] = accessToken
		token["refresh_token"] = refreshToken
		// return nil, nil, nil

		return &user, token, nil
	}
	return nil, nil, errors.New(util.ErrInternalServerError)
	// return nil, nil, nil
}

func (s *service) Login(ctx context.Context, identity string, password string) (*datastruct.UserInformation, map[string]string, error) {

	var err error
	var user *datastruct.UserInformation

	if strings.Contains(identity, "@") {
		user, err = s.repository.GetUserByEmail(ctx, identity)
		if err != nil && err == sql.ErrNoRows {
			return nil, nil, errors.New(util.ErrInvalidUsernameEmail)
		}

		if err != nil {
			level.Error(s.logger).Log("err", err)
			return nil, nil, err
		}
	} else {
		user, err = s.repository.GetUserByUsername(ctx, identity)
		if err != nil && err == sql.ErrNoRows {
			return nil, nil, errors.New(util.ErrInvalidUsernameEmail)
		}
		if err != nil {
			level.Error(s.logger).Log("err", err)
			return nil, nil, err
		}
	}

	if !user.EmailVerified {
		return nil, nil, errors.New(util.ErrEmailUnverified)
	}

	if err := util.PasswordCompare(user.Password, password); err != nil {
		fmt.Println(err)
		return nil, nil, errors.New(util.ErrInvalidPassword)
	}

	accessToken, err := jwt.GenerateAccessToken(fmt.Sprint(user.UserID), int64(s.configs.JwtExpiration), s.configs.JwtSecret)
	if err != nil {
		level.Error(s.logger).Log("msg", "unable to generate access token", "err", err)
		return nil, nil, errors.New(util.ErrLoginToken)
	}

	custKey := jwt.CreateCustomKey(user.TokenHash, fmt.Sprint(user.UserID))

	refreshToken, err := jwt.GenerateRefreshToken(fmt.Sprint(user.UserID), custKey, s.configs.JwtSecret)
	if err != nil {
		level.Error(s.logger).Log("msg", "unable to generate refresh token", "err", err)
		return nil, nil, errors.New(util.ErrLoginToken)
	}

	token := make(map[string]string)
	token["access_token"] = accessToken
	token["refresh_token"] = refreshToken

	return user, token, nil
}

func (s *service) UsernameAvailability(ctx context.Context, username string) (string, error) {
	isExist, err := s.repository.UsernameIsExist(ctx, username)
	if err != nil {
		level.Error(s.logger).Log("msg", "unable check usernmae availability", "err", err)
		return "", errors.New(util.ErrDBPostgre)
	}
	if isExist && err == nil {
		return "", errors.New(util.ErrUsernameAvailability)
	}
	return util.MsgUserAvail, nil
}

func (s *service) EmailAvailability(ctx context.Context, email string) (string, error) {
	isExist, err := s.repository.EmailIsExist(ctx, email)
	if err != nil {
		level.Error(s.logger).Log("msg", "unable check email availability", "err", err)
		return "", err
	}
	if isExist && err == nil {
		return "", errors.New(util.ErrEmailAvailability)
	}
	return util.MsgEmailAvail, nil
}

func (s *service) VerifyPasswordReset(ctx context.Context, identity, code string) (bool, string, error) {

	var user *datastruct.UserInformation
	var actualVerificationData *datastruct.VerificationData
	var verificationData datastruct.VerificationData

	var err error
	if strings.Contains(identity, "@") {
		user, err = s.repository.GetUserByEmail(ctx, identity)
		if err != nil && err == sql.ErrNoRows {
			return false, "", errors.New(util.ErrInvalidUsernameEmail)
		}

		if err != nil {
			level.Error(s.logger).Log("err", err)
			return false, "", err
		}
	} else {
		user, err = s.repository.GetUserByUsername(ctx, identity)
		if err != nil && err == sql.ErrNoRows {
			return false, "", errors.New(util.ErrInvalidUsernameEmail)
		}
		if err != nil {
			level.Error(s.logger).Log("err", err)
			return false, "", err
		}
	}

	verificationData.Code = code
	verificationData.Email = user.Email
	verificationData.Type = datastruct.VerificationDataType(2)
	actualVerificationData, err = s.repository.GetVerificationData(ctx, user.Email, 2)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return false, "", err
	}

	_, err = verifyCode(actualVerificationData, verificationData)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return false, "", err
	}

	return true, code, nil
}

func (s *service) GetResetPasswordCode(ctx context.Context, identity string) (bool, error) {
	var user *datastruct.UserInformation
	var err error
	if strings.Contains(identity, "@") {
		user, err = s.repository.GetUserByEmail(ctx, identity)
		if err != nil && err == sql.ErrNoRows {
			return false, errors.New(util.ErrInvalidUsernameEmail)
		}

		if err != nil {
			level.Error(s.logger).Log("err", err)
			return false, err
		}
	} else {
		user, err = s.repository.GetUserByUsername(ctx, identity)
		if err != nil && err == sql.ErrNoRows {
			return false, errors.New(util.ErrInvalidUsernameEmail)
		}
		if err != nil {
			level.Error(s.logger).Log("err", err)
			return false, err
		}
	}

	code, err := util.GenerateRandom6Digits()
	if err != nil {
		return false, errors.New(util.ErrGenerateOTP)
	}

	// mailData := &MailDataTemplate{
	// 	Username: user.Username,
	// 	// Code:     strings.ToUpper(util.GenerateRandomString(4)),
	// 	Code: fmt.Sprint(code),
	// }
	verificationData := &datastruct.VerificationData{
		Email:     user.Email,
		Code:      fmt.Sprint(code),
		Type:      datastruct.VerificationDataType(PassReset),
		ExpiresAt: time.Now().Add(time.Minute * time.Duration(30)),
	}

	// _, err = sendEmailVerification(mailData, PassReset, user, s.configs)
	// if err != nil {
	// 	level.Error(s.logger).Log("err", err.Error())
	// 	return false, errors.New(util.ErrEmailSend)
	// }

	// Send verification mail
	from := "sandbox.repoerna@gmail.com"
	to := []string{user.Email}
	subject := "Email Verification for Bookite"
	mailType := mailer.PassReset
	mailData := &mailer.MailData{
		Username: user.Username,
		Code:     fmt.Sprint(code),
	}

	mailReq := s.mailer.NewMail(from, to, subject, mailType, mailData)
	if err = s.mailer.SendMail(mailReq); err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return false, errors.New("can't send verification email")

	}

	if err = s.repository.CreateVerificationData(ctx, verificationData); err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return false, errors.New(util.ErrDBPostgre)
	}
	return true, nil
}

func (s *service) RefreshToken(ctx context.Context, identity, customKey string) (string, error) {
	user, err := s.repository.GetUserByUsername(ctx, identity)
	if err != nil {
		return "", err
	}

	getCustomKey := jwt.CreateCustomKey(user.TokenHash, fmt.Sprint(user.UserID))

	actualCustomKey := jwt.GenerateCustomKey(getCustomKey)

	level.Debug(s.logger).Log("actual", actualCustomKey, "get", customKey)

	if customKey != actualCustomKey {
		return "", errors.New(util.ErrUnauthorized)
	}

	token, err := jwt.GenerateAccessToken(fmt.Sprint(user.UserID), int64(s.configs.JwtExpiration), s.configs.JwtSecret)
	if err != nil {
		return "", errors.New(util.ErrGenerateToken)
	}

	return token, nil
}

func (s *service) ResetPassword(ctx context.Context, identity, password, passwordRe, code string) error {

	var user *datastruct.UserInformation
	var actualVerificationData *datastruct.VerificationData
	var verificationData datastruct.VerificationData
	var err error

	if strings.Contains(identity, "@") {
		user, err = s.repository.GetUserByEmail(ctx, identity)
		if err != nil {
			level.Error(s.logger).Log("err", err.Error())
			return err
		}
	} else {
		user, err = s.repository.GetUserByUsername(ctx, identity)
		if err != nil {
			level.Error(s.logger).Log("err", err.Error())
			return err
		}
	}

	verificationData.Code = code
	verificationData.Email = user.Email
	verificationData.Type = datastruct.VerificationDataType(2)
	actualVerificationData, err = s.repository.GetVerificationData(ctx, user.Email, 2)
	if err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return err
	}

	// fmt.Println(actualVerificationData.Code)
	// fmt.Println(verificationData.Code)
	_, err = verifyCode(actualVerificationData, verificationData)
	if err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return err
	}

	if password != passwordRe {
		level.Error(s.logger).Log("err", util.ErrPassordNotMatched)
		return errors.New(util.ErrPassordNotMatched)
	}

	hashedPass, err := util.PasswordHashing(password)
	if err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return err
	}

	tokenHash := util.GenerateRandomString(15)

	if err := s.repository.UpdateUserPassword(ctx, user.Email, hashedPass, tokenHash); err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return errors.New(util.ErrDBPostgre)
	}

	if err = s.repository.DeleteVerificationData(ctx, actualVerificationData); err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return errors.New(util.ErrDBPostgre)
	}
	return nil
}

func (s *service) AddUserAvatar(ctx context.Context, identity string, file multipart.File, fileHeader *multipart.FileHeader) (string, error) {
	var err error
	var user *datastruct.UserInformation

	if strings.Contains(identity, "@") {
		user, err = s.repository.GetUserByEmail(ctx, identity)
		if err != nil && err == sql.ErrNoRows {
			return "", errors.New(util.ErrInvalidUsernameEmail)
		}
		if err != nil {
			level.Error(s.logger).Log("err", err.Error())
			return "", err
		}
	} else {
		user, err = s.repository.GetUserByUsername(ctx, identity)
		if err != nil && err == sql.ErrNoRows {
			return "", errors.New(util.ErrInvalidUsernameEmail)
		}
		if err != nil {
			level.Error(s.logger).Log("err", err.Error())
			return "", err
		}
	}

	defer file.Close()
	avatarName := fmt.Sprintf("%s-avatar.png", user.Username)
	avatar, err := os.Create(fmt.Sprintf("assets/user-avatar/%s", avatarName))
	if err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return "", errors.New(util.ErrUpdateAvatar)
	}
	defer avatar.Close()
	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return "", errors.New(util.ErrUpdateAvatar)
	}

	_, err = avatar.Write(fileBytes)
	if err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return "", errors.New(util.ErrUpdateAvatar)
	}

	user.ImageFile = avatarName
	if err := s.repository.UpdateUserAvatar(ctx, user); err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return "", errors.New(util.ErrDBPostgre)
	}

	return user.ImageFile, nil
}

func (s *service) VerifyUserEmail(ctx context.Context, identity, code string) (bool, error) {
	var user *datastruct.UserInformation
	var actualVerificationData *datastruct.VerificationData
	var verificationData datastruct.VerificationData

	var err error
	if strings.Contains(identity, "@") {
		user, err = s.repository.GetUserByEmail(ctx, identity)
		if err != nil && err == sql.ErrNoRows {
			return false, errors.New(util.ErrInvalidUsernameEmail)
		}

		if err != nil {
			level.Error(s.logger).Log("err", err)
			return false, err
		}
	} else {
		user, err = s.repository.GetUserByUsername(ctx, identity)
		if err != nil && err == sql.ErrNoRows {
			return false, errors.New(util.ErrInvalidUsernameEmail)
		}
		if err != nil {
			level.Error(s.logger).Log("err", err)
			return false, err
		}
	}

	verificationData.Code = code
	verificationData.Email = user.Email
	verificationData.Type = datastruct.VerificationDataType(MailConfirmation)
	actualVerificationData, err = s.repository.GetVerificationData(ctx, user.Email, int(MailConfirmation))
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return false, err
	}

	_, err = verifyCode(actualVerificationData, verificationData)
	if err != nil {
		level.Error(s.logger).Log("err", err)
		return false, err
	}

	user.EmailVerified = true
	if err := s.repository.UpdateEmailVerified(ctx, user); err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return false, errors.New(util.ErrDBPostgre)
	}

	if err = s.repository.DeleteVerificationData(ctx, actualVerificationData); err != nil {
		level.Error(s.logger).Log("err", err.Error())
		return false, errors.New(util.ErrDBPostgre)
	}

	return true, nil
}

func verifyCode(actualVerificationData *datastruct.VerificationData, verificationData datastruct.VerificationData) (bool, error) {

	// check for expiration
	if actualVerificationData.ExpiresAt.Before(time.Now()) {
		return false, errors.New(util.ErrPasswordResetCodeExpired)
	}

	if actualVerificationData.Code != verificationData.Code {
		return false, errors.New(util.ErrPasswordResetCodeInvalid)
	}

	return true, nil
}

// SendEmailVerification ..
func sendEmailVerification(mailData *MailDataTemplate, typeCode MailType, user *datastruct.UserInformation, conf *util.Configurations) (bool, error) {

	// var expireDuration int
	var emailSubject string
	var templatePath string

	if typeCode == 1 {
		emailSubject = "Email Verification"
		// expireDuration = auth.configs.MailVerifCodeExpiration
		templatePath = conf.MailVerifTemplatePath

	} else if typeCode == 2 {
		emailSubject = "Password Reset Request"
		// expireDuration = auth.configs.PassResetCodeExpiration
		templatePath = conf.PassResetTemplatePath

	}

	mailConf := mailer.NewConfig(
		"sadlex.auth.service",
		"sadhelx.info@gmail.com",
		"ugmdomeenewdxvau",
		"smtp.gmail.com",
		587,
	)

	mailReq := mailer.NewRequest(
		"sadhelx.info@gmail.com",
		emailSubject,
		"",
		user.Email,
	)
	if err := mailReq.WithTemplate(
		templatePath,
		mailData,
	); err != nil {
		return false, err
	}

	ok, err := mailReq.SendEmailWithConfig(mailConf)

	return ok, err
}
