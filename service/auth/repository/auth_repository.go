package repository

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"shadelx-be-usermgmt/datastruct"
	"shadelx-be-usermgmt/service/auth/pkg/mailer"
	"shadelx-be-usermgmt/util"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"golang.org/x/crypto/bcrypt"
)

type (
	// Authentication interface lists the methods that our authentication service should implement
	Authentication interface {
		Authenticate(reqUser *datastruct.UserInformation, user *datastruct.UserInformation) bool
		GenerateAccessToken(user *datastruct.UserInformation) (string, error)
		GenerateRefreshToken(user *datastruct.UserInformation) (string, error)
	}

	// RefreshTokenCustomClaims specifies the claims for refresh token
	RefreshTokenCustomClaims struct {
		UserID    uint32
		CustomKey string
		KeyType   string
		jwt.StandardClaims
	}

	// AccessTokenCustomClaims specifies the claims for access token
	AccessTokenCustomClaims struct {
		UserID  uint32
		KeyType string
		jwt.StandardClaims
	}

	// AuthRepository is the implementation of our Authentication
	AuthRepository struct {
		configs *util.Configurations
		logger  log.Logger
	}
)

// NewAuthRepo returns a new instance of the auth service
func NewAuthRepo(configs *util.Configurations, logger log.Logger) *AuthRepository {
	return &AuthRepository{
		configs,
		logger,
	}
}

// Authenticate checks the user credentials in request against the db and authenticates the request
func (auth *AuthRepository) Authenticate(password string, user *datastruct.UserInformation) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(password), []byte(user.Password)); err != nil {
		level.Debug(auth.logger).Log("msg", "password hashes are not same")
		level.Debug(auth.logger).Log("msg", "password")
		level.Debug(auth.logger).Log("msg", user.Password)

		return false
	}
	return true
}

// GenerateAccessToken generates a new access token for the given user
func (auth *AuthRepository) GenerateAccessToken(user *datastruct.UserInformation) (string, error) {

	userID := user.UserID
	tokenType := "access"

	claims := AccessTokenCustomClaims{
		userID,
		tokenType,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * time.Duration(auth.configs.JwtExpiration)).Unix(),
			Issuer:    "sadlex.auth.service",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(auth.configs.JwtSecret))
}

// GenerateRefreshToken generate a new refresh token for the given user
func (auth *AuthRepository) GenerateRefreshToken(user *datastruct.UserInformation) (string, error) {

	cusKey := auth.GenerateCustomKey(fmt.Sprint(user.UserID), user.TokenHash)
	tokenType := "refresh"

	claims := RefreshTokenCustomClaims{
		user.UserID,
		cusKey,
		tokenType,
		jwt.StandardClaims{
			Issuer: "sadlex.auth.service",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(auth.configs.JwtSecret))
}

// GenerateCustomKey creates a new key for our jwt payload
// the key is a hashed combination of the userID and user tokenhash
func (auth *AuthRepository) GenerateCustomKey(userID string, tokenHash string) string {

	h := hmac.New(sha256.New, []byte(tokenHash))
	h.Write([]byte(userID))
	sha := hex.EncodeToString(h.Sum(nil))
	return sha
}

// SendEmailVerification ..
func (auth *AuthRepository) SendEmailVerification(mailData *MailDataTemplate, user *datastruct.UserInformation, typeCode MailType) (bool, error) {

	// var expireDuration int
	var emailSubject string
	var templatePath string

	if typeCode == 1 {
		emailSubject = "Email Verification"
		// expireDuration = auth.configs.MailVerifCodeExpiration
		templatePath = auth.configs.MailVerifTemplatePath

	} else if typeCode == 2 {
		emailSubject = "Password Reset Request"
		// expireDuration = auth.configs.PassResetCodeExpiration
		templatePath = auth.configs.PassResetTemplatePath

	}
	// verificationData := &datastruct.VerificationData{
	// 	Email:     user.Email,
	// 	Code:      mailData.Code,
	// 	Type:      datastruct.VerificationDataType(typeCode),
	// 	ExpiresAt: time.Now().Add(time.Minute * time.Duration(expireDuration)),
	// }

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
		"user.Email",
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

// VerifyCode ...
func (auth *AuthRepository) VerifyCode(actualVerificationData *datastruct.VerificationData, verificationData *datastruct.VerificationData) (bool, error) {

	// check for expiration
	if actualVerificationData.ExpiresAt.Before(time.Now()) {
		return false, errors.New("Confirmation code has expired. Please try generating a new code")
	}

	if actualVerificationData.Code != verificationData.Code {
		return false, errors.New("Verification code provided is Invalid. Please look in your mail for the code")
	}

	return true, nil
}
