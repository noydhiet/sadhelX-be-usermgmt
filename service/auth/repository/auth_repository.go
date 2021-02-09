package repository

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"shadelx-be-usermgmt/datastruct"
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
