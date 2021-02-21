package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type (
	// CustomKey contains to 2 string to create hmac
	CustomKey struct {
		Secret string
		Data   string
	}

	// RefreshTokenCustomClaims specifies the claims for refresh token
	RefreshTokenCustomClaims struct {
		UserData  string
		CustomKey string
		KeyType   string
		jwt.StandardClaims
	}

	// AccessTokenCustomClaims specifies the claims for access token
	AccessTokenCustomClaims struct {
		UserData string
		KeyType  string
		jwt.StandardClaims
	}
)

// CreateCustomKey ...
func CreateCustomKey(secret, data string) *CustomKey {
	return &CustomKey{
		Secret: secret,
		Data:   data,
	}
}

// GenerateCustomKey ...
func GenerateCustomKey(custKey *CustomKey) string {
	h := hmac.New(sha256.New, []byte(custKey.Secret))

	h.Write([]byte(custKey.Data))
	sha := hex.EncodeToString(h.Sum(nil))
	return sha
}

// GenerateAccessToken generates a new access token for the given user
func GenerateAccessToken(userData string, jwtExpiration int64, jwtSecret string) (string, error) {

	tokenType := "access"

	claims := AccessTokenCustomClaims{
		string(userData),
		tokenType,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * time.Duration(jwtExpiration)).Unix(),
			Issuer:    "sadlex.auth.service",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(jwtSecret))
}

// GenerateRefreshToken generate a new refresh token for the given user
func GenerateRefreshToken(userData string, custKey *CustomKey, jwtSecret string) (string, error) {

	key := GenerateCustomKey(custKey)

	tokenType := "refresh"

	claims := RefreshTokenCustomClaims{
		string(userData),
		key,
		tokenType,
		jwt.StandardClaims{
			Issuer: "sadlex.auth.service",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(jwtSecret))
}

//  ValidateRefreshToken(tokenString string) (string, string, error) {
func ValidateRefreshToken(tokenString string) (string, error) {

	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// if err := token.Method.(*jwt.SigningMethodHMAC); err != nil {
		// if err := token.Method.Verify(*jwt.SigningMethodHS256); err != nil {
		// 	return nil, errors.New("Unexpected signing method in auth token")
		// }
		// return token, nil

		// fmt.Println(err)

		fmt.Println(token.Valid)
		if jwt.GetSigningMethod("HS256") != token.Method {
			return nil, errors.New("Unexpected signing method in auth token")
		}

		fmt.Println("this code")
		fmt.Println(token)

		return []byte("bE8fsjU^BD$n%7"), nil
	})

	if token == nil && err != nil {
		fmt.Println("this err")
		fmt.Println(err)

		// auth.logger.Error("unable to parse claims", "error", err)
		return "", err
	}

	fmt.Println("here")

	claims, ok := token.Claims.(*RefreshTokenCustomClaims)
	// auth.logger.Debug("ok", ok)
	if !ok || !token.Valid || claims.UserData == "" || claims.KeyType != "refresh" {
		// auth.logger.Debug("could not extract claims from token")
		fmt.Println("this err too")
		fmt.Println(token.Valid)
		fmt.Println(claims)

		return "", errors.New("invalid token: authentication failed")
	}
	return claims.CustomKey, nil
}
