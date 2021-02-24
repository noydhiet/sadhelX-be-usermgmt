package util

import (
	crand "crypto/rand"
	"math/big"
	"math/rand"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// GenerateUUID in uint32 format
func GenerateUUID() (uint32, error) {
	uuid, err := uuid.NewUUID()
	if err != nil {
		// logging.Error("error generate uuid")
		return 0, err
	}

	return uuid.ID(), nil
}

// PasswordHashing ...
func PasswordHashing(raw string) (string, error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPass), nil
}

//PasswordCompare two passwords
func PasswordCompare(p1, p2 string) error {
	err := bcrypt.CompareHashAndPassword([]byte(p1), []byte(p2))
	if err != nil {
		return err
	}
	return nil
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// GenerateRandomString ...
func GenerateRandomString(n int) string {
	rand.Seed(time.Now().UTC().UnixNano())
	sb := strings.Builder{}
	sb.Grow(n)
	for i := 0; i < n; i++ {
		idx := rand.Int63() % int64(len(letterBytes))
		sb.WriteByte(letterBytes[idx])
	}
	return sb.String()
}

// GetNow ...
func GetNow() time.Time {
	return time.Now().UTC()
}

// GenerateRandom4Digits ...
func GenerateRandom4Digits() (uint64, error) {
	rand.Seed(time.Now().UTC().UnixNano())
	max := big.NewInt(9999)
	n, err := crand.Int(crand.Reader, max)
	if err != nil {
		return 0, err
	}
	return n.Uint64(), nil
}
