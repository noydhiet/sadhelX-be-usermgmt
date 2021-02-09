package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
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

var (
	ErrBadRouting      = errors.New("bad routing")
	ErrUserNotFound    = errors.New("user not found")
	ErrCmdRepository   = errors.New("unable to command repository")
	ErrQueryRepository = errors.New("unable to query repository")
)

// RespErr ...
type RespErr interface {
	Message() string
	Status() int
	Error() string
	Causes() []interface{}
}

type respErr struct {
	ErrMessage string        `json:"message"`
	ErrStatus  int           `json:"status"`
	ErrError   string        `json:"error"`
	ErrCauses  []interface{} `json:"causes"`
}

func (e respErr) Error() string {
	return fmt.Sprintf("message: %s - status: %d - error: %s - causes: %v",
		e.ErrMessage, e.ErrStatus, e.ErrError, e.ErrCauses)
}

func (e respErr) Message() string {
	return e.ErrMessage
}

func (e respErr) Status() int {
	return e.ErrStatus
}

func (e respErr) Causes() []interface{} {
	return e.ErrCauses
}

// NewRespError ...
func NewRespError(message string, status int, err string, causes []interface{}) RespErr {
	return respErr{
		ErrMessage: message,
		ErrStatus:  status,
		ErrError:   err,
		ErrCauses:  causes,
	}
}

// NewRespErrorFromBytes ...
func NewRespErrorFromBytes(bytes []byte) (RespErr, error) {
	var apiErr respErr
	if err := json.Unmarshal(bytes, &apiErr); err != nil {
		return nil, errors.New("invalid json")
	}
	return apiErr, nil
}

// NewBadRequestError ...
func NewBadRequestError(message string) RespErr {
	return respErr{
		ErrMessage: message,
		ErrStatus:  http.StatusBadRequest,
		ErrError:   "bad_request",
	}
}

// NewNotFoundError ...
func NewNotFoundError(message string) RespErr {
	return respErr{
		ErrMessage: message,
		ErrStatus:  http.StatusNotFound,
		ErrError:   "not_found",
	}
}

// NewUnauthorizedError ...
func NewUnauthorizedError(message string) RespErr {
	return respErr{
		ErrMessage: message,
		ErrStatus:  http.StatusUnauthorized,
		ErrError:   "unauthorized",
	}
}

// NewInternalServerError ...
func NewInternalServerError(message string, err error) RespErr {
	result := respErr{
		ErrMessage: message,
		ErrStatus:  http.StatusInternalServerError,
		ErrError:   "internal_server_error",
	}
	if err != nil {
		result.ErrCauses = append(result.ErrCauses, err.Error())
	}
	return result
}
