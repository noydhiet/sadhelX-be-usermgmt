package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"runtime/debug"
	"shadelx-be-usermgmt/datastruct"
	"shadelx-be-usermgmt/service/auth/pkg/jwt"

	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"gopkg.in/go-playground/validator.v9"
	en_translations "gopkg.in/go-playground/validator.v9/translations/en"
)

type GenericResponse struct {
	Status  bool        `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}
type UserKey struct{}

const lowerAlphaNumericPeriod = "[A-Z,!,@,#,$,%,^,&,*,(,),-,+,+,{,},\\[,\\],\\\\,|,;,:,\",',<,>,?,/,\\,]"

// const lowerCaseAlphaNumericPeriod = "[+,*,?,^,$,(,),[,\\],{,},|,!,@,#,%,&,-,=,\\,\\/,<,>,;,:,\",',.,-,A-Z,\\s]gm"

var (
	lowerAlphaNumericPeriodRegex = regexp.MustCompile(lowerAlphaNumericPeriod)
)

func IsUsernameValid(fl validator.FieldLevel) bool {
	username := fl.Field().String()

	// fmt.Println(lowerAlphaNumericPeriodRegex.MatchString(username))
	if lowerAlphaNumericPeriodRegex.MatchString(username) {
		return false
	}

	return true
	// return lowerCaseAlphaNumericPeriodRegex.MatchString(field.String())
}

func MiddlewareValidateUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// w.Header().Set("Content-Type", "application/json")

		// ah.logger.Debug("user json", r.Body)
		fmt.Println("step-1")

		user := &datastruct.UserInformation{}
		if e := json.NewDecoder(r.Body).Decode(&user); e != nil {
			fmt.Println(e)
			w.WriteHeader(http.StatusInternalServerError)
			ToJSON(&Response{Status: false, Message: "can't decode request"}, w)
			return
		}
		fmt.Println(user)

		fmt.Println("step-2")

		translator := en.New()
		uni := ut.New(translator, translator)

		// this is usually known or extracted from http 'Accept-Language' header
		// also see uni.FindTranslator(...)
		trans, found := uni.GetTranslator("en")
		if !found {
			fmt.Println("translator not found")
			// level.Debug(log.).Log("err", "translator not found")
		}

		v := validator.New()

		if err := en_translations.RegisterDefaultTranslations(v, trans); err != nil {
			fmt.Println(err)
		}

		_ = v.RegisterTranslation("username", trans, func(ut ut.Translator) error {
			return ut.Add("username", "Only use lowercase alphanumeric (a-z & 0-9), and period (.) caracters allowed", false) // see universal-translator for details
		}, func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("username", fe.Field())
			return t
		})

		_ = v.RegisterTranslation("required", trans,
			func(ut ut.Translator) error {
				return ut.Add("required", "{0} is a required field", true) // see universal-translator for details
			},
			func(ut ut.Translator, fe validator.FieldError) string {
				fld, _ := ut.T("required", fe.Field())
				t, err := ut.T(fe.Tag(), fld)
				if err != nil {
					return fe.(error).Error()
				}
				return t
			})

		_ = v.RegisterValidation("passwd", func(fl validator.FieldLevel) bool {
			return len(fl.Field().String()) > 6
		})

		_ = v.RegisterValidation("username", IsUsernameValid)

		fmt.Println("step-3")

		// validate the user
		err := v.Struct(user)
		fmt.Println(err)
		if err != nil {
			fmt.Println("step-4")
			// fmt.Println(err)

			// var errorList map[string]string
			// for i, e := range err.(validator.ValidationErrors) {
			// 	errorList[string(i)] = e.Translate(trans)
			// }
			// ah.logger.Error("validation of user json failed", "error", errs)
			w.WriteHeader(http.StatusBadRequest)
			// ToJSON(&Response{Status: false, Message: "Bad Request", Data: errorList}, w)
			ToJSON(&Response{Status: false, Message: "Bad Request", Data: err.(validator.ValidationErrors).Translate(trans)}, w)

			return
		}

		fmt.Println("step-5")

		// add the user to the context
		// ctx := context.WithValue(r.Context(), UserKey{}, *user)
		// r = r.WithContext(ctx)

		// call the next handler
		next.ServeHTTP(w, r)
	})
}

func MiddlewareValidateRefreshToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// w.Header().Set("Content-Type", "application/json")

		// ah.logger.Debug("validating refresh token")
		// ah.logger.Debug("auth header", r.Header.Get("Authorization"))
		token, err := extractToken(r)
		if err != nil {
			// ah.logger.Error("token not provided or malformed")
			w.WriteHeader(http.StatusBadRequest)
			ToJSON(&Response{Status: false, Message: "Authentication failed. Token not provided or malformed"}, w)
			return
		}

		fmt.Println(token)
		mKey, err := jwt.ValidateRefreshToken(token)

		fmt.Println(mKey)
		if err != nil {
			// ah.logger.Error("token validation failed", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			ToJSON(&Response{Status: false, Message: "Authentication failed. Invalid token"}, w)
			return
		}
		// ah.logger.Debug("refresh token validated")

		// ah.logger.Debug("token present in header", token)

		ctxReq := context.WithValue(r.Context(), UserKey{}, mKey)
		r = r.WithContext(ctxReq)

		next.ServeHTTP(w, r)
	})
}

func extractToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	authHeaderContent := strings.Split(authHeader, " ")
	if len(authHeaderContent) != 2 {
		return "", errors.New("Token not provided or malformed")
	}
	return authHeaderContent[1], nil
}

// LoggingMiddleware logs the incoming HTTP request & its duration.
func LoggingMiddleware(logger log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					logger.Log(
						"err", err,
						"trace", debug.Stack(),
					)
				}
			}()

			start := time.Now()
			wrapped := wrapResponseWriter(w)
			next.ServeHTTP(wrapped, r)

			bufReq := new(bytes.Buffer)
			bufReq.ReadFrom(r.Body)
			req := bufReq.String()

			// bufRes := new(bytes.Buffer)
			// bufRes.ReadFrom()

			level.Info(logger).Log(
				"status", wrapped.status,
				"method", r.Method,
				"path", r.URL.EscapedPath(),
				"duration", time.Since(start),
				"req", req,
				// "res",
			)
		}

		return http.HandlerFunc(fn)
	}
}

type responseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func wrapResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w}
}

func (rw *responseWriter) Status() int {
	return rw.status
}

func (rw *responseWriter) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}

	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
	rw.wroteHeader = true

	return
}

// ToJSON serializes the given interface into a string based JSON format
func ToJSON(i interface{}, w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(i)
}

// FromJSON deserializes the object from JSON string
// given in the io.Reader to the given interface
func FromJSON(i interface{}, r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(i)
}
