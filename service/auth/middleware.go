package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"shadelx-be-usermgmt/service/auth/pkg/jwt"
	"strings"
	"time"

	"github.com/d-vignesh/go-jwt-auth/data"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

type GenericResponse struct {
	Status  bool        `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}
type UserKey struct{}

func MiddlewareValidateRefreshToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// w.Header().Set("Content-Type", "application/json")

		// ah.logger.Debug("validating refresh token")
		// ah.logger.Debug("auth header", r.Header.Get("Authorization"))
		token, err := extractToken(r)
		if err != nil {
			// ah.logger.Error("token not provided or malformed")
			w.WriteHeader(http.StatusBadRequest)
			data.ToJSON(&Response{Status: false, Message: "Authentication failed. Token not provided or malformed"}, w)
			return
		}

		fmt.Println(token)
		mKey, err := jwt.ValidateRefreshToken(token)

		fmt.Println(mKey)
		if err != nil {
			// ah.logger.Error("token validation failed", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			data.ToJSON(&Response{Status: false, Message: "Authentication failed. Invalid token"}, w)
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
