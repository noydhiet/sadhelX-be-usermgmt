package auth

import (
	"context"
	"net/http"

	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
)

// NewHTTPServer ...
func NewHTTPServer(ctx context.Context, endpoints Endpoints) http.Handler {
	baseR := mux.NewRouter()

	baseR.Methods(http.MethodPost).Path("/signup").Handler(httptransport.NewServer(
		endpoints.Signup,
		decodeSignupRequest,
		encodeResponse,
	))

	baseR.Methods(http.MethodPost).Path("/login").Handler(httptransport.NewServer(
		endpoints.Login,
		decodeLoginRequest,
		encodeResponse,
	))

	baseR.Methods(http.MethodPost).Path("/refresh-token").Handler(httptransport.NewServer(
		endpoints.RefresToken,
		decodeRefreshTokenRequest,
		encodeResponse,
	))

	baseR.Methods(http.MethodGet).Path("/check-username/{username}").Handler(httptransport.NewServer(
		endpoints.UsernameAvailability,
		decodeUsernameAvailabilityRequest,
		encodeResponse,
	))

	// @ %40
	baseR.Methods(http.MethodGet).Path("/check-email/{email}").Handler(httptransport.NewServer(
		endpoints.EmailAvailability,
		decodeEmailAvailabilityRequest,
		encodeResponse,
	))

	return baseR

}

// JSONHeader ...
func JSONHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}
