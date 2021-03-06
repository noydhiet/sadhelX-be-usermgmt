package auth

import (
	"context"
	"fmt"
	"net/http"

	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
)

// NewHTTPServer ...
func NewHTTPServer(ctx context.Context, endpoints Endpoints) http.Handler {
	r := mux.NewRouter()

	storageR := r
	storageR.Use(ImageHeader)
	storageR.Path("/avatar-storage/{image_file}").HandlerFunc(avatarHandler)

	apiR := r
	apiR.Use(JSONHeader)

	postR := apiR.Methods(http.MethodPost).Subrouter()
	// postR.Use(MiddlewareValidateUser)

	regisR := apiR.Methods(http.MethodPost).Subrouter()
	// regisR.Use(MiddlewareValidateUser)

	regisR.Path("/signup").Handler(httptransport.NewServer(
		endpoints.Signup,
		decodeSignupRequest,
		encodeResponse,
	))

	postR.Path("/login").Handler(httptransport.NewServer(
		endpoints.Login,
		decodeLoginRequest,
		encodeResponse,
	))

	postR.Path("/get-password-reset-code").Handler(httptransport.NewServer(
		endpoints.GetResetPasswordCode,
		decodeGetResetPasswordCodeRequest,
		encodeResponse,
	))

	refTokenR := apiR.Methods(http.MethodPost).Subrouter()
	refTokenR.Use(MiddlewareValidateRefreshToken)
	refTokenR.Path("/refresh-token").Handler(httptransport.NewServer(
		endpoints.RefresToken,
		decodeRefreshTokenRequest,
		encodeResponse,
	))

	mailR := apiR.PathPrefix("/verify").Methods(http.MethodPost).Subrouter()
	mailR.Path("/password-reset").Handler(httptransport.NewServer(
		endpoints.VerifyPasswordReset,
		decodeVerifyPasswordReset,
		encodeResponse,
	))
	mailR.Path("/email").Handler(httptransport.NewServer(
		endpoints.VerfiyUserEmail,
		decodeVerifyUserEmail,
		encodeResponse,
	))

	putR := apiR.Methods(http.MethodPut).Subrouter()
	putR.Path("/reset-password").Handler(httptransport.NewServer(
		endpoints.ResetPassword,
		decodeResetPassword,
		encodeResponse,
	))

	putR.Path("/avatar-upload").Handler(httptransport.NewServer(
		endpoints.UpdateAvatar,
		decodeUpdateAvatar,
		encodeResponse,
	))

	getR := apiR.Methods(http.MethodGet).Subrouter()

	getR.Path("/check-username/{username}").Handler(httptransport.NewServer(
		endpoints.UsernameAvailability,
		decodeUsernameAvailabilityRequest,
		encodeResponse,
	))

	// @ %40
	getR.Path("/check-email/{email}").Handler(httptransport.NewServer(
		endpoints.EmailAvailability,
		decodeEmailAvailabilityRequest,
		encodeResponse,
	))

	return r

}

// JSONHeader ...
func JSONHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

// ImageHeader ...
func ImageHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "image/png")
		next.ServeHTTP(w, r)
	})
}

func avatarHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/jpeg")
	vars := mux.Vars(r)
	key := vars["image_file"]
	url := fmt.Sprintf("assets/user-avatar/%s", key)
	http.ServeFile(w, r, url)
}
