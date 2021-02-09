package auth

import (
	"context"
	"net/http"

	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
)

// NewHTTPServer ...
func NewHTTPServer(ctx context.Context, endpoints Endpoints) http.Handler {
	r := mux.NewRouter()
	r.Use(JSONHeader)

	r.Methods("POST").Path("/signup").Handler(httptransport.NewServer(
		endpoints.Signup,
		decodeSignupRequest,
		encodeResponse,
	))

	r.Methods("POST").Path("/login").Handler(httptransport.NewServer(
		endpoints.Login,
		decodeLoginRequest,
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
