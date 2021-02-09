package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"shadelx-be-usermgmt/datastruct"
	"shadelx-be-usermgmt/util"

	"github.com/go-kit/kit/endpoint"
)

type (
	Endpoints struct {
		Signup endpoint.Endpoint
		Login  endpoint.Endpoint
	}

	SignupRequest struct {
		User datastruct.UserInformation
	}
	SignupResponse struct {
		Message string `json:"msg"`
		Err     error  `json:"error,omitempty"`
	}
	LoginRequest struct {
		Email    string
		Password string
	}
	LoginResponse struct {
		// Token token `json:"token"`
		TokenAccess  string `json:"token_access"`
		TokenRefresh string `json:"token_refresh"`
		Err          error  `json:"error,omitempty"`
	}
	token struct {
		TokenAccess  string `json:"token_access"`
		TokenRefresh string `json:"token_refresh"`
	}
	UserKey struct{}
)

// MakeUserEndpoints ...
func MakeAuthEndpoints(svc Service) Endpoints {
	return Endpoints{
		Signup: makeSignupEndpoint(svc),
		Login:  makeLoginEndopint(svc),
	}
}

func makeSignupEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(SignupRequest)
		res, err := svc.Signup(ctx, req.User)
		return SignupResponse{Message: res, Err: err}, nil
	}
}

func makeLoginEndopint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(LoginRequest)
		res, err := svc.Login(ctx, req.Email, req.Password)
		if err != nil {
			return nil, err
		}

		return LoginResponse{
			TokenAccess:  res["access_token"],
			TokenRefresh: res["refresh_token"],
			Err:          err,
		}, nil
	}
}

func decodeSignupRequest(_ context.Context, r *http.Request) (request interface{}, err error) {
	var req SignupRequest
	if e := json.NewDecoder(r.Body).Decode(&req.User); e != nil {
		return nil, e
	}
	return req, nil
}

func decodeLoginRequest(_ context.Context, r *http.Request) (request interface{}, err error) {
	var req LoginRequest

	if e := json.NewDecoder(r.Body).Decode(&req); e != nil {
		return nil, e
	}
	return req, nil
}

func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeErrorResponse(ctx, e.error(), w)
		return nil
	}
	return json.NewEncoder(w).Encode(response)
}

type errorer interface {
	error() error
}

func encodeErrorResponse(_ context.Context, err error, w http.ResponseWriter) {
	if err == nil {
		panic("encodeError with nil error")
	}
	w.WriteHeader(codeFrom(err))
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": err.Error(),
	})
}

func codeFrom(err error) int {
	switch err {
	case util.ErrUserNotFound:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}
