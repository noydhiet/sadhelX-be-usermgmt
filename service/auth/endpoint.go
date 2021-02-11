package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"shadelx-be-usermgmt/datastruct"
	"shadelx-be-usermgmt/util"

	"github.com/go-kit/kit/endpoint"
	"github.com/gorilla/mux"
)

type (
	// Endpoints define all endpoint
	Endpoints struct {
		Signup               endpoint.Endpoint
		Login                endpoint.Endpoint
		UsernameAvailability endpoint.Endpoint
		EmailAvailability    endpoint.Endpoint
		RefresToken          endpoint.Endpoint
	}

	// SignupRequest data format
	SignupRequest struct {
		User datastruct.UserInformation
	}
	// SignupResponse data format
	SignupResponse struct {
		Message string `json:"msg"`
		Err     error  `json:"error,omitempty"`
	}
	// LoginRequest data format
	LoginRequest struct {
		Email    string
		Password string
	}
	// LoginResponse data format
	LoginResponse struct {
		// Token token `json:"token"`
		TokenAccess  string `json:"token_access"`
		TokenRefresh string `json:"token_refresh"`
		Err          error  `json:"error,omitempty"`
	}
	// UsernameAvailabilityRequest data format
	UsernameAvailabilityRequest struct {
		Username string `json:"username"`
	}
	// EmailAvailabilityRequest data format
	EmailAvailabilityRequest struct {
		Email string `json:"email"`
	}
	// RefresTokenRequest data format
	RefresTokenRequest struct {
		Username string `json:"username"`
	}
	// Response format
	Response struct {
		Status  bool        `json:"status"`
		Message string      `json:"msg"`
		Data    interface{} `json:"data,omitempty"`
	}
	token struct {
		TokenAccess  string `json:"token_access,omitempty"`
		TokenRefresh string `json:"token_refresh,omitempty"`
	}
)

// MakeAuthEndpoints ...
func MakeAuthEndpoints(svc Service) Endpoints {
	return Endpoints{
		Signup:               makeSignupEndpoint(svc),
		Login:                makeLoginEndopint(svc),
		UsernameAvailability: makeUsernameAvailabilityRequest(svc),
		EmailAvailability:    makeEmailAvailabilityRequest(svc),
		RefresToken:          makeRefreshTokenEndopint(svc),
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

func makeUsernameAvailabilityRequest(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(UsernameAvailabilityRequest)

		ok, err := svc.UsernameAvailability(ctx, req.Username)
		if err != nil {
			return Response{Status: false, Message: err.Error()}, nil

		} else if ok {
			return Response{Status: true, Message: "User available"}, nil

		}
		return Response{Status: false, Message: util.ErrInternalServerError}, nil

	}

}

func makeEmailAvailabilityRequest(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(EmailAvailabilityRequest)

		ok, err := svc.EmailAvailability(ctx, req.Email)
		if err != nil {
			return Response{Status: false, Message: err.Error()}, nil

		} else if ok && err == nil {
			return Response{Status: true, Message: "User available"}, nil

		}
		return Response{Status: false, Message: util.ErrInternalServerError}, nil

	}

}

func makeRefreshTokenEndopint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(RefresTokenRequest)
		res, err := svc.RefreshToken(ctx, req.Username)
		if res == "" && err != nil {
			return Response{
				Status:  false,
				Message: err.Error(),
			}, nil
		}

		if res != "" && err == nil {
			return Response{
				Status: true,
				Data: token{
					TokenAccess: res,
				},
			}, nil

		}
		return Response{Status: false, Message: util.ErrInternalServerError}, nil
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

func decodeUsernameAvailabilityRequest(_ context.Context, r *http.Request) (request interface{}, err error) {
	var req UsernameAvailabilityRequest
	params := mux.Vars(r)
	username := params["username"]

	req.Username = username

	return req, nil
}

func decodeEmailAvailabilityRequest(_ context.Context, r *http.Request) (request interface{}, err error) {
	var req EmailAvailabilityRequest
	params := mux.Vars(r)
	email := params["email"]

	req.Email = email

	return req, nil
}

func decodeRefreshTokenRequest(_ context.Context, r *http.Request) (request interface{}, err error) {
	var req RefresTokenRequest
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
