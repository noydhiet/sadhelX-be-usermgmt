package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
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
		GoogleSignIn         endpoint.Endpoint
		UsernameAvailability endpoint.Endpoint
		EmailAvailability    endpoint.Endpoint
		RefresToken          endpoint.Endpoint
		GetResetPasswordCode endpoint.Endpoint
		VerifyPasswordReset  endpoint.Endpoint
		ResetPassword        endpoint.Endpoint
		UpdateAvatar         endpoint.Endpoint
		VerfiyUserEmail      endpoint.Endpoint
	}

	// SignupReq data format
	SignupReq struct {
		User datastruct.UserInformation
	}

	// LoginReq data format
	LoginReq struct {
		Identity string
		Password string
	}

	googleSignInReq struct {
		IDToken string `json:"id_token"`
	}

	// UsernameAvailabilityReq data format
	UsernameAvailabilityReq struct {
		Username string `json:"username"`
	}

	// EmailAvailabilityReq data format
	EmailAvailabilityReq struct {
		Email string `json:"email"`
	}

	// RefresTokenReq data format
	RefresTokenReq struct {
		Username  string `json:"username"`
		CustomKey string `json:"custom_key,omitempty"`
	}

	// GetResetPasswordCodeReq data format
	GetResetPasswordCodeReq struct {
		Identity string `json:"identity"`
	}

	// VerifyOTPCode data format
	VerifyOTPCode struct {
		Identity string `json:"identity"`
		Code     string `json:"code"`
	}

	// ResetPasswordReq data format
	ResetPasswordReq struct {
		Identity   string `json:"identity"`
		Password   string `json:"password"`
		PasswordRe string `json:"password_re"`
		Code       string `json:"code"`
	}

	// UploadAvatarReq ...
	UploadAvatarReq struct {
		Identity   string `json:"identity"`
		FileHeader *multipart.FileHeader
		File       multipart.File
	}
	// Response format
	Response struct {
		Status  bool        `json:"status"`
		Message string      `json:"msg"`
		Data    interface{} `json:"data,omitempty"`
	}
	tokenRes struct {
		TokenAccess  string `json:"token_access,omitempty"`
		TokenRefresh string `json:"token_refresh,omitempty"`
	}
	userRes struct {
		UserID    uint32 `json:"user_id,omitempty"`
		Username  string `json:"username,omitempty"`
		Email     string `json:"email,omitempty"`
		Firstname string `json:"firstname,omitempty"`
		ImageFile string `json:"image_file,omitempty"`
	}
	passwordResetCodeRes struct {
		Code string `json:"code,omitempty"`
	}
	addUserAvatarRes struct {
		Filename string `json:"file_name"`
	}
)

// MakeAuthEndpoints ...
func MakeAuthEndpoints(svc Service) Endpoints {
	return Endpoints{
		Signup:               makeSignupEndpoint(svc),
		Login:                makeLoginEndopint(svc),
		GoogleSignIn:         makeGoogleSignIn(svc),
		UsernameAvailability: makeUsernameAvailabilityRequest(svc),
		EmailAvailability:    makeEmailAvailabilityRequest(svc),
		RefresToken:          makeRefreshTokenEndopint(svc),
		GetResetPasswordCode: makeGetResetPasswordCodeEndpoint(svc),
		VerifyPasswordReset:  makeVerifyPasswordResetEndpoint(svc),
		VerfiyUserEmail:      makeVerifyUserEmailEndpoint(svc),
		ResetPassword:        makeResetPasswordEndpoint(svc),
		UpdateAvatar:         makeUpdateAvatar(svc),
	}
}

func makeSignupEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(SignupReq)

		_, err := svc.Signup(ctx, req.User)
		if err != nil {
			return Response{Status: false, Message: err.Error()}, nil
		}

		// var useSend userRes
		// useSend.UserID = user.UserID
		// useSend.Username = user.Username
		// useSend.Email = user.Email
		// useSend.Firstname = user.Firstname

		// data := make(map[string]interface{})
		// data["user"] = useSend

		return Response{Status: true, Message: util.MsgCreateUser}, nil
	}
}

func decodeSignupRequest(_ context.Context, r *http.Request) (request interface{}, err error) {
	var req SignupReq
	if e := json.NewDecoder(r.Body).Decode(&req.User); e != nil {
		return nil, e
	}
	return req, nil
}

func makeLoginEndopint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(LoginReq)
		user, token, err := svc.Login(ctx, req.Identity, req.Password)
		if err != nil {
			return Response{Status: false, Message: err.Error()}, nil
		}

		var tokenRes tokenRes
		tokenRes.TokenAccess = token["access_token"]
		tokenRes.TokenRefresh = token["refresh_token"]

		var userRes userRes
		userRes.UserID = user.UserID
		userRes.Username = user.Username
		userRes.Email = user.Email
		userRes.Firstname = user.Firstname
		userRes.ImageFile = user.ImageFile

		data := make(map[string]interface{})
		data["user"] = userRes
		data["token"] = tokenRes

		return Response{
			Status:  true,
			Message: util.MsgLoginSuccess,
			Data:    data,
		}, nil
	}
}

func decodeLoginRequest(_ context.Context, r *http.Request) (request interface{}, err error) {
	var req LoginReq

	if e := json.NewDecoder(r.Body).Decode(&req); e != nil {
		return nil, e
	}
	return req, nil
}

func makeGoogleSignIn(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(googleSignInReq)

		user, token, err := svc.GoogleSignIn(ctx, req.IDToken)
		if err != nil {
			// fmt.Println(err)
			return Response{Status: false, Message: err.Error()}, nil
		}

		var tokenRes tokenRes
		tokenRes.TokenAccess = token["access_token"]
		tokenRes.TokenRefresh = token["refresh_token"]

		var userRes userRes
		userRes.UserID = user.UserID
		userRes.Username = user.Username
		userRes.Email = user.Email
		userRes.Firstname = user.Firstname
		userRes.ImageFile = user.ImageFile

		data := make(map[string]interface{})
		data["user"] = userRes
		data["token"] = tokenRes

		return Response{
			Status:  true,
			Message: util.MsgLoginSuccess,
			Data:    data,
		}, nil
	}
}

func decodeGoogleSignIn(_ context.Context, r *http.Request) (request interface{}, err error) {
	var req googleSignInReq
	if e := json.NewDecoder(r.Body).Decode(&req); e != nil {
		return nil, e
	}
	return req, nil

}

func makeUsernameAvailabilityRequest(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(UsernameAvailabilityReq)

		res, err := svc.UsernameAvailability(ctx, req.Username)
		if err != nil {
			return Response{Status: false, Message: err.Error()}, nil
		}
		return Response{Status: true, Message: res}, nil
	}
}

func decodeUsernameAvailabilityRequest(_ context.Context, r *http.Request) (request interface{}, err error) {
	var req UsernameAvailabilityReq
	params := mux.Vars(r)
	username := params["username"]

	req.Username = username

	return req, nil
}

func makeEmailAvailabilityRequest(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(EmailAvailabilityReq)

		res, err := svc.EmailAvailability(ctx, req.Email)
		if err != nil {
			return Response{Status: false, Message: err.Error()}, nil
		}
		return Response{Status: true, Message: res}, nil
	}
}

func decodeEmailAvailabilityRequest(_ context.Context, r *http.Request) (request interface{}, err error) {
	var req EmailAvailabilityReq
	params := mux.Vars(r)
	email := params["email"]

	req.Email = email
	fmt.Println(email)
	return req, nil
}

func makeRefreshTokenEndopint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(RefresTokenReq)
		res, err := svc.RefreshToken(ctx, req.Username, req.CustomKey)
		if res == "" && err != nil {
			return Response{
				Status:  false,
				Message: err.Error(),
			}, nil
		}

		if res != "" && err == nil {
			return Response{
				Status: true,
				Data: tokenRes{
					TokenAccess: res,
				},
			}, nil

		}
		return Response{Status: false, Message: util.ErrInternalServerError}, nil
	}
}

func decodeRefreshTokenRequest(_ context.Context, r *http.Request) (request interface{}, err error) {
	var req RefresTokenReq
	if e := json.NewDecoder(r.Body).Decode(&req); e != nil {
		return nil, e
	}

	customKey, ok := r.Context().Value(UserKey{}).(string)
	if !ok {
		return nil, errors.New("Can't get context")
	}

	req.CustomKey = customKey

	return req, nil
}

func makeGetResetPasswordCodeEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(GetResetPasswordCodeReq)
		ok, err := svc.GetResetPasswordCode(ctx, req.Identity)
		if err != nil {
			return Response{Status: false, Message: err.Error()}, nil
		} else if ok && err == nil {
			return Response{Status: true, Message: util.MsgGeneratedPasswordResetCode}, nil
		}
		return Response{Status: false, Message: util.ErrInternalServerError}, nil

	}
}

func decodeGetResetPasswordCodeRequest(_ context.Context, r *http.Request) (request interface{}, err error) {
	var req GetResetPasswordCodeReq
	if e := json.NewDecoder(r.Body).Decode(&req); e != nil {
		return nil, e
	}
	return req, nil
}

func makeVerifyPasswordResetEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(VerifyOTPCode)
		ok, otpCode, err := svc.VerifyPasswordReset(ctx, req.Identity, req.Code)
		if err != nil {
			return Response{Status: false, Message: err.Error()}, nil
		} else if ok && err == nil {
			data := make(map[string]interface{})
			data["code"] = otpCode
			return Response{Status: true, Message: util.MsgVerifiedPasswordResetCode, Data: data}, nil
		}
		return Response{Status: false, Message: util.ErrInternalServerError}, nil
	}
}

func decodeVerifyPasswordReset(_ context.Context, r *http.Request) (request interface{}, err error) {
	var req VerifyOTPCode
	if e := json.NewDecoder(r.Body).Decode(&req); e != nil {
		return nil, e
	}
	return req, nil
}

func makeVerifyUserEmailEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(VerifyOTPCode)
		ok, err := svc.VerifyUserEmail(ctx, req.Identity, req.Code)
		if err != nil {
			return Response{Status: false, Message: err.Error()}, nil
		} else if ok && err == nil {

			return Response{Status: true, Message: util.MsgVerifyUserEmail}, nil
		}
		return Response{Status: false, Message: util.ErrInternalServerError}, nil
	}
}

func decodeVerifyUserEmail(_ context.Context, r *http.Request) (request interface{}, err error) {
	var req VerifyOTPCode
	if e := json.NewDecoder(r.Body).Decode(&req); e != nil {
		return nil, e
	}
	return req, nil
}

func makeResetPasswordEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(ResetPasswordReq)
		err := svc.ResetPassword(ctx, req.Identity, req.Password, req.PasswordRe, req.Code)
		if err != nil {
			return Response{Status: false, Message: err.Error()}, nil
		}
		return Response{Status: true, Message: util.MsgPasswordReset}, nil
	}
}

func decodeResetPassword(_ context.Context, r *http.Request) (request interface{}, err error) {
	var req ResetPasswordReq

	if e := json.NewDecoder(r.Body).Decode(&req); e != nil {
		return nil, e
	}
	return req, nil
}

func makeUpdateAvatar(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(UploadAvatarReq)
		filename, err := svc.AddUserAvatar(ctx, req.Identity, req.File, req.FileHeader)
		if err != nil {
			return Response{Status: false, Message: err.Error()}, nil
		}
		data := make(map[string]interface{})
		data["file_name"] = filename
		return Response{Status: true, Message: util.MsgUpdateAvatar, Data: data}, nil
	}
}

func decodeUpdateAvatar(_ context.Context, r *http.Request) (request interface{}, err error) {
	var req UploadAvatarReq

	r.ParseMultipartForm(32 << 20)
	identity := r.FormValue("identity")
	file, fileHeader, err := r.FormFile("avatar")
	if err != nil {
		fmt.Println("Error Retrieving the File")
		fmt.Println(err)
		return
	}

	req.Identity = identity
	req.File = file
	req.FileHeader = fileHeader

	return req, nil
}

func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	res := response.(Response)
	sc := util.StatusCode(res.Message)
	if sc == 0 {
		sc = 500
	}
	w.WriteHeader(sc)
	return json.NewEncoder(w).Encode(&res)
}
