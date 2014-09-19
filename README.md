accesstoken
===========

A martini middleware that handles access serialization / de-serialization before request handling and it also attaches a function to the request object which can be called by the actual view handler function to retrieve the de-serialized access token object.


Example
===========

import (
	"github.com/go-martini/martini"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func GetHome(authContext AuthContext, parms martini.Params) (int, string) {
	out, err := authContext.GetAccessTokenData()
	if err == nil {
		if userID, ok := out["userID"].(string); ok {
			if userID != "123456" {
				return http.StatusForbidden, "userID incorrect"
			}
		} else {
			return http.StatusInternalServerError, "userID not processable"
		}
		if expiryTime, ok := out["expiryTime"].(int64); ok {
			if expiryTime != 123 {
				return http.StatusForbidden, "expiryTime incorrect"
			}
		} else {
			return http.StatusInternalServerError, "expiryTime not processable"
		}
		if version, ok := out["version"].(int64); ok {
			if version != 0 {
				return http.StatusForbidden, "version incorrect"
			}
		} else {
			return http.StatusInternalServerError, "version not processable"
		}
		return http.StatusOK, "Got Home"
	}
	return http.StatusBadRequest, err.Error()
}

func Test_AccessToken(t *testing.T) {
	recorder := httptest.NewRecorder()
	m := martini.New()
	m.Use(AttachAuthContext(
		"secret", time.Duration(123), "X-Browzoo-Authorization",
	))
	r := martini.NewRouter()
	r.Get("/", GetHome)
	m.Action(r.Handle)

	// Verify the access token works
	accessToken := GenerateUserIDAndExpiryTimeAccessToken(
		[]byte("123456"), time.Duration(123), "secret", 0,
	)
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Browzoo-Authorization", string(accessToken))
	m.ServeHTTP(recorder, req)
	if recorder.Code != 200 {
		t.Error("ResponseRecorder.Code not 200; it's ", recorder.Code)
		t.Error("ResponseRecorder.Body ", recorder.Body)
	}
}

