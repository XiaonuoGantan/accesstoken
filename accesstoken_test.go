package accesstoken

import (
	"github.com/go-martini/martini"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func GetHome(authContext AuthContext, parms martini.Params) (int, string) {
	out, err := authContext.GetAccessTokenData()
	if err != nil {
		return http.StatusBadRequest, err.Error()
	}
	if err == nil {
		if userID, ok := out["userID"].(string); ok {
			if userID != "123456" {
				return http.StatusForbidden, "userID incorrect"
			}
		} else {
			return http.StatusInternalServerError, "userID not processable"
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
		"secret", "X-Browzoo-Authorization",
	))
	r := martini.NewRouter()
	r.Get("/", GetHome)
	m.Action(r.Handle)

	// Make an access token that expires in 10 seconds in the future
	accessToken := GenerateUserIDAndExpiryTimeAccessToken(
		[]byte("123456"), time.Duration(10*time.Second), "secret", 0,
	)
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Browzoo-Authorization", string(accessToken))
	m.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Error("ResponseRecorder.Code not 200; it's ", recorder.Code)
		t.Error("ResponseRecorder.Body ", recorder.Body)
	}

	// Make an access token that expires in 10 seconds in the past
	recorder = httptest.NewRecorder()
	accessToken = GenerateUserIDAndExpiryTimeAccessToken(
		[]byte("123456"), time.Duration(-10*time.Second), "secret", 0,
	)
	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Browzoo-Authorization", string(accessToken))
	m.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Error("ResponseRecorder.Code not 400; it's ", recorder.Code)
		t.Error("ResponseRecorder.Body ", recorder.Body)
	}
}
