package accesstoken

import (
	"fmt"
	"github.com/go-martini/martini"
	"github.com/vmihailenco/msgpack"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func GetHome(authContext AuthContext, parms martini.Params) (int, string) {
	data, ok := authContext.GetAccessToken()
	if ok {
		var out map[string]interface{}
		err := msgpack.Unmarshal(data, &out)
		if err != nil {
			fmt.Println(err)
		}
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
	}
	return http.StatusOK, "Got Home"
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
