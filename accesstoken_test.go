package accesstoken

import (
	"github.com/go-martini/martini"
	"net/http"
	"net/http/httptest"
	"time"
	"testing"
	"fmt"
	"encoding/gob"
	"bytes"
)

func GetHome(authContext AuthContext, parms martini.Params) (int, string) {
	data, ok := authContext.GetAccessToken()
	if ok {
		buffer := bytes.NewBuffer(data)
		u := new(UserIDExpiryTime)
		decoder := gob.NewDecoder(buffer)
		err := decoder.Decode(u)
		fmt.Printf("UserIDExpiryTime.userID = %s\n", u.userID)
		fmt.Println("Error: ", err)
		// ToDo: continue from here
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
		[]byte("123456"), time.Duration(123), "secret",
	)
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Browzoo-Authorization", string(accessToken))
	m.ServeHTTP(recorder, req)
}
