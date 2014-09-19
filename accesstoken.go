package accesstoken

import (
	"crypto/hmac"
	"crypto/md5"
	"github.com/go-martini/martini"
	"github.com/vmihailenco/msgpack"
	vm_signer "github.com/vmihailenco/signer"
	"hash"
	"net/http"
	"time"
)

func GetUserIDAndExpiryTimeAccessToken(accessToken []byte, signer *vm_signer.Base64Signer) ([]byte, bool) {
	return signer.Verify(accessToken)
}

func GenerateUserIDAndExpiryTimeAccessToken(
	userID []byte, expiryTime time.Duration, secret string, version int8,
) []byte {
	h := hmac.New(func() hash.Hash {
		return md5.New()
	}, []byte(secret))
	s := vm_signer.NewBase64Signer(h)
	u := map[string]interface{}{
		"version": version, "userID": userID, "expiryTime": expiryTime,
	}
	data, err := msgpack.Marshal(u)
	if err != nil {
		panic(err)
	}
	return s.Sign(data)
}

type ProcessError struct {
	error string
}

func (e ProcessError) Error() string {
	return e.error
}

func NewProcessError(text string) error {
	return &ProcessError{text}
}

type ExpiredError struct {
	error string
}

func (e ExpiredError) Error() string {
	return e.error
}

func NewExpiredError(text string) error {
	return &ExpiredError{text}
}

type AuthContextInterface interface {
	GetAccessToken() ([]byte, bool)
}

type AuthContext struct {
	secret      string
	accessToken []byte
}

func (ac AuthContext) GetAccessTokenRawBytes() ([]byte, bool) {
	h := hmac.New(func() hash.Hash {
		return md5.New()
	}, []byte(ac.secret))
	signer := vm_signer.NewBase64Signer(h)
	return GetUserIDAndExpiryTimeAccessToken(
		ac.accessToken, signer,
	)
}

func (ac AuthContext) GetAccessTokenData() (map[string]interface{}, error) {
	data, ok := ac.GetAccessTokenRawBytes()
	var out map[string]interface{}
	if ok {
		err := msgpack.Unmarshal(data, &out)
		if err != nil {
			return nil, err
		}
		if expiryTime, ok := out["expiryTime"].(int64); ok {
			expiresAt := time.Duration(expiryTime)
			now := time.Duration(time.Now().UTC().Unix())
			if expiresAt < now {
				return nil, NewExpiredError("AccessToken expired")
			}
		} else {
			return nil, NewProcessError("expiryTime not processable")
		}
		return out, nil
	}
	return nil, NewProcessError("AccessToken not processable")
}

func AttachAuthContext(secret string, accessTokenHeaderField string) martini.Handler {
	return func(res http.ResponseWriter, req *http.Request, c martini.Context) {
		accessToken := []byte(req.Header.Get(accessTokenHeaderField))
		if accessToken != nil {
			ac := AuthContext{secret, accessToken}
			c.Map(ac)
		}
	}
}
