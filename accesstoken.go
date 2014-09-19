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

func GetUserIDAndExpiryTimeAccessToken(accessToken []byte, expiryTime time.Duration, signer *vm_signer.Base64TimeSigner) ([]byte, bool) {
	return signer.Verify(accessToken, expiryTime)
}

func GenerateUserIDAndExpiryTimeAccessToken(
	userID []byte, expiryTime time.Duration, secret string, version int8,
) []byte {
	h := hmac.New(func() hash.Hash {
		return md5.New()
	}, []byte(secret))
	s := vm_signer.NewBase64TimeSigner(h)
	u := map[string]interface{}{
		"version": version, "userID": userID, "expiryTime": expiryTime,
	}
	data, err := msgpack.Marshal(u)
	if err != nil {
		panic(err)
	}
	return s.Sign(data)
}

type AuthContextInterface interface {
	GetAccessToken() ([]byte, bool)
}

type AuthContext struct {
	expiryTime  time.Duration
	secret      string
	accessToken []byte
}

func (ac AuthContext) GetAccessToken() ([]byte, bool) {
	h := hmac.New(func() hash.Hash {
		return md5.New()
	}, []byte(ac.secret))
	signer := vm_signer.NewBase64TimeSigner(h)
	return GetUserIDAndExpiryTimeAccessToken(
		ac.accessToken, ac.expiryTime, signer,
	)
}

func AttachAuthContext(secret string, expiryTime time.Duration, accessTokenHeaderField string) martini.Handler {
	return func(res http.ResponseWriter, req *http.Request, c martini.Context) {
		accessToken := []byte(req.Header.Get(accessTokenHeaderField))
		if accessToken != nil {
			authContext := AuthContext{expiryTime, secret, accessToken}
			c.Map(authContext)
		}
	}
}
