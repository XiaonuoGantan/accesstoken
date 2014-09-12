package accesstoken

import (
	"crypto/hmac"
	"crypto/md5"
	"github.com/go-martini/martini"
	vm_signer "github.com/vmihailenco/signer"
	"net/http"
	"time"
	"hash"
	"encoding/gob"
	"bytes"
	"log"
)

func GetUserIDAndExpiryTimeAccessToken(accessToken []byte, expiryTime time.Duration, signer *vm_signer.Base64TimeSigner) ([]byte, bool) {
	return signer.Verify(accessToken, expiryTime)
}

type UserIDExpiryTime struct {
	userID []byte
	expiryTime time.Duration
}

func (u *UserIDExpiryTime) GobEncode() ([]byte, error) {
	w := new(bytes.Buffer)
	encoder := gob.NewEncoder(w)
	err := encoder.Encode(u.userID)
	if err != nil {
		return nil, err
	}
	err = encoder.Encode(u.expiryTime)
	if err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func (u *UserIDExpiryTime) GobDecode(buf []byte) error {
	r := bytes.NewBuffer(buf)
	decoder := gob.NewDecoder(r)
	err := decoder.Decode(&u.userID)
	if err != nil {
		return err
	}
	return decoder.Decode(&u.expiryTime)
}

func GenerateUserIDAndExpiryTimeAccessToken(userID []byte, expiryTime time.Duration, secret string) ([]byte) {
	h := hmac.New(func() hash.Hash {
		return md5.New()
	}, []byte(secret))
	s := vm_signer.NewBase64TimeSigner(h)
	u := UserIDExpiryTime{userID, expiryTime}
	buffer := new(bytes.Buffer)
	enc := gob.NewEncoder(buffer)
	err := enc.Encode(u)
	if err != nil {
		log.Fatal("encode error:", err)
	}
	return s.Sign(buffer.Bytes())
}

type AuthContextInterface interface {
	GetAccessToken() ([]byte, bool)
}

type AuthContext struct {
	expiryTime time.Duration
	secret string
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
