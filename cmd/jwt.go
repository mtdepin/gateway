package cmd

import (
	"errors"
	"net/http"
	"time"

	jwtgo "github.com/golang-jwt/jwt"
	jwtreq "github.com/golang-jwt/jwt/request"
	"github.com/minio/minio/internal/auth"
	xjwt "github.com/minio/minio/internal/jwt"
	"github.com/minio/minio/internal/logger"
)

const (
	jwtAlgorithm = "Bearer"

	// Inter-node JWT token expiry is 15 minutes.
	defaultInterNodeJWTExpiry = 15 * time.Minute
)

var (
	errInvalidAccessKeyID = errors.New("The access key ID you provided does not exist in our records")
	errAuthentication     = errors.New("Authentication failed, check your access credentials")
	errNoAuthToken        = errors.New("JWT token missing")
)

func authenticateNode(accessKey, secretKey, audience string) (string, error) {
	claims := xjwt.NewStandardClaims()
	claims.SetExpiry(UTCNow().Add(defaultInterNodeJWTExpiry))
	claims.SetAccessKey(accessKey)
	claims.SetAudience(audience)

	jwt := jwtgo.NewWithClaims(jwtgo.SigningMethodHS512, claims)
	return jwt.SignedString([]byte(secretKey))
}

// Callback function used for parsing
func webTokenCallback(claims *xjwt.MapClaims) ([]byte, error) {
	if claims.AccessKey == globalActiveCred.AccessKey {
		return []byte(globalActiveCred.SecretKey), nil
	}
	ok, _, err := globalIAMSys.IsTempUser(claims.AccessKey)
	if err != nil {
		if err == errNoSuchUser {
			return nil, errInvalidAccessKeyID
		}
		return nil, err
	}
	if ok {
		return []byte(globalActiveCred.SecretKey), nil
	}
	//cred, ok := globalIAMSys.GetUser(claims.AccessKey)
	cred := auth.Credentials{}
	if !ok {
		return nil, errInvalidAccessKeyID
	}
	return []byte(cred.SecretKey), nil

}

// Check if the request is authenticated.
// Returns nil if the request is authenticated. errNoAuthToken if token missing.
// Returns errAuthentication for all other errors.
func webRequestAuthenticate(req *http.Request) (*xjwt.MapClaims, bool, error) {
	token, err := jwtreq.AuthorizationHeaderExtractor.ExtractToken(req)
	if err != nil {
		if err == jwtreq.ErrNoTokenInRequest {
			return nil, false, errNoAuthToken
		}
		return nil, false, err
	}
	claims := xjwt.NewMapClaims()
	if err := xjwt.ParseWithClaims(token, claims, webTokenCallback); err != nil {
		return claims, false, errAuthentication
	}
	owner := claims.AccessKey == globalActiveCred.AccessKey
	return claims, owner, nil
}

func newAuthToken(audience string) string {
	cred := globalActiveCred
	token, err := authenticateNode(cred.AccessKey, cred.SecretKey, audience)
	logger.CriticalIf(GlobalContext, err)
	return token
}
