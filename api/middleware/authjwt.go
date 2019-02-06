package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/appleboy/gin-jwt"
	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vulscano/postgresdb"
	gojwt "gopkg.in/dgrijalva/jwt-go.v3"
)

const (
	jwtKey    = "-7qXWYLjBN]f#M/C]s9F}bc!^fFs@dM"
	realmName = "Vulscano"
)

var (
	rootURL  = "/api/v1/admin"
	rootRole = "vulscanoroot"
)

// Login is used to unmarshal a login in request so that we can parse it
type Login struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// JwtConfigGenerate is used to generate our JWT configuration for Authentication and Authorization
func JwtConfigGenerate() *jwt.GinJWTMiddleware {

	authMiddleware := &jwt.GinJWTMiddleware{
		Realm:            realmName,
		Key:              []byte(jwtKey),
		Timeout:          time.Hour * 1,
		MaxRefresh:       time.Hour * 1,
		SigningAlgorithm: "HS256",
		PayloadFunc: func(data interface{}) jwt.MapClaims {

			// Payload Func to additional user details within JWT claim
			if v, ok := data.(*postgresdb.VulscanoDBUser); ok {
				return jwt.MapClaims{
					"role":       v.Role,
					"enterprise": v.EnterpriseID,
					"userID":     v.UserID,
					"email":      v.Email,
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: func(claims gojwt.MapClaims) interface{} {
			return claims["role"]
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {

			var loginVals Login

			if err := c.ShouldBind(&loginVals); err != nil {
				return nil, jwt.ErrMissingLoginValues
			}

			userID := loginVals.Username
			password := loginVals.Password

			vulscanoAuthUser, errAuth := authenticateUser(userID, password)

			if errAuth != nil {

				return nil, errAuth
			}
			return vulscanoAuthUser, nil
		},

		Authorizator: func(data interface{}, c *gin.Context) bool {

			claim := jwt.ExtractClaims(c)

			// Make sure user still exists in DB before authorizing
			if !checkUserExists(claim["email"]) {
				return false
			}

			if strings.Contains(c.Request.URL.Path, rootURL) {

				if v, ok := data.(string); ok && v == rootRole {
					return true
				}

				return false

			}

			if v, ok := data.(string); ok && v != "" {
				return true
			}

			return false
		},

		TokenLookup:   "header:Authorization",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
		SendCookie:    false,

		LoginResponse: func(c *gin.Context, code int, token string, expire time.Time) {
			c.JSON(http.StatusOK, gin.H{
				"code":   http.StatusOK,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		},
	}
	return authMiddleware
}

// AuthenticateUser queries the DB for credentials match and return user details
func authenticateUser(u string, p string) (*postgresdb.VulscanoDBUser, error) {

	userDetails, err := postgresdb.DBInstance.AuthenticateUser(u, p)

	if err != nil {
		return nil, err
	}

	return userDetails, nil
}

// Wrapper Function to validate JWT against user existing in DB
func checkUserExists(i interface{}) bool { return postgresdb.DBInstance.AssertUserExists(i) }
