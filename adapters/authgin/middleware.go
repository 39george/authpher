package authgin

import (
	"encoding/gob"
	"errors"
	"net/http"

	"github.com/39george/authpher"
	"github.com/gin-gonic/gin"
)

func Auth[P comparable, C any](backend authpher.AuthzBackend[P, C], store authpher.SessionStore) gin.HandlerFunc {
	gob.Register(authpher.Data{})
	dataKey := "user-login.data"
	if backend == nil || store == nil {
		panic("Backend and store shouldn't be nil!")
	}
	return func(c *gin.Context) {
		authSession, err := authpher.AuthRun(c, store, dataKey, backend)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		c.Set(authpher.AuthContextString, authSession)
		c.Next()
	}
}

func PermissionRequired[P comparable, C any](permission P) gin.HandlerFunc {
	return func(c *gin.Context) {
		authSession, err := AuthSessionFromGinContext[P, C](c)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		err = authpher.RequirePermission(c, permission, authSession)
		if err != nil {
			switch {
			case errors.Is(err, authpher.ErrInternal):
				c.AbortWithError(http.StatusInternalServerError, err)
			case errors.Is(err, authpher.ErrForbidden):
				c.AbortWithStatus(http.StatusForbidden)
			case errors.Is(err, authpher.ErrUnauthorized):
				c.AbortWithStatus(http.StatusUnauthorized)
			}
			return
		}
		c.Next()
	}
}

func AuthSessionFromGinContext[P comparable, C any](
	c *gin.Context,
) (*authpher.AuthSession[P, C], error) {
	authSession, exists := c.Get(authpher.AuthContextString)
	if !exists {
		return nil, errors.New(
			"authSession not found. Is Auth middleware enabled?",
		)
	}
	aS := authSession.(*authpher.AuthSession[P, C])
	return aS, nil
}
