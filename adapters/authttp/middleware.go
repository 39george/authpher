package authttp

import (
	"context"
	"encoding/gob"
	"errors"
	"net/http"
	"sync"

	"github.com/39george/authpher"
)

type ErrorHandler func(error)

var (
	errorHandlers []ErrorHandler
	mu            sync.Mutex
)

func RegisterErrorHandler(handler ErrorHandler) {
	mu.Lock()
	defer mu.Unlock()
	errorHandlers = append(errorHandlers, handler)
}

func Auth[P comparable, C any](backend authpher.AuthzBackend[P, C], store authpher.SessionStore) func(http.Handler) http.Handler {
	gob.Register(authpher.Data{})
	dataKey := "user-login.data"
	if backend == nil || store == nil {
		panic("Backend and store shouldn't be nil!")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			authSession, err := authpher.AuthRun(ctx, store, dataKey, backend)
			if err != nil {
				handleInternalError(w, err)
				return
			}
			r = r.WithContext(context.WithValue(ctx, authpher.AuthContextString, authSession))
			next.ServeHTTP(w, r)
		})
	}
}

func PermissionRequired[P comparable, C any](permission P) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			authSession, err := authSessionFromContext[P, C](ctx)
			if err != nil {
				handleInternalError(w, err)
			}
			err = authpher.RequirePermission(ctx, permission, authSession)
			if err != nil {
				switch {
				case errors.Is(err, authpher.ErrInternal):
					handleInternalError(w, err)
				case errors.Is(err, authpher.ErrForbidden):
					http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				case errors.Is(err, authpher.ErrUnauthorized):
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func authSessionFromContext[P comparable, C any](
	ctx context.Context,
) (*authpher.AuthSession[P, C], error) {
	authSession := ctx.Value(authpher.AuthContextString)
	if authSession == nil {
		return nil, errors.New(
			"authSession not found. Is Auth middleware enabled?",
		)
	}
	aS := authSession.(*authpher.AuthSession[P, C])
	return aS, nil
}

func handleInternalError(w http.ResponseWriter, err error) {
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	mu.Lock()
	defer mu.Unlock()
	for _, handler := range errorHandlers {
		handler(err)
	}
}
