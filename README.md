<h1 align="center">
authpher
</h1>

<div align="center">
    <a href="https://pkg.go.dev/github.com/39george/authpher">
        <img src="https://img.shields.io/badge/go.dev-reference-blue?logo=go&logoColor=white&style=flat-square" />
    </a>
</div>

<div align="center">
	<img src="https://github.com/user-attachments/assets/af3e4b65-c3f9-4982-9265-c93a4871d224" width=500 />
</div>



# What is that?
Authpher performs users identification, authentication, and authorization acting as middleware, using your actual implementation
behind the scenes.

## How does it work?
The idea is simple. You implement 3 interfaces:
- `AuthUser` - provides user ID and auth hash for certain user
- `AuthnBackend` - authenticates user using credentials 
- `AuthzBackend` - authorizes users by providing its permissions 

After that, use `Auth` middleware for all routes where you want to authenticate users, and
use `PermissionRequired` middleware for all routes you want to protect.

Middlewares for http go package and [gin](https://github.com/gin-gonic/gin) framework are provided as adapters.
You also need session manager for authpher to work, so you can use your custom or just go with
`github.com/39george/authpher/sessions/ginsessions` for [gin](https://github.com/gin-gonic/gin), or `github.com/39george/authpher/sessions/httpsessions` for go http,
both are using [scs](https://github.com/alexedwards/scs) as a session manager.

# Installation
To install, run:
```bash
go get github.com/39george/authpher
```
Also, for example, if you will use `ServerMux` from http package, install:
```bash
go get github.com/39george/authpher/sessions/httpsessions
```
Or with [gin](https://github.com/gin-gonic/gin):
```bash
go get github.com/39george/authpher/sessions/ginsessions
go get github.com/39george/authpher/adapters/authgin 
```
# Usage
Start with backend implementation:
```go
package authbackend

import (
	"context"
	"errors"

	mapset "github.com/deckarep/golang-set/v2"

	"github.com/39george/authpher"
)

// Example user type
type User struct {
	ID           int32
	Username     string
	PasswordHash string
}

// Implement `AuthUser`

func (tu TestUser) UserId() any {
	return tu.ID

}
func (tu TestUser) SessionAuthHash() []byte {
	return []byte(tu.PasswordHash)
}

// Example credentials type
type Credentials struct {
	Username string
	Password string
}

// Can contain database handlers, app state, etc
type TestBackend struct {}

// Implement `AuthnBackend`

func (mb TestBackend) Authenticate(
	ctx context.Context,
	creds TestCredentials,
) (authpher.AuthUser, error) {
	shouldBe := Credentials{Username: "testuser", Password: "testpassword"}
	if creds == shouldBe {
		return &User{123, "testuser", "testpasswordhash"}, nil
	} else {
		return nil, errors.New("bad credentials")
	}
}

func (mb TestBackend) GetUser(
	ctx context.Context,
	userId any,
) (authpher.AuthUser, error) {
	usrId := userId.(int32)
	if usrId == 123 {
		return &User{123, "testuser", "testpasswordhash"}, nil
	} else {
		return nil, errors.New("bad user id")
	}
}

// Implement `AuthzBackend`

func (mb TestBackend) GetUserPermissions(
	ctx context.Context,
	user authpher.AuthUser,
) (mapset.Set[string], error) {
	perms := mapset.NewSet[string]()
	// Cast to TestUser.ID type
	if user.UserId().(int32) == 123 {
		perms.Add("userpermission")
	}
	return perms, nil
}

func (mb TestBackend) GetGroupPermissions(
	ctx context.Context,
	user authpher.AuthUser,
) (mapset.Set[string], error) {
	perms := mapset.NewSet[string]()
	return perms, nil
}
```
Then, if you use `ServerMux`:
```go
package authttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/39george/authpher"
	"github.com/39george/authpher/adapters/authttp"
	"github.com/39george/authpher/sessions/httpsessions"
	scsRedisStore "github.com/39george/scs_redisstore"
	"github.com/alexedwards/scs/v2"
	"github.com/justinas/alice"
)

func runServer(permission string) (net.Addr, error) {
	// Prepare
	redisClient := helpers.GetRedisConnectionPool()
	err := redisClient.Ping(context.Background()).Err()
	if err != nil {
		return nil, err
	}
	sessionManager := scs.New()
	sessionManager.Store = scsRedisStore.New(redisClient)
	sessionManager.Lifetime = 24 * time.Hour

	auth := authttp.Auth(
		backend.TestBackend{},
		&httpsessions.GoSessions{Store: sessionManager},
	)

	mux := http.NewServeMux()

	// Middleware
	muxChain := alice.New(
		sessionManager.LoadAndSave,
		auth,
	).Then(mux)

	// Open routes
	mux.Handle("/login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		credentials := new(backend.TestCredentials)
		err := json.NewDecoder(r.Body).Decode(&credentials)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		aS := ctx.Value(authpher.AuthContextString)
		authSession := aS.(*authpher.AuthSession[string, testbackend.TestCredentials])
		user, err := authSession.Authenticate(ctx, *credentials)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		if user != nil {
			u := user.(*testbackend.TestUser)
			err = authSession.Login(ctx, u)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		} else {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}
	}))

	// Protected routes
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/testpath", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		w.WriteHeader(http.StatusOK)
	})
	protectedHandler := authttp.PermissionRequired[string, testbackend.TestCredentials](permission)(protectedMux)

	mux.Handle("/protected/", http.StripPrefix("/protected", protectedHandler))

	listener, err := net.Listen(
		"tcp",
		"localhost:",
	)
	if err != nil {
		return nil, err
	}
	http.Serve(listener, muxChain)
}
```
See [full mongodb example](https://github.com/39george/authpher/blob/main/examples/http/mongodb/main.go)
