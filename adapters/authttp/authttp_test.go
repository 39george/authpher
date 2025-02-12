package authttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/39george/authpher"
	scsRedisStore "github.com/39george/scs_redisstore"
	"github.com/alexedwards/scs/v2"
	"github.com/justinas/alice"
	"github.com/stretchr/testify/assert"

	"github.com/39george/authpher/adapters/authttp"
	"github.com/39george/authpher/adapters/helpers"
	"github.com/39george/authpher/adapters/helpers/testbackend"
	"github.com/39george/authpher/sessions/httpsessions"
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
		testbackend.TestBackend{},
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
		credentials := new(testbackend.TestCredentials)
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
		// Ensure handler was called
		w.Write([]byte{1, 2, 3})
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
	go http.Serve(listener, muxChain)
	return listener.Addr(), nil
}

func TestUnauthenticatedAccessRestricted(t *testing.T) {
	assert := assert.New(t)
	addr, err := runServer("userpermission")
	assert.NoError(err)

	webClient := &http.Client{Jar: helpers.NewJar()}

	req := fmt.Sprintf("http://%s/protected/testpath", addr.String())
	resp, err := webClient.Get(req)
	assert.NoError(err)
	defer resp.Body.Close()
	assert.Equal(http.StatusUnauthorized, resp.StatusCode)

}

func TestAuthorizedAccessAllowed(t *testing.T) {
	assert := assert.New(t)
	addr, err := runServer("userpermission")
	assert.NoError(err)

	webClient := &http.Client{Jar: helpers.NewJar()}

	req := fmt.Sprintf("http://%s/login", addr.String())
	creds := testbackend.TestCredentials{
		Username: "testuser",
		Password: "testpassword",
	}
	body, err := json.Marshal(&creds)
	assert.NoError(err)
	resp, err := webClient.Post(req, "application/json", bytes.NewReader(body))
	assert.NoError(err)
	assert.Equal(http.StatusOK, resp.StatusCode)
	req = fmt.Sprintf("http://%s/protected/testpath", addr.String())
	resp, err = webClient.Get(req)
	assert.NoError(err)

	// Ensure last handler was called
	respBody, err := io.ReadAll(resp.Body)
	assert.NoError(err)
	assert.Equal([]byte{1, 2, 3}, respBody)

	defer resp.Body.Close()
	assert.Equal(http.StatusOK, resp.StatusCode)
}

func TestUnauthorizedAccessForbidden(t *testing.T) {
	assert := assert.New(t)
	addr, err := runServer("adminpermission")
	assert.NoError(err)

	webClient := &http.Client{Jar: helpers.NewJar()}

	req := fmt.Sprintf("http://%s/login", addr.String())
	creds := testbackend.TestCredentials{
		Username: "testuser",
		Password: "testpassword",
	}
	body, err := json.Marshal(&creds)
	assert.NoError(err)
	resp, err := webClient.Post(req, "application/json", bytes.NewReader(body))
	assert.NoError(err)
	assert.Equal(http.StatusOK, resp.StatusCode)
	req = fmt.Sprintf("http://%s/protected/testpath", addr.String())
	resp, err = webClient.Get(req)
	assert.NoError(err)
	defer resp.Body.Close()
	assert.Equal(http.StatusForbidden, resp.StatusCode)
}
