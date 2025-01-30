package main

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/39george/authpher"
	"github.com/39george/authpher/adapters/authttp"
	"github.com/39george/authpher/sessions/httpsessions"
	scsRedisStore "github.com/39george/scs_redisstore"
	"github.com/alexedwards/scs/v2"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/justinas/alice"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/39george/authpher/examples/common"
)

type User struct {
	ID           bson.ObjectID      `json:"_id" bson:"_id,omitempty"`
	Username     string             `json:"username" bson:"username"`
	PasswordHash string             `json:"password_hash" bson:"password_hash"`
	Email        string             `json:"email" bson:"email"`
	Permissions  common.Permissions `json:"permissions" bson:"permissions"`
}

func (u *User) SessionAuthHash() []byte {
	return []byte(u.PasswordHash)
}

func (u *User) UserId() any {
	return u.ID
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type MyBackend struct {
	Mongo     *mongo.Collection
	RedisPool *redis.Client
}

func (mb MyBackend) Authenticate(
	ctx context.Context,
	creds Credentials,
) (authpher.AuthUser, error) {
	// Get user data by username
	user := User{}
	err := mb.Mongo.
		FindOne(ctx, bson.M{"username": &creds.Username}).
		Decode(&user)
	if err != nil {
		return nil, WrapErr(fmt.Errorf(
			"failed to get auth user data for %v, %w",
			creds,
			err,
		))
	}
	// Run argon2 verification
	match, err := common.ComparePasswordAndHash(
		creds.Password,
		user.PasswordHash,
	)
	if err != nil {
		return nil, WrapErr(err)
	}
	if match {
		return &user, nil
	} else {
		return nil, nil
	}
}

func (mb MyBackend) GetUser(
	ctx context.Context,
	userId any,
) (authpher.AuthUser, error) {
	usr := User{}
	usrId := userId.(bson.ObjectID)

	// Try to get user usrData by username from cache
	rKey := fmt.Sprintf("user_data_cache:%v", usrId)
	usrJson, err := mb.RedisPool.Get(ctx, rKey).Bytes()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, WrapErr(fmt.Errorf(
			"failed to fetch user_data_cache from redis: %w",
			err,
		))
	} else if len(usrJson) != 0 {
		// Prevent error, see https://github.com/deckarep/golang-set/issues/135
		usr.Permissions = common.NewPermissions()
		err := json.Unmarshal(usrJson, &usr)
		if err != nil {
			slog.Warn(fmt.Errorf("failed to unmarshal user: %w", err).Error())
		} else {
			// Return pointer!
			return &usr, nil
		}
	}

	// Get user usrData by username from db
	err = mb.Mongo.
		FindOne(ctx, bson.M{"_id": usrId}).
		Decode(&usr)
	if err != nil {
		return nil, WrapErr(err)
	}

	// Cache user
	usrJson, err = json.Marshal(&usr)
	if err != nil {
		return nil, WrapErr(err)
	}
	_, err = mb.RedisPool.Set(ctx, rKey, usrJson, 0).Result()
	if err != nil {
		slog.Error(fmt.Errorf("failed to cache user: %w", err).Error())
	}
	_, err = mb.RedisPool.Expire(ctx, rKey, time.Minute*5).Result()
	if err != nil {
		slog.Error(fmt.Errorf("failed to set expiration: %w", err).Error())
	}

	// Return pointer!
	return &usr, nil
}

// No personal permissions now
func (mb MyBackend) GetUserPermissions(
	ctx context.Context,
	user authpher.AuthUser,
) (mapset.Set[string], error) {
	perms := mapset.NewSetWithSize[string](0)
	return perms, nil
}

func (mb MyBackend) GetGroupPermissions(
	ctx context.Context,
	usr authpher.AuthUser,
) (mapset.Set[string], error) {
	// user is a pointer!
	u := usr.(*User)

	// Try to get user permissions from cache
	rKey := fmt.Sprintf("user_permissions_cache:%v", u.ID)
	slice, err := mb.RedisPool.SMembers(ctx, rKey).Result()
	if err != nil {
		return nil, WrapErr(fmt.Errorf(
			"failed to fetch user_permissions_cache from redis: %w",
			err,
		))
	} else if len(slice) != 0 {
		return mapset.NewSet(slice...), nil
	}

	// Get user permissions from db
	var permissionsMap map[string]common.Permissions
	err = mb.Mongo.FindOne(ctx, bson.M{"_id": u.ID}, options.FindOne().SetProjection(bson.M{"permissions": 1, "_id": 0})).Decode(&permissionsMap)
	if err != nil {
		return nil, WrapErr(err)
	}
	permissions := permissionsMap["permissions"]

	// Cache permissions
	_, err = mb.RedisPool.SAdd(ctx, rKey, permissions.ToSlice()).Result()
	if err != nil {
		slog.Error(
			fmt.Errorf("failed to cache user permissions: %w", err).Error(),
		)
	}
	_, err = mb.RedisPool.Expire(ctx, rKey, time.Minute).Result()
	if err != nil {
		slog.Error(fmt.Errorf("failed to set expiration: %w", err).Error())
	}
	return permissions, nil
}

func main() {
	redisPool := GetRedisConnectionPool()
	mongo := GetMongoDb()

	// Initialize a new session manager and configure the session lifetime.
	sessionManager := scs.New()
	sessionManager.Store = scsRedisStore.New(redisPool)
	sessionManager.Lifetime = 24 * time.Hour

	// Prepare user colleciton
	usersCollecion := mongo.Database("test").Collection("users")

	auth := authttp.Auth(
		MyBackend{
			Mongo:     usersCollecion,
			RedisPool: redisPool,
		},
		httpsessions.GoSessions{
			Store: sessionManager,
		},
	)
	authttp.RegisterErrorHandler(func(err error) {
		slog.Error(err.Error())
	})

	mux := http.NewServeMux()
	apiV1 := http.NewServeMux()
	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", apiV1))

	// Middleware
	muxChain := alice.New(
		sessionManager.LoadAndSave,
		auth,
	).Then(mux)

	// Routes
	apiV1.Handle("/user/", http.StripPrefix("/user", userRoutes()))
	apiV1.Handle("/auth/", http.StripPrefix("/auth", authRoutes()))

	// Application address
	addr := "localhost:"

	slog.Info("Started!", "fields", map[string]string{"hello": "world"})
	server := &http.Server{
		Addr:    addr,
		Handler: muxChain,
	}
	err := server.ListenAndServe()
	if err != nil {
		slog.Error("Failed to run server: ", err.Error(), "")
	}

}

func userRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthcheck", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		w.WriteHeader(http.StatusOK)
	}))

	// Auth middleware
	handler := authttp.PermissionRequired[string, Credentials](
		common.PermissionUser,
	)(mux)
	return handler
}

func authRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		ctx := r.Context()
		credentials := new(Credentials)
		err := json.NewDecoder(r.Body).Decode(&credentials)
		if err != nil {
			clientError(w, http.StatusBadRequest, err)
			return
		}
		auSes := ctx.Value(authpher.AuthContextString)
		authSession := auSes.(*authpher.AuthSession[string, Credentials])
		usr, err := authSession.Authenticate(ctx, *credentials)
		if err != nil {
			clientError(w, http.StatusUnauthorized, nil)
			return
		}
		if usr != nil {
			u := usr.(*User)
			err = authSession.Login(ctx, u)
			if err != nil {
				slog.Error("failed to login user", "error", err)
			}
		} else {
			clientError(w, http.StatusUnauthorized, nil)
		}

	}))
	return mux
}

// Helpers

func GetRedisConnectionPool() *redis.Client {
	opts := &redis.Options{
		Addr:     getEnv("REDIS_ADDR"),
		Password: getEnv("REDIS_PASS"),
		DB:       0,
	}
	return redis.NewClient(opts)
}

func GetMongoDb() *mongo.Client {
	reg := bson.NewRegistry()

	// Permissions type
	reg.RegisterTypeEncoder(
		common.PermissionsType,
		bson.ValueEncoderFunc(common.PermissionsEncoder))
	reg.RegisterTypeDecoder(common.PermissionsType, bson.ValueDecoderFunc(common.PermissionsDecoder))

	// Register bson's ID to gob (we store that id in cookie)
	gob.Register(bson.NewObjectID())

	mongoClient, err := mongo.Connect(options.Client().ApplyURI(getEnv("MONGO_ADDR")).SetAuth(options.Credential{
		Username: getEnv("MONGO_USER"),
		Password: getEnv("MONGO_PASS"),
	}).SetRegistry(reg))
	panicOnError(err, "Failed to connect to mongodb")
	return mongoClient
}

func getEnv(key string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	} else {
		panic("Not found key in the environment: " + key)
	}
}

func panicOnError(err error, message string) {
	if err != nil {
		panic(message + ": " + err.Error())
	}
}

type WrappedErr struct {
	err  error
	line int
	file string
}

func (w WrappedErr) Error() string {
	return fmt.Sprintf("%v, at %s:%d", w.err.Error(), w.file, w.line)
}

func WrapErr(err error) error {
	_, file, line, _ := runtime.Caller(1)
	w := WrappedErr{err, line, strings.TrimPrefix(file, "github.com/olegus199/")}
	return &w
}

func ServerError(w http.ResponseWriter, err error) {
	slog.Error(err.Error())
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

// Send reason for error in the body as [HttpError]
func clientError(w http.ResponseWriter, status int, err error) {
	errStr := "client error"
	if err != nil {
		errStr = err.Error()
	}
	slog.Error(errStr)
	w.WriteHeader(status)
	_, err = w.Write([]byte(errStr))
	if err != nil {
		slog.Error(err.Error())
	}
}

func AbortOnInternalError(w http.ResponseWriter, err error) bool {
	if err != nil {
		ServerError(w, err)
		return true
	}
	return false
}
