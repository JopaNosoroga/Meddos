package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"meddos/pkg/dbwork"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var secret = []byte("Hochy_sir_kosichky:)")

type claims struct {
	GUID string `json:"GUID"`
	jwt.RegisteredClaims
}

func CreateAccessToken(GUID string) (string, error) {
	claims := &claims{
		GUID: GUID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(8 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	err := dbwork.DB.EnableSession(GUID)
	if err != nil {
		return "", err
	}
	return token.SignedString([]byte(secret))
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			http.Error(rw, "Authorization header не найден", http.StatusUnauthorized)
			return
		}

		tokenParts := strings.Split(authHeader, " ")

		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			http.Error(rw, "Токен в запросе не найден", http.StatusUnauthorized)
			return
		}

		tokenString := tokenParts[1]
		GUID, err := CheckAccessToken(tokenString)
		if err != nil {
			http.Error(rw, "Ошибка проверки токена", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "GUID", GUID)
		next.ServeHTTP(rw, r.WithContext(ctx))
	})
}

func CheckAccessToken(access string) (string, error) {
	claim := &claims{}

	token, err := jwt.ParseWithClaims(
		access,
		claim,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		},
	)
	if err != nil || !token.Valid {
		return "-1", fmt.Errorf("Неверный access токен")
	}

	err = dbwork.DB.CheckActiveSession(claim.GUID)
	if err != nil {
		return "-1", err
	}

	return claim.GUID, nil
}

func CreateRefreshToken(GUID, userAgent, userIP string) (string, error) {
	for range 10 {
		var refresh [32]byte

		_, err := rand.Read(refresh[:])
		if err != nil {
			return "", err
		}

		strRefresh := base64.StdEncoding.EncodeToString(refresh[:])

		hashRefresh, err := bcrypt.GenerateFromPassword([]byte(strRefresh), bcrypt.DefaultCost)
		if err != nil {
			return "", err
		}

		err = dbwork.DB.CheckCollisionsRefresh(string(hashRefresh))
		if err == nil {
			err = dbwork.DB.AddRefreshToDB(string(hashRefresh), GUID, userAgent, userIP)
			if err != nil {
				return "", err
			}
			return string(strRefresh), nil
		}

	}
	return "", fmt.Errorf("Не удалось создать refresh token")
}
