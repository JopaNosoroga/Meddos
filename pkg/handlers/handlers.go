package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"meddos/pkg/auth"
	"meddos/pkg/dbwork"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

type tokens struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

func Authorization(rw http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	GUID := vars["GUID"]

	userAgent := r.Header.Get("User-Agent")
	ip := r.RemoteAddr

	var token tokens
	var err error

	token.Access, err = auth.CreateAccessToken(GUID)
	if err != nil {
		log.Println(err)
		http.Error(rw, "Не удалось создать токен", http.StatusInternalServerError)
		return
	}

	token.Refresh, err = auth.CreateRefreshToken(GUID, userAgent, ip)
	if err != nil {
		log.Println(err)
		http.Error(rw, "Не удалось создать токен", http.StatusInternalServerError)
		return
	}

	encoder := json.NewEncoder(rw)
	err = encoder.Encode(token)
	if err != nil {
		http.Error(rw, "Ошибка отправки токенов", http.StatusInternalServerError)
	}
}

func Refresh(rw http.ResponseWriter, r *http.Request) {
	refreshHeader := r.Header.Get("Refresh")

	if refreshHeader == "" {
		http.Error(rw, "Refresh header не найден", http.StatusBadRequest)
		return
	}

	tokenParts := strings.Split(refreshHeader, " ")
	if len(tokenParts) != 4 || tokenParts[0] != "Bearer" || tokenParts[2] != "Refresh" {
		http.Error(rw, "Токены в запросе не найдены", http.StatusBadRequest)
		return
	}
	token := tokens{}
	token.Access = tokenParts[1]
	token.Refresh = tokenParts[3]

	GUID, err := auth.CheckAccessToken(token.Access)
	if err != nil {
		log.Println(err)
		http.Error(rw, "Ошибка проверки токенов", http.StatusUnauthorized)
		return
	}

	err = dbwork.DB.CheckWorkerRefreshAndStopping(token.Refresh, GUID, r.UserAgent())
	if err != nil {
		log.Println(err)
		http.Error(rw, "Ошибка проверки токенов", http.StatusUnauthorized)
		return
	}

	token.Access, err = auth.CreateAccessToken(GUID)
	if err != nil {
		http.Error(rw, "Ошибка создания токенов", http.StatusInternalServerError)
		return
	}

	token.Refresh, err = auth.CreateRefreshToken(GUID, r.UserAgent(), r.RemoteAddr)
	if err != nil {
		http.Error(rw, "Ошибка создания токенов", http.StatusInternalServerError)
		return
	}

	encoder := json.NewEncoder(rw)
	err = encoder.Encode(token)
	if err != nil {
		http.Error(rw, "Ошибка отправки токенов", http.StatusInternalServerError)
	}
}

func GetGUID(rw http.ResponseWriter, r *http.Request) {
	GUID, ok := r.Context().Value("GUID").(string)
	if !ok {
		http.Error(rw, "Вы не авторизованы", http.StatusUnauthorized)
		return
	}

	body := fmt.Sprintf("Ваш GUID = %s", GUID)
	fmt.Fprintf(rw, "%s", body)
}
