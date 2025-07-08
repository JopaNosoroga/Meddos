package handlers

import (
	"bytes"
	"encoding/json"
	"log"
	"meddos/pkg/auth"
	"meddos/pkg/dbwork"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/mo7zayed/reqip"
)

// структура хранящая в себе access и refresh токены
// swagger:model
type tokens struct {
	// Access token (JWT)
	Access string `json:"access"`
	// Refresh token
	Refresh string `json:"refresh"`
}

// swagger:model
type guid struct {
	// Индентификатор пользователя
	GUID string `json:"GUID"`
}

var webhook string

func InitializationWebhook(url string) {
	webhook = url
}

// swagger:route POST /auth/{GUID} tokens Authorization
// # Авторизация в системе Authorization()
//
// # Для авторизации необходимо сделать POST запрос с указание GUID в параметре запроса
// # Пример запроса:
// # - curl -X POST http://localhost:8080/auth/{GUID} вместо {GUID} ввести тестовый GUID
// # При успехе сервер вернёт json с access и refresh токенами

// responses:
//
//	200: tokens
//	500: description: Ошибка сервера
func Authorization(rw http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	GUID := vars["GUID"]

	userAgent := r.Header.Get("User-Agent")
	ip := reqip.GetClientIP(r)
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
		return
	}
}

// swagger:route POST /refresh tokens Refresh
//
// # Обновление токенов access и refresh Refresh()
//
// # Для обновления токенов необходимо сделать POST запрос с указание двух заголовков
// # Authorization: Bearer {access}
// # Refresh: Refresh {refresh}
// # Пример запроса:
// # - curl -X POST -H "Authorization: Bearer {access}" -H "Refresh: Refresh {refresh}" http://localhost:8080/refresh
// # - вместо {access} и {refresh} надо ввести токена полученные в запросе к http://localhost:8080/auth/{GUID}

//
// # При успехе сервер вернёт json с access и refresh токенами
//
// responses:
//	200: tokens
//	400: description: Ошибка в запросе
//	401: description: Ошибка авторизации
//	500: description: Ошибка сервера
//

func Refresh(rw http.ResponseWriter, r *http.Request) {
	accessHeader := r.Header.Get("Authorization")

	if accessHeader == "" {
		http.Error(rw, "Authorization header не найден", http.StatusBadRequest)
		return
	}

	refreshHeader := r.Header.Get("Refresh")

	if refreshHeader == "" {
		http.Error(rw, "Refresh header не найден", http.StatusBadRequest)
		return
	}

	accessTokenParts := strings.Split(accessHeader, " ")
	if len(accessTokenParts) != 2 || accessTokenParts[0] != "Bearer" {
		http.Error(rw, "Токены в запросе не найдены", http.StatusBadRequest)
		return
	}

	refreshTokenParts := strings.Split(refreshHeader, " ")
	if len(refreshTokenParts) != 2 || refreshTokenParts[0] != "Refresh" {
		http.Error(rw, "Токены в запросе не найдены", http.StatusBadRequest)
		return
	}

	token := tokens{}
	token.Access = accessTokenParts[1]
	token.Refresh = refreshTokenParts[1]

	GUID, _ := auth.CheckAccessToken(token.Access)

	err := dbwork.DB.CheckActiveSession(GUID)
	if err != nil {
		log.Println(err)
		http.Error(rw, "Сессия токенов закрыта", http.StatusUnauthorized)
		return
	}

	userIPBefore, err := dbwork.DB.CheckWorkerRefreshAndStopping(token.Refresh, GUID, r.UserAgent())
	if err != nil {
		log.Println(err)
		http.Error(rw, "Ошибка проверки токенов", http.StatusUnauthorized)
		return
	}
	ip := reqip.GetClientIP(r)
	if userIPBefore != ip {
		data := bytes.NewReader([]byte("Попытка входа с другого IP адресса" + ip))
		_, err = http.Post(webhook, "application/json", data)
		if err != nil {
			log.Println(err)
			http.Error(rw, "Ошибка", http.StatusInternalServerError)
			return
		}
	}

	token.Access, err = auth.CreateAccessToken(GUID)
	if err != nil {
		http.Error(rw, "Ошибка создания токенов", http.StatusInternalServerError)
		return
	}

	token.Refresh, err = auth.CreateRefreshToken(GUID, r.UserAgent(), reqip.GetClientIP(r))
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

// swagger:route GET /GUID GetGUID GetGUID
//
// # Получение собственного GUID GetGUID()
//
// # Для получения собственного GUID необходимо ввыполнить GET запрос с заголовком Authorization
// # Authorization: Bearer {access}
// # Пример запроса:
// # - curl -X GET -H "Authorization: Bearer {access}" http://localhost:8080/GUID
// # При успехе сервер вернёт json с GUID
//
// responses:
//
//	200: guid
//	401: description: Ошибка авторизации
//	500: description: Ошибка сервера
func GetGUID(rw http.ResponseWriter, r *http.Request) {
	GUID, ok := r.Context().Value("GUID").(string)
	if !ok {
		http.Error(rw, "Ошибка", http.StatusUnauthorized)
		return
	}

	encoder := json.NewEncoder(rw)
	err := encoder.Encode(GUID)
	if err != nil {
		log.Println(err)
		http.Error(rw, "Ошибка отправки GUID", http.StatusInternalServerError)
		return
	}
}

// swagger:route POST /logout tokens Logout
//
// # Деавторизация Logout()
//
// # Для деавторизации необходимо выполнить POST запрос с заголовком Authorization
// # Authorization: Bearer {access}
// # Пример запроса:
// # - curl -X POST -H "Authorization: Bearer {access}" http://localhost:8080/logout вместо {access} надо ввести полученный access токен
// # При успехе сервер вернёт статус 200
//
// responses:
//
//		200: description: Пользователь успешно деавторизован
//	 401: description: Ошибка авторизации
//		500: description: Ошибка сервера
func Logout(rw http.ResponseWriter, r *http.Request) {
	GUID, ok := r.Context().Value("GUID").(string)
	if !ok {
		http.Error(rw, "Ошибка", http.StatusInternalServerError)
		return
	}

	err := dbwork.DB.StopSession(GUID)
	if err != nil {
		log.Println(err)
		http.Error(rw, "Попытка закрыть сессию провалилась", http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusOK)
}
