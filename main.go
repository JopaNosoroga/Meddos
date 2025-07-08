package main

import (
	"encoding/json"
	"log"
	"meddos/pkg/auth"
	"meddos/pkg/dbwork"
	"meddos/pkg/handlers"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

// @title Authentication Service API
// @version 1.0
func main() {
	configDBFile, err := os.ReadFile("configs/DBconfig.json")

	configDB := dbwork.PostgresDBParams{}

	err = json.Unmarshal(configDBFile, &configDB)
	if err != nil {
		log.Println(err)
		return
	}

	err = dbwork.InitializationPostgresDB(configDB)
	if err != nil {
		log.Println(err)
		return
	}

	configAuthFile, err := os.ReadFile("configs/AuthConfig.json")
	if err != nil {
		log.Println(err)
		return
	}

	var configAuth struct {
		JWTSecret         string `json:"jwt_secret"`
		JWTExpirationHour int    `json:"jwt_expiration_hours"`
		Webhook           string `json:"webhook"`
	}

	err = json.Unmarshal(configAuthFile, &configAuth)
	if err != nil {
		log.Println(err)
		return
	}

	handlers.InitializationWebhook(configAuth.Webhook)
	auth.InitializationSecretAndExpires(configAuth.JWTSecret, configAuth.JWTExpirationHour)

	router := mux.NewRouter()

	router.HandleFunc("/auth/{GUID}", handlers.Authorization).Methods("POST")
	router.HandleFunc("/refresh", handlers.Refresh).Methods("POST")

	protected := router.PathPrefix("").Subrouter()
	protected.Use(auth.AuthMiddleware)

	protected.HandleFunc("/GUID", handlers.GetGUID).Methods("GET")
	protected.HandleFunc("/logout", handlers.Logout).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", router))
}
