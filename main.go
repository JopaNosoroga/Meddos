package main

import (
	"log"
	"meddos/pkg/auth"
	"meddos/pkg/dbwork"
	"meddos/pkg/handlers"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	err := dbwork.InitializationPostgresDB()
	if err != nil {
		log.Println(err)
		return
	}
	router := mux.NewRouter()

	router.HandleFunc("/auth/{GUID}", handlers.Authorization).Methods("POST")
	router.HandleFunc("/refresh", handlers.Refresh).Methods("POST")

	protected := router.PathPrefix("").Subrouter()
	protected.Use(auth.AuthMiddleware)

	protected.HandleFunc("/GUID", handlers.GetGUID).Methods("GET")

	log.Fatal(http.ListenAndServe(":8080", router))
}
