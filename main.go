package main

import (
	"net/http"

	"github.com/gorilla/mux"

	controllers "./controllers"
)

var router = mux.NewRouter()

func main() {
	// Users
	router.HandleFunc("/", controllers.HomeHandler).Methods("GET")
	router.HandleFunc("/login", controllers.LoginHandler).Methods("POST")
	router.HandleFunc("/register", controllers.RegisterHandler).Methods("POST")
	router.HandleFunc("/client", controllers.CreateClientHandler).Methods("POST")
	router.HandleFunc("/client", controllers.RemoveClientHandler).Methods("DELETE")

	// Clients
	router.HandleFunc("/user", controllers.GetUserHandler).Methods("GET")

	http.Handle("/", router)
	http.ListenAndServe(":8080", nil)
}
