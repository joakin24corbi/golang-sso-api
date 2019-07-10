package main

import (
	"log"
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

	// Clients
	router.HandleFunc("/user", controllers.ValidateTokenMiddleware(controllers.GetUserHandler)).Methods("GET")

	http.Handle("/", router)

	// HTTPS
	log.Printf("Listening at https://127.0.0.1:10443/")
	err := http.ListenAndServeTLS(":443", "server.crt", "server.key", nil)

	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
