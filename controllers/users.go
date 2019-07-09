package controllers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	models "../models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
)

// This is what is retured to the user
type AuthToken struct {
	TokenType string `json:"token_type"`
	Token     string `json:"access_token"`
	ExpiresIn int64  `json:"expires_in"`
}

// This is the cliam object which gets parsed from the authorization header
type AuthTokenClaim struct {
	*jwt.StandardClaims
	models.User
}

type Result struct {
	User  map[string]interface{} `json:"user"`
	Token AuthToken              `json:"token"`
	Url   string                 `json:"url"`
}

type ResponseResult struct {
	Error  string `json:"error"`
	Result Result `json:"result"`
}

func HomeHandler(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	json.NewEncoder(response).Encode("Golang Single Sign On")
}

func RegisterHandler(response http.ResponseWriter, request *http.Request) {

	response.Header().Set("Content-Type", "application/json")

	var res ResponseResult

	// Decode post body
	body, err := ioutil.ReadAll(request.Body)

	var parsed map[string]interface{}

	err = json.Unmarshal(body, &parsed)

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(response).Encode(res)
		return
	}

	name, ok := parsed["name"]

	if !ok {
		res.Error = "Missing name field in body request"
		json.NewEncoder(response).Encode(res)
		return
	}

	email, ok := parsed["email"]

	if !ok {
		res.Error = "Missing email field in body request"
		json.NewEncoder(response).Encode(res)
		return
	}

	password, ok := parsed["password"]

	if !ok {
		res.Error = "Missing password field in body request"
		json.NewEncoder(response).Encode(res)
		return
	}

	url, ok := parsed["url"]

	if !ok {
		url = "/"
	} else {
		url = url.(string)
	}

	user := models.User{name.(string), email.(string), password.(string)}

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(response).Encode(res)
		return
	}

	// Insert new user into bd
	userBD, err := models.UserRegister(user)

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(response).Encode(res)
		return
	}

	expiresAt := time.Now().Add(time.Hour * 24).Unix()

	token := jwt.New(jwt.SigningMethodHS256)

	// This userBD must not contain sensitive data
	token.Claims = &AuthTokenClaim{
		&jwt.StandardClaims{
			ExpiresAt: expiresAt,
		},
		*userBD,
	}

	tokenString, err := token.SignedString([]byte("secret"))

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(response).Encode(res)
		return
	}

	res.Result = Result{
		map[string]interface{}{
			"name":  userBD.Name,
			"email": userBD.Email,
		},
		AuthToken{
			Token:     tokenString,
			TokenType: "Bearer",
			ExpiresIn: expiresAt,
		},
		url.(string)}

	json.NewEncoder(response).Encode(res)
	return
}

func LoginHandler(response http.ResponseWriter, request *http.Request) {

	response.Header().Set("Content-Type", "application/json")

	var res ResponseResult

	// Decode post body
	body, err := ioutil.ReadAll(request.Body)

	var parsed map[string]interface{}

	err = json.Unmarshal(body, &parsed)

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(response).Encode(res)
		return
	}

	email, ok := parsed["email"]

	if !ok {
		res.Error = "Missing email field in body request"
		json.NewEncoder(response).Encode(res)
		return
	}

	password, ok := parsed["password"]

	if !ok {
		res.Error = "Missing password field in body request"
		json.NewEncoder(response).Encode(res)
		return
	}

	url, ok := parsed["url"]

	if !ok {
		url = "/"
	} else {
		url = url.(string)
	}

	user := models.User{"", email.(string), password.(string)}

	// Insert new user into bd
	userBD, err := models.UserLogin(user)

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(response).Encode(res)
		return
	}

	expiresAt := time.Now().Add(time.Hour * 24).Unix()

	token := jwt.New(jwt.SigningMethodHS256)

	// This userBD must not contain sensitive data
	token.Claims = &AuthTokenClaim{
		&jwt.StandardClaims{
			ExpiresAt: expiresAt,
		},
		*userBD,
	}

	tokenString, err := token.SignedString([]byte("secret"))

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(response).Encode(res)
		return
	}

	res.Result = Result{
		map[string]interface{}{
			"name":  userBD.Name,
			"email": userBD.Email,
		},
		AuthToken{
			Token:     tokenString,
			TokenType: "Bearer",
			ExpiresIn: expiresAt,
		},
		url.(string)}

	json.NewEncoder(response).Encode(res)
	return
}

func ValidateTokenMiddleware(next http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {

		authorizationHeader := request.Header.Get("token")

		if authorizationHeader != "" {

			bearerToken := strings.Split(authorizationHeader, " ")

			if len(bearerToken) == 2 {

				token, err := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {

					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}

					return []byte("secret"), nil
				})

				if err != nil {
					json.NewEncoder(response).Encode(err.Error())
					return
				}

				if token.Valid {
					context.Set(request, "decoded", token.Claims)
					next(response, request)
				} else {
					json.NewEncoder(response).Encode("Invalid authorization token")
				}
			} else {
				json.NewEncoder(response).Encode("Invalid authorization token")
			}
		} else {
			json.NewEncoder(response).Encode("An authorization header is required")
		}
	})
}
