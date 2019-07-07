package controllers

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	models "../models"
)

func HomeHandler(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	json.NewEncoder(response).Encode("hola")
}

func RegisterHandler(response http.ResponseWriter, request *http.Request) {

	response.Header().Set("Content-Type", "application/json")

	var user models.User

	body, _ := ioutil.ReadAll(request.Body)

	err := json.Unmarshal(body, &user)

	var res models.ResponseResult

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(response).Encode(res)
		return
	}

	users, err := models.GetUsers()

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(response).Encode(res)
		return
	}

	json.NewEncoder(response).Encode(users)

	/*

		err = users.FindOne(context.TODO(), bson.D{{"email", user.Email}}).Decode(&result)

		if err != nil {
			if err.Error() == "bd: no documents in result" {
				hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 5)

				if err != nil {
					res.Error = "Error While Hashing Password, Try Again"
					json.NewEncoder(response).Encode(res)
					return
				}
				user.Password = string(hash)

				_, err = users.InsertOne(context.TODO(), user)
				if err != nil {
					res.Error = "Error While Creating User, Try Again"
					json.NewEncoder(response).Encode(res)
					return
				}
				res.Result = "Registration Successful"
				json.NewEncoder(response).Encode(res)
				return
			}

			res.Error = err.Error()
			json.NewEncoder(response).Encode(res)
			return
		}

		res.Result = "Username already Exists!!"
		json.NewEncoder(response).Encode(res)
		return

		/* old

		request.ParseForm()

		email := request.FormValue("email")
		pwd := request.FormValue("password")
		confirmPwd := request.FormValue("confirmPassword")

		_email, _pwd, _confirmPwd := false, false, false
		_email = !helpers.IsEmpty(email)
		_pwd = !helpers.IsEmpty(pwd)
		_confirmPwd = !helpers.IsEmpty(confirmPwd)

		if _email && _pwd && _confirmPwd {
			if _pwd == _confirmPwd {
				_userRegistered, err := models.UserRegister(email, pwd)

				if err != nil {
					fmt.Fprintln(response, err)
				} else if _userRegistered {
					SetCookie(email, response)
					http.Redirect(response, request, "/index", 301)
				}
			} else {
				fmt.Fprintln(response, "Password does not match")
			}
		} else {
			fmt.Fprintln(response, "This fields can not be blank!")
		}
	*/
}

func LoginHandler(response http.ResponseWriter, request *http.Request) {
	/*
			name := request.FormValue("email")
			pass := request.FormValue("password")
			redirectTarget := "/"

			if !helpers.IsEmpty(name) && !helpers.IsEmpty(pass) {
				// Database check for user data!
				_userIsValid := models.UserIsValid(name, pass)

				if _userIsValid {
					SetCookie(name, response)
					redirectTarget = "/index"
				} else {
					redirectTarget = "/register"
				}
			}

		http.Redirect(response, request, redirectTarget, 302)

	*/
}

func CreateClientHandler(response http.ResponseWriter, request *http.Request) {

}

func RemoveClientHandler(response http.ResponseWriter, request *http.Request) {

}
