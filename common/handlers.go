package handlers

import (
	"fmt"
	"net/http"

	helpers "../helpers"
	repos "../repos"
	"github.com/gorilla/securecookie"
)

var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

// Handlers

// for GET
func LoginPageHandler(response http.ResponseWriter, request *http.Request) {
	var body, _ = helpers.LoadFile("views/login.html")
	fmt.Fprintf(response, body)
}

// for POST
func LoginHandler(response http.ResponseWriter, request *http.Request) {
	name := request.FormValue("email")
	pass := request.FormValue("password")
	redirectTarget := "/"

	if !helpers.IsEmpty(name) && !helpers.IsEmpty(pass) {
		// Database check for user data!
		_userIsValid := repos.UserIsValid(name, pass)

		if _userIsValid {
			SetCookie(name, response)
			redirectTarget = "/index"
		} else {
			redirectTarget = "/register"
		}
	}

	http.Redirect(response, request, redirectTarget, 302)
}

// for GET
func RegisterPageHandler(response http.ResponseWriter, request *http.Request) {
	var body, _ = helpers.LoadFile("views/register.html")
	fmt.Fprintf(response, body)
}

// for POST
func RegisterHandler(response http.ResponseWriter, request *http.Request) {

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
			_userRegistered, err := repos.UserRegister(email, pwd)

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
}

// for GET
func IndexPageHandler(response http.ResponseWriter, request *http.Request) {
	userName := GetUserName(request)
	if !helpers.IsEmpty(userName) {
		var indexBody, _ = helpers.LoadFile("views/index.html")
		fmt.Fprintf(response, indexBody, userName)
	} else {
		http.Redirect(response, request, "/", 302)
	}
}

// for POST
func LogoutHandler(response http.ResponseWriter, request *http.Request) {
	ClearCookie(response)
	http.Redirect(response, request, "/", 302)
}

// Cookie
func SetCookie(userName string, response http.ResponseWriter) {
	value := map[string]string{
		"name": userName,
	}
	if encoded, err := cookieHandler.Encode("cookie", value); err == nil {
		cookie := &http.Cookie{
			Name:  "cookie",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(response, cookie)
	}
}

func ClearCookie(response http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   "cookie",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(response, cookie)
}

func GetUserName(request *http.Request) (userName string) {
	if cookie, err := request.Cookie("cookie"); err == nil {
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode("cookie", cookie.Value, &cookieValue); err == nil {
			userName = cookieValue["name"]
		}
	}
	return userName
}
