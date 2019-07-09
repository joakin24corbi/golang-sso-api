package controllers

import (
	"encoding/json"
	"net/http"

	models "../models"
	"github.com/gorilla/context"
	"github.com/mitchellh/mapstructure"
)

func GetUserHandler(response http.ResponseWriter, request *http.Request) {

	response.Header().Set("Content-Type", "application/json")

	var res ResponseResult

	decoded := context.Get(request, "decoded")

	var user models.User

	mapstructure.Decode(decoded, &user)

	// TODO check if the information is requested from the same domain to which the access token was granted

	userBD, err := models.UserGet(user.Email)

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(response).Encode(res)
		return
	}

	res.Result = Result{
		map[string]interface{}{
			"name":  userBD.Name,
			"email": userBD.Email},
		AuthToken{},
		""}

	json.NewEncoder(response).Encode(res)
	return
}
