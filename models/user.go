package models

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

type User struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var (
	ErrInvalidHash         = errors.New("The encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("Incompatible version of argon2")
	ErrRegisteredUser      = errors.New("User registered yet")
	ErrUserNotRegistered   = errors.New("User not registered")
	ErrInvalidData         = errors.New("Incorrect email or password")
)

var users []User

func UserRegister(newUser User) (user *User, err error) {

	// establish the parameters to use for Argon2
	p := &params{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   32,
	}

	// open our jsonFile
	jsonFile, err := os.Open("db.json")

	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}

	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	fmt.Println("Successfully opened db.json")

	// read our opened jsonFile as a byte array
	byteValue, _ := ioutil.ReadAll(jsonFile)

	// we unmarshal our byteArray which contains our jsonFile's content
	json.Unmarshal(byteValue, &users)

	fmt.Println(users)

	// Check if user is registered yet
	var found *User

	for _, v := range users {
		if v.Email == newUser.Email {
			found = &v
		}
	}

	if found != nil {
		return nil, ErrRegisteredUser
	} else {
		// generate password hash
		encodedHash, err := generateFromPassword(newUser.Password, p)

		if err != nil {
			log.Fatal(err)
		}

		newUser.Password = encodedHash

		users = append(users, newUser)

		// create a JSON text result from user info
		jsonData, err := json.MarshalIndent(users, "", "	")

		if err != nil {
			panic(err)
		}

		// write json text in our db file
		jsonFile.Write(jsonData)

		// write file info into file archive
		_ = ioutil.WriteFile("db.json", jsonData, 0644)

		return &newUser, nil
	}
}

func UserLogin(newUser User) (user *User, err error) {

	// open our jsonFile
	jsonFile, err := os.Open("db.json")

	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}

	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	fmt.Println("Successfully opened db.json")

	// read our opened jsonFile as a byte array
	byteValue, _ := ioutil.ReadAll(jsonFile)

	// we unmarshal our byteArray which contains our jsonFile's content
	json.Unmarshal(byteValue, &users)

	fmt.Println(users)

	// Check if user is registered yet
	var found User

	for _, v := range users {
		if v.Email == newUser.Email {
			found = v
		}
	}

	if &found != nil {
		// compare inserted password with the stored one
		match, err := comparePasswordAndHash(newUser.Password, found.Password)

		if err != nil {
			log.Fatal(err)
		}

		if match {
			return &found, nil
		} else {
			return nil, ErrInvalidData
		}
	} else {
		return nil, ErrUserNotRegistered
	}
}

func UserGet(email string) (user *User, err error) {

	// open our jsonFile
	jsonFile, err := os.Open("db.json")

	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}

	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	fmt.Println("Successfully opened db.json")

	// read our opened jsonFile as a byte array
	byteValue, _ := ioutil.ReadAll(jsonFile)

	// we unmarshal our byteArray which contains our jsonFile's content
	json.Unmarshal(byteValue, &users)

	fmt.Println(users)

	// Check if user is registered yet
	var found User

	for _, v := range users {
		if v.Email == email {
			found = v
		}
	}

	if &found != nil {
		return &found, nil
	} else {
		return nil, ErrUserNotRegistered
	}
}

func generateFromPassword(password string, p *params) (encodedHash string, err error) {

	// create random salt
	salt, err := generateRandomBytes(p.saltLength)

	if err != nil {
		return "", err
	}

	// derives a key from the password, salt, and cost parameters using Argon2id
	hash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	// base64 encode the salt and hashed password
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// return a string using the standard encoded hash representation
	encodedHash = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.memory, p.iterations, p.parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {

	b := make([]byte, n)
	_, err := rand.Read(b)

	if err != nil {
		return nil, err
	}

	return b, nil
}

func comparePasswordAndHash(password, encodedHash string) (match bool, err error) {

	// extract the parameters, salt and derived key from the encoded password hash
	p, salt, hash, err := decodeHash(encodedHash)

	if err != nil {
		return false, err
	}

	// derive the key from the other password using the same parameters
	otherHash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	// check that the contents of the hashed passwords are identical. Note
	// that we are using the subtle.ConstantTimeCompare() function for this
	// to help prevent timing attacks
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}

	return false, nil
}

func decodeHash(encodedHash string) (p *params, salt, hash []byte, err error) {

	// split the string to obtain the parameters
	vals := strings.Split(encodedHash, "$")

	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int

	// check the algorithm version
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)

	if err != nil {
		return nil, nil, nil, err
	}

	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p = &params{}

	// check the algorithm parameters
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism)

	if err != nil {
		return nil, nil, nil, err
	}

	// decode de salt
	salt, err = base64.RawStdEncoding.DecodeString(vals[4])

	if err != nil {
		return nil, nil, nil, err
	}

	p.saltLength = uint32(len(salt))

	// decode the password
	hash, err = base64.RawStdEncoding.DecodeString(vals[5])

	if err != nil {
		return nil, nil, nil, err
	}

	p.keyLength = uint32(len(hash))

	return p, salt, hash, nil
}
