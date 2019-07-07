package models

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

type User struct {
	Email    string   `json:"email"`
	Password string   `json:"password"`
	Clients  []Client `json:"clients"`
}

type ResponseResult struct {
	Error  string `json:"error"`
	Result string `json:"result"`
}

type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
	ErrRegisteredUser      = errors.New("The user is registered yet")
)

var users []User

func GetUsers() (users []User, err error) {
	// Open our jsonFile
	jsonFile, err := os.Open("db.json")

	// if we os.Open returns an error then handle it
	if err != nil {
		return nil, err
	}

	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	fmt.Println("Successfully opened db.json")

	// read our opened jsonFile as a byte array
	byteValue, _ := ioutil.ReadAll(jsonFile)

	// unmarshal our byteArray which contains our jsonFile's content
	json.Unmarshal(byteValue, &users)

	return users, nil
}

func UserIsValid(email, pwd string) bool {
	/*
		// Open our jsonFile
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

		// unmarshal our byteArray which contains our jsonFile's content
		json.Unmarshal(byteValue, &users)

		fmt.Println(users)

		// check if email exists in file
		if val, ok := m[email]; ok {

			// compare inserted password with the stored one
			match, err := comparePasswordAndHash(pwd, val)

			if err != nil {
				log.Fatal(err)
			}

			fmt.Printf("Match: %v\n", match)

			return match
		} else {
			return false
		}
	*/

	return false
}

func UserRegister(email, pwd string) (res bool, err error) {

	/*
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
		json.Unmarshal(byteValue, &m)

		fmt.Println(m)

		// check if email exists in db yet
		if val, ok := m[email]; ok {
			fmt.Println(val)

			return false, ErrRegisteredUser
		} else {
			// generate password hash
			encodedHash, err := generateFromPassword(pwd, p)

			if err != nil {
				log.Fatal(err)
			}

			// assign password hash to user info array
			m[email] = encodedHash

			// create a JSON text result from user info
			jsonData, err := json.MarshalIndent(m, "", "	")

			if err != nil {
				panic(err)
			}

			// write json text in our db file
			jsonFile.Write(jsonData)

			// write file info into file archive
			_ = ioutil.WriteFile("db.json", jsonData, 0644)

			return true, nil
		}
	*/

	return false, nil
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
