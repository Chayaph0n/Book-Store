package main

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email    string `gorm:"unique"` //ไม่ให้ซ้ำกัน
	Password string `json:"password"`
}

func createUser(db *gorm.DB, user *User) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost) //random generate password inform byte

	if err != nil {
		return err
	}

	user.Password = string(hashedPassword) //convert to string
	result := db.Create(user)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

func loginUser(db *gorm.DB, user *User) (string, error) {
	//get user from email
	selectedUser := new(User)
	result := db.Where("email = ?", user.Email).First(selectedUser) // check exist email
	if result.Error != nil {
		return "", result.Error
	}

	//compare password
	err := bcrypt.CompareHashAndPassword([]byte(selectedUser.Password), []byte(user.Password))

	if err != nil {
		return "", err
	}

	//pass = return jwt
	// Create JWT token
	jwtSecretKey := "TestSecret"             //should be env
	token := jwt.New(jwt.SigningMethodHS256) //generate token
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = selectedUser.ID
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix() // 72 hours expired

	t, err := token.SignedString([]byte(jwtSecretKey))
	if err != nil {
		return "", err
	}

	return t, nil
}
