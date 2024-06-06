package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/websocket"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Token struct {
	Username string `json:"username"`
	Expires  int64  `json:"expires"`
}

var AESKey = []byte("3d308f8e8b228b72ab8f42b6653cc128")
var credentialsFile = "credentials.txt"

func main() {
	http.Handle("/ws", websocket.Handler(wsHandler))
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/endpoint1", authMiddleware(endpoint1Handler))
	http.HandleFunc("/endpoint2", authMiddleware(endpoint2Handler))
	http.HandleFunc("/endpoint3", authMiddleware(endpoint3Handler))

	fmt.Println("Server started at :8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}
}

func registerHandler(writer http.ResponseWriter, request *http.Request) {
	fmt.Println("Register handler called")
	var newUser User
	err := json.NewDecoder(request.Body).Decode(&newUser)
	if err != nil {
		http.Error(writer, "Invalid request body", http.StatusBadRequest)
		return
	}
	if newUser.Username == "" || newUser.Password == "" {
		http.Error(writer, "Username and password are required", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(writer, "Error hashing password", http.StatusInternalServerError)
		return
	}

	newUser.Password = string(hashedPassword)

	credentials, err := readCredentials()
	if err != nil && !isNotExist(err) {
		http.Error(writer, "Error reading credentials", http.StatusInternalServerError)
		return
	}

	credentials = append(credentials, newUser)

	err = writeCredentials(credentials)
	if err != nil {
		http.Error(writer, "Error storing credentials", http.StatusInternalServerError)
		return
	}
	writer.WriteHeader(http.StatusCreated)
}

func readCredentials() ([]User, error) {
	var credentials []User
	data, err := ioutil.ReadFile(credentialsFile)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &credentials)
	if err != nil {
		return nil, err
	}
	return credentials, nil
}

func writeCredentials(credentials []User) error {
	data, err := json.Marshal(credentials)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(credentialsFile, data, 0644)
}

func isNotExist(err error) bool {
	if pathErr, ok := err.(*os.PathError); ok && os.IsNotExist(pathErr) {
		return true
	}
	return false
}

func wsHandler(ws *websocket.Conn) {
	defer ws.Close()

	fmt.Println("WebSocket handler called")
	tokenString := ws.Request().URL.Query().Get("token")

	if tokenString == "" {
		fmt.Println("No token provided")
		websocket.Message.Send(ws, "Unauthorized")
		return
	}

	tokenData := decryptAES(tokenString)

	var token Token
	err := json.Unmarshal([]byte(tokenData), &token)
	if err != nil || token.Expires < time.Now().Unix() {
		websocket.Message.Send(ws, "Unauthorized")
		return
	}

	var msg string
	for {
		err := websocket.Message.Receive(ws, &msg)
		if err != nil {
			fmt.Println("WebSocket error:", err)
			break
		}
		fmt.Println("Received message:", msg)
		response := fmt.Sprintf("Message received: %s", msg)
		err = websocket.Message.Send(ws, response)
		if err != nil {
			fmt.Println("WebSocket send error:", err)
			break
		}
	}
}

func endpoint1Handler(writer http.ResponseWriter, request *http.Request) {
	fmt.Println("Endpoint 1 handler called")
	_, err := writer.Write([]byte("endpoint 1"))
	if err != nil {
		return
	}
}

func endpoint2Handler(writer http.ResponseWriter, request *http.Request) {
	fmt.Println("Endpoint 2 handler called")
	_, err := writer.Write([]byte("endpoint 2"))
	if err != nil {
		return
	}
}

func endpoint3Handler(writer http.ResponseWriter, request *http.Request) {
	fmt.Println("Endpoint 3 handler called")
	_, err := writer.Write([]byte("endpoint 3"))
	if err != nil {
		return
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Auth middleware called")
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tokenString := decryptAES(authHeader)
		var token Token
		err := json.Unmarshal([]byte(tokenString), &token)
		if err != nil || token.Expires < time.Now().Unix() {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func loginHandler(writer http.ResponseWriter, request *http.Request) {
	fmt.Println("Login handler called")
	var user User
	err := json.NewDecoder(request.Body).Decode(&user)
	if err != nil {
		http.Error(writer, "Invalid request body", http.StatusBadRequest)
		return
	}

	credentials, err := readCredentials()
	if err != nil {
		http.Error(writer, "Error reading credentials", http.StatusInternalServerError)
		return
	}

	var storedUser *User
	for _, u := range credentials {
		if u.Username == user.Username {
			storedUser = &u
			break
		}
	}

	if storedUser == nil {
		http.Error(writer, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password))
	if err != nil {
		http.Error(writer, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token := Token{
		Username: user.Username,
		Expires:  time.Now().Add(24 * time.Hour).Unix(),
	}
	tokenString, _ := json.Marshal(token)
	encryptedToken := encryptAES(string(tokenString))
	writer.Write([]byte(encryptedToken))
}

func encryptAES(plaintext string) string {
	block, _ := aes.NewCipher(AESKey)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))
	return base64.URLEncoding.EncodeToString(ciphertext)
}

func decryptAES(ciphertext string) string {
	block, _ := aes.NewCipher(AESKey)
	decodedCiphertext, _ := base64.URLEncoding.DecodeString(ciphertext)
	iv := decodedCiphertext[:aes.BlockSize]
	decodedCiphertext = decodedCiphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(decodedCiphertext, decodedCiphertext)
	return string(decodedCiphertext)
}
