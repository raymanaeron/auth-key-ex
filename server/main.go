package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"github.com/golang-jwt/jwt/v5"
	"auth-key-exchange/common"
)

// Private variable to hold the list of ClientPublicKeyMap
var clientPublicKeyList = []common.ClientPublicKeyMap{}

// Private variable to hold the list of keypairs for clients
var serverKeyPairList = []common.ServerKeyPairMap{}

func main() {
	http.HandleFunc("/api/pubkey", getPublicKey)
	http.HandleFunc("/api/auth", authenticate)
	http.HandleFunc("/api/keypair", generateKeyPair)

	fmt.Println("Starting server on port 4311...")
	err := http.ListenAndServe(":4311", nil)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// Client call this function to generate a unique keypair for the client
// The public key is sent to the client while server holds on to the private key
func getPublicKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Read the query parameter named username
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username parameter is required", http.StatusBadRequest)
		return
	}

	// Find the server public key for the given username
	publicKey, err := getServerPublicKeyForUser(username)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error retrieving public key: %v", err), http.StatusInternalServerError)
		return
	}

	// Return the public key as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"publicKey": publicKey})
}

// Find the public key from the in memory list
// If found return it otherwise generate one and update the list
func getServerPublicKeyForUser(username string) (string, error) {
	for _, keyPair := range serverKeyPairList {
		if keyPair.Username == username {
			return string(keyPair.PublicKey), nil
		}
	}

	// Username does not exist, generate a new key pair
	newKeyPair, err := common.GenerateKeyPair()
	if err != nil {
		return "", fmt.Errorf("error generating new key pair: %v", err)
	}

	// Add the new key pair to the list
	serverKeyPairList = append(serverKeyPairList, common.ServerKeyPairMap{
		Username:  username,
		PublicKey: newKeyPair.PublicKey,
		PrivateKey: newKeyPair.PrivateKey,
	})

	return string(newKeyPair.PublicKey), nil
}

func getServerKeysForUser(username string) (common.ServerKeyPairMap, error) {
	var skp common.ServerKeyPairMap

	for _, kp := range serverKeyPairList {
		if kp.Username == username {
			skp.Username = kp.Username
			skp.PublicKey = kp.PublicKey
			skp.PrivateKey = kp.PrivateKey

			return skp, nil
		}
	}

	// Username does not exist, generate a new key pair
	newKeyPair, err := common.GenerateKeyPair()
	if err != nil {
		return skp, fmt.Errorf("error generating new key pair: %v", err)
	}

	skp.Username = username
	skp.PublicKey = newKeyPair.PublicKey
	skp.PrivateKey = newKeyPair.PrivateKey

	// Add the new key pair to the list
	serverKeyPairList = append(serverKeyPairList, skp)	
	return skp, nil
}

// authenticate handles the authentication logic
func authenticate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var authRequest common.AuthRequest
	var authResponse common.AuthResponse

	err := json.NewDecoder(r.Body).Decode(&authRequest)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error decoding request: %v", err), http.StatusInternalServerError)
		return
	}

	// Print out the passed in AuthRequest object
	fmt.Printf("Received AuthRequest: %+v\n", authRequest)

	// Validate the Username and ClientPublicKey fields
	if authRequest.Username == "" || authRequest.ClientPublicKey == "" {
		http.Error(w, "Username and ClientPublicKey cannot be empty", http.StatusBadRequest)
		return
	}

	isAuthenticated := false
	// TODO: Database Check
	if authRequest.Username == "test" && authRequest.Encrypted != "" {
		isAuthenticated = true
	}

	if isAuthenticated {
		// Check if the username already exists in the clientPublicKeyList
		found := false
		for i, clientKey := range clientPublicKeyList {
			if clientKey.Username == authRequest.Username {
				// Replace the existing public key
				clientPublicKeyList[i].PublicKey = authRequest.ClientPublicKey
				found = true
				break
			}
		}

		if !found {
			// Add the new username and public key to the list
			clientPublicKeyList = append(clientPublicKeyList, common.ClientPublicKeyMap{
				Username:  authRequest.Username,
				PublicKey: authRequest.ClientPublicKey,
			})
		}

		serverKeyPair, err := getServerKeysForUser(authRequest.Username)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error creating/retriving server key pair: %v", err), http.StatusInternalServerError)
			return
		}

		// Parse the PEM-encoded private key
		privateKey, err := common.ParsePrivateKey(serverKeyPair.PrivateKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error parsing private key: %v", err), http.StatusInternalServerError)
			return
		}

		// create a jwt token
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"username": authRequest.Username,
			"exp":      time.Now().Add(time.Hour * 72).Unix(),
		})

		// Sign the token with the server's RSA private key
		tokenString, err := token.SignedString(privateKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error signing token: %v", err), http.StatusInternalServerError)
			return
		}

		authResponse.Authenticated = isAuthenticated
		authResponse.Token = tokenString
		authResponse.ServerPublicKey = string(serverKeyPair.PublicKey)

	} else {
		authResponse.Authenticated = false
		authResponse.Token = ""
		authResponse.ServerPublicKey = ""
	}

	// Return the AuthResponse as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(authResponse)
}

// generateKeyPair handles the key pair generation logic
func generateKeyPair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	keyPair, err := common.GenerateKeyPair()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error generating key pair: %v", err), http.StatusInternalServerError)
		return
	}

	// Return the key pair as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keyPair)
}
