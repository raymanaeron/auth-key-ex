package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"github.com/golang-jwt/jwt/v5"
	"auth-key-exchange/common"
)

// Private variable to hold the list of ClientPublicKeyMap
var clientPublicKeyList = []common.ClientPublicKeyMap{}

// Private variable to hold the list of keypairs for clients
var serverKeyPairList = []common.ServerKeyPairMap{}

func main() {
	http.HandleFunc("/api/auth", authenticate)
	http.HandleFunc("/api/keypair", generateKeyPair)

	fmt.Println("Starting server on port 4311...")
	err := http.ListenAndServe(":4311", nil)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// authenticate handles the authentication logic
func authenticate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var authRequest common.AuthRequest
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
	if authRequest.Username == "test" && authRequest.encrypted != "" {
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

		// Check if server keypair exist for this user
		serverKeyPair, err := common.GenerateKeyPair()
		if err != nil {
			fmt.Println("Error generating server key pair:", err)
			return
		}
		
		server_keypair_found := false
		for i, k := range serverKeyPairList {
			if k.Username == authRequest.Username {
				// Entry exists so update the keys
				serverKeyPairList[i].PublicKey = serverKeyPair.PublicKey
				serverKeyPairList[i].PrivateKey = serverKeyPair.PrivateKey
				server_keypair_found = true
				break
			}	
		}

		// Entry does not exist so append a new one
		if !server_keypair_found {
			serverKeyPairList = append(serverKeyPairList, common.ServerKeyPairMap {
				Username: authRequest.Username,
				PublicKey: serverKeyPair.PublicKey,
				PrivateKey: serverKeyPair.PrivateKey,
			})
		}

		// create a jwt token
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"username": authRequest.Username,
			"exp":      time.Now().Add(time.Hour * 72).Unix(),
		})

		// Sign the token with the server's RSA private key
		tokenString, err := token.SignedString(serverKeyPair.PrivateKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error signing token: %v", err), http.StatusInternalServerError)
			return
		}

		authResponse := common.AuthResponse{
			Authenticated:   isAuthenticated,
			Token:           "dummy_token", // In a real scenario, generate a proper token.
			ServerPublicKey: serverKeyPair.PublicKey
		}
	} else {
		authResponse := common.AuthResponse{
			Authenticated:   false,
			Token:           "", 
			ServerPublicKey: ""
		}
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