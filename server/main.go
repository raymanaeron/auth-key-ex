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

// Private variable to hold the list of keypairs for clientss
var userKeyPairList = []common.UserKeyPairMap{}

func main() {
	// http routes
	http.HandleFunc("/api/exchange", exchangePublicKeys)
	http.HandleFunc("/api/auth", authenticate)
	http.HandleFunc("/api/keypair", generateKeyPair)

	fmt.Println("Starting server on port 4311...")
	err := http.ListenAndServe(":4311", nil)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// Client calls this function to generate a unique keypair for the client
// The public key is sent to the client while server holds on to the private key
func exchangePublicKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Read the query parameter named username
	// DO NOT DELETE - Need it for test purpose
	// username := r.URL.Query().Get("username")

	var exchangeRequest common.ExchangeRequest
	err := json.NewDecoder(r.Body).Decode(&exchangeRequest)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error decoding request: %v", err), http.StatusInternalServerError)
		return
	}
	
	if exchangeRequest.Username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}

	if exchangeRequest.ClientPublicKey == "" {
		http.Error(w, "clientpublickey is required", http.StatusBadRequest)
		return
	}
	
	// Find the keys for the given username
	userKeys, err := getUserKeys(exchangeRequest.Username)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error retrieving public key: %v", err), http.StatusInternalServerError)
		return
	}

	// Since we got a clientPublicKey, we need to update the local list of user key maps
	for i, ukpm := range userKeyPairList {
		if ukpm.Username == exchangeRequest.Username {
			userKeyPairList[i].ClientPublicKey = []byte(exchangeRequest.ClientPublicKey)
			break
		}
	}

	// Return the server public key as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"username":         exchangeRequest.Username,
		"serverpublickey":  string(userKeys.ServerPublicKey),
	})
}

// Find the public key from the in memory list
// If found return it otherwise generate one and update the list
func getUserKeys(username string) (common.UserKeyPairMap, error) {
	var result common.UserKeyPairMap
	for _, ukpm := range userKeyPairList {
		if ukpm.Username == username {
			// in this case we have a ClientPublicKey in the ukpm
			return ukpm, nil
		}
	}

	// Username does not exist, generate a new key pair
	newKeyPair, err := common.GenerateKeyPair()
	if err != nil {
		// return empty result with an error message
		return result, fmt.Errorf("error generating new key pair: %v", err)
	}

	// in this case we DO NOT have a ClientPublicKey in the ukpm
	result.Username = username
	result.ServerPublicKey = newKeyPair.PublicKey
	result.ServerPrivateKey = newKeyPair.PrivateKey

	// Add the new key pair to the list
	userKeyPairList = append(userKeyPairList, result)

	return result, nil
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
		userKeys, err := getUserKeys(authRequest.Username)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error creating/retriving server key pair: %v", err), http.StatusInternalServerError)
			return
		}

		// Parse the PEM-encoded private key
		privateKey, err := common.ParsePrivateKey(userKeys.ServerPrivateKey)
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
		authResponse.ServerPublicKey = string(userKeys.ServerPublicKey)

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
