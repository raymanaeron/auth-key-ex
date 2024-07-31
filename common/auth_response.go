package common

// AuthResponse represents the authentication response structure
type AuthResponse struct {
	Authenticated   bool   `json:"authenticated"`
	Token           string `json:"token"`
	ServerPublicKey string `json:"serverPublicKey"`
}