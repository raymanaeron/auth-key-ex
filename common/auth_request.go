package common

// AuthRequest represents the authentication request structure
type AuthRequest struct {
	Username       string `json:"username"`
	Encrypted      string `json:"encrypted"`
	ClientPublicKey string `json:"clientPublicKey"`
}
