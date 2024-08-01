package common

// AuthRequest represents the authentication request structure
type ExchangeRequest struct {
	Username       string `json:"username"`
	ClientPublicKey string `json:"clientpublickey"`
}
