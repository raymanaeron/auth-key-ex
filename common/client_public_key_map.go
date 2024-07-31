package common

// ClientPublicKeyMap represents a mapping of a username to a public key
type ClientPublicKeyMap struct {
	Username  string `json:"username"`
	PublicKey string `json:"publicKey"`
}