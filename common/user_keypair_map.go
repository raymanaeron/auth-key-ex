// keypair.go
package common

type UserKeyPairMap struct {
	Username string
    ServerPublicKey  []byte
    ServerPrivateKey []byte
    ClientPublicKey  []byte
}
