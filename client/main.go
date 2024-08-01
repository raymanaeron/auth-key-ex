// main.go
package main

import (
    "fmt"
	"auth-key-exchange/common"
)

var localKeyPair common.KeyPair

func main() {
    // Generate the public/private key pair and assign it to localKeyPair
    keyPair, err := common.GenerateKeyPair()
    if err != nil {
        fmt.Println("Error generating key pair:", err)
        return
    }
    localKeyPair = keyPair

    fmt.Println(string(localKeyPair.PublicKey))

    testEncryptAndDecrypt()
}

func testEncryptAndDecrypt() {
    // Sample data to encrypt and decrypt
    originalData := "Hello, this is a secret message!"

    // Encrypt the data using the public key
    encryptedData, err := common.EncryptWithPublicKey([]byte(originalData), localKeyPair.PublicKey)
    if err != nil {
        fmt.Println("Error encrypting data:", err)
        return
    }
    fmt.Printf("Encrypted Data: %x\n", encryptedData)

    // Decrypt the data using the private key
    decryptedData, err := common.DecryptWithPrivateKey(encryptedData, localKeyPair.PrivateKey)
    if err != nil {
        fmt.Println("Error decrypting data:", err)
        return
    }
    fmt.Printf("Decrypted Data: %s\n", decryptedData)
}
