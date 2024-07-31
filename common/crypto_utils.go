// crypto_utils.go
package common

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "errors"
)

// generateKeyPair generates an RSA public/private key pair and returns a KeyPair struct
func GenerateKeyPair() (KeyPair, error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return KeyPair{}, err
    }

    publicKey := &privateKey.PublicKey

    // Encode private key to PEM format
    privateKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
    })

    // Encode public key to PEM format
    publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {
        return KeyPair{}, err
    }
    publicKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: publicKeyBytes,
    })

    return KeyPair{
        PublicKey:  publicKeyPEM,
        PrivateKey: privateKeyPEM,
    }, nil
}

// EncryptWithPublicKey encrypts the given data using the provided public key
func EncryptWithPublicKey(data []byte, publicKeyPEM []byte) ([]byte, error) {
    // Decode the PEM encoded public key
    block, _ := pem.Decode(publicKeyPEM)
    if block == nil || block.Type != "RSA PUBLIC KEY" {
        return nil, errors.New("failed to decode PEM block containing public key")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    publicKey, ok := pub.(*rsa.PublicKey)
    if !ok {
        return nil, errors.New("not a valid RSA public key")
    }

    // Encrypt the data
    encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
    if err != nil {
        return nil, err
    }

    return encryptedBytes, nil
}

// DecryptWithPrivateKey decrypts the given data using the provided private key
func DecryptWithPrivateKey(data []byte, privateKeyPEM []byte) ([]byte, error) {
    // Decode the PEM encoded private key
    block, _ := pem.Decode(privateKeyPEM)
    if block == nil || block.Type != "RSA PRIVATE KEY" {
        return nil, errors.New("failed to decode PEM block containing private key")
    }

    privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    // Decrypt the data
    decryptedBytes, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
    if err != nil {
        return nil, err
    }

    return decryptedBytes, nil
}
