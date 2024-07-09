package crypto

import (
	"crypto/ecdsa"
	"log"

	"github.com/ethereum/go-ethereum/crypto"
	ps "github.com/etaaa/Golang-Ethereum-Personal-Sign"
)

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

func PersonalSign(message string, privateKey *ecdsa.PrivateKey) (string, error) {
	signature, err := ps.PersonalSign(message, privateKey)
	if err != nil {
		log.Fatal(err)
	}
	return signature, nil
}
