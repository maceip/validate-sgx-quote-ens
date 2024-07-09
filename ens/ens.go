package ens

import (
	"context"
	"fmt"
	"log"
	"time"
	ens "github.com/wealdtech/go-ens/v3"
	"github.com/ethereum/go-ethereum/ethclient"
	"tideland.dev/go/wait"
)

func Resolve(client *ethclient.Client, domain string) (string, error) {
	address, err := ens.Resolve(client, domain)
	if err != nil {
		log.Fatal("ens.Resolve: ", err)
		return "", err
	}
	return address.Hex(), nil
}

func PollEnsResolution(client *ethclient.Client, name string) {
	ensTicker := wait.MakeMaxIntervalsTicker(5*time.Millisecond, 10)
	ensQuery := func() (bool, error) {
		domain := name
		fmt.Println("resolving: " + domain)
		address, err := Resolve(client, domain)
		if err != nil {
			log.Fatal("ens.Resolve: ", err)
			return false, err
		}
		fmt.Printf("address is %s\n", address)
		return true, nil
	}

	wait.Poll(context.Background(), ensTicker, ensQuery)
}
