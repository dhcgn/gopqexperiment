package cryptohelper

import (
	"fmt"
)

type EphemeralKeyPair struct {
	KeyPair StaticHpkeKeyPair
}

var counter = 1

func GenerateHpkeEphemeralKeyPairsWorker(hpkes chan<- EphemeralKeyPair) {
	for {
		kp, err := GenerateKeyPair()
		if err != nil {
			panic(err)
		}

		hpkes <- EphemeralKeyPair{
			KeyPair: kp,
		}

		fmt.Println("GenerateHpkeEphemeralKeyPairs", counter)
		counter++
	}
}
