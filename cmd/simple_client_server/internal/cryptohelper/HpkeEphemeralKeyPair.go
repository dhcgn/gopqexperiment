package cryptohelper

import (
	"fmt"
)

type EphemeralKeyPair struct {
	EncryptionKeyPair EncryptionKeyPair
}

var counter = 1

func GenerateHpkeEphemeralKeyPairsWorker(hpkes chan<- EphemeralKeyPair) {
	for {
		kp, err := GenerateKeyPair()
		if err != nil {
			panic(err)
		}

		hpkes <- EphemeralKeyPair{
			EncryptionKeyPair: kp,
		}

		fmt.Println("GenerateHpkeEphemeralKeyPairs", counter)
		counter++
	}
}
