package hpkehelper

import (
	"fmt"
)

type HpkeEphemeralKeyPair struct {
	KeyPair KeyPair
}

var counter = 1

func GenerateHpkeEphemeralKeyPairsWorker(hpkes chan<- HpkeEphemeralKeyPair) {
	for {
		kp, err := GenerateKeyPair()
		if err != nil {
			panic(err)
		}

		hpkes <- HpkeEphemeralKeyPair{
			KeyPair: kp,
		}

		fmt.Println("GenerateHpkeEphemeralKeyPairs", counter)
		counter++
	}
}
