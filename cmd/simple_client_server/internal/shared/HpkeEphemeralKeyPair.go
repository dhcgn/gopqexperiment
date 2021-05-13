package shared

import (
	"fmt"

	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/hpkehelper"
)

type HpkeEphemeralKeyPair struct {
	KeyPair hpkehelper.KeyPair
}

var counter = 1

func GenerateHpkeEphemeralKeyPairsWorker(hpkes chan<- HpkeEphemeralKeyPair) {
	for {
		kp, err := hpkehelper.GenerateKeyPair()
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
