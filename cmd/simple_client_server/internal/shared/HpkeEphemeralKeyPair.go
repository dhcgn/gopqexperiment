package shared

import "fmt"

type HpkeEphemeralKeyPair struct {
}

var counter = 1

func GenerateHpkeEphemeralKeyPairs(hpkes chan<- HpkeEphemeralKeyPair) {
	for {
		hpkes <- HpkeEphemeralKeyPair{}

		fmt.Println("GenerateHpkeEphemeralKeyPairs", counter)
		counter++
	}
}
