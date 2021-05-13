package shared

type Node struct {
	StaticKeyPair         StaticKeyPair
	HpkeEphemeralKeyPairs chan HpkeEphemeralKeyPair
}
