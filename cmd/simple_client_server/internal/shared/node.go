package shared

import "github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/hpkehelper"

type Node struct {
	StaticSigningKeyPair  StaticKeyPair
	StaticDeriveKeyPair   hpkehelper.KeyPair
	HpkeEphemeralKeyPairs chan HpkeEphemeralKeyPair
}

func (s Node) GenerateStaticKeyPairs() {
	kp, err := GeneratedStaticKey()
	if err != nil {
		panic(err)
	}
	s.StaticSigningKeyPair = kp

	kpDerive, err := hpkehelper.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	s.StaticDeriveKeyPair = kpDerive
}
