package hpkehelper

import "github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/shared"

type Node struct {
	StaticSigningKeyPair  shared.StaticKeyPair
	HpkeStaticKeyPair     KeyPair
	HpkeEphemeralKeyPairs chan HpkeEphemeralKeyPair
}

func (s *Node) GenerateStaticKeyPairs() {
	kp, err := shared.GeneratedStaticKey()
	if err != nil {
		panic(err)
	}
	s.StaticSigningKeyPair = kp

	kpDerive, err := GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	s.HpkeStaticKeyPair = kpDerive
}
