package cryptohelper

type Node struct {
	StaticSigningKeyPair  StaticKeyPair
	HpkeStaticKeyPair     KeyPair
	HpkeEphemeralKeyPairs chan HpkeEphemeralKeyPair
}

func (s *Node) GenerateStaticKeyPairs() {
	kp, err := GeneratedStaticKey()
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
