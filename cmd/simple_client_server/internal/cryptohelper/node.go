package cryptohelper

type Node struct {
	StaticSigningKeyPair  StaticSigningKeyPair
	StaticHpkeKeyPair     StaticHpkeKeyPair
	EphemeralHpkeKeyPairs chan EphemeralKeyPair
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

	s.StaticHpkeKeyPair = kpDerive
}
