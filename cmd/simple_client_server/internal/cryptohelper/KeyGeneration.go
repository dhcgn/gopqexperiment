package cryptohelper

import (
	"crypto/ed25519"
	"crypto/rand"
)

func GeneratedStaticKey() (StaticSigningKeyPair, error) {

	pub, priv, err := ed25519.GenerateKey(rand.Reader)

	return StaticSigningKeyPair{pub, priv}, err
}

type StaticSigningKeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}
