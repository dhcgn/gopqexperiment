package cryptohelper

import (
	"crypto/ed25519"
	"crypto/rand"
)

func GeneratedStaticKey() (StaticKeyPair, error) {

	pub, priv, err := ed25519.GenerateKey(rand.Reader)

	return StaticKeyPair{pub, priv}, err
}

type StaticKeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}
