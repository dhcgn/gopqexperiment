package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/cloudflare/circl/hpke"
)

const (
	// KEM_X448_HKDF_SHA512 is a KEM using X448 Diffie-Hellman function and
	// HKDF with SHA-512.
	kemID = hpke.KEM_X448_HKDF_SHA512
	// KDF_HKDF_SHA512 is a KDF using HKDF with SHA-512.
	kdfID = hpke.KDF_HKDF_SHA512
	// AEAD_AES256GCM is AES-256 block cipher in Galois Counter Mode (GCM).
	aeadID = hpke.AEAD_AES256GCM
)

var (
	printMessages = true
)

func main() {
	Println("Hello simple_use_case_hpke")

	Println("Success:", mainInternal())
}

func mainInternal() bool {
	Println("Hello simple_use_case_hpke")

	// ---------------
	Println("Generation Public Keys")
	// ---------------

	aliceKeyPair, err := GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	Println(" - Alice KeyPair: ", aliceKeyPair.GetJson())

	bobKeyPair, err := GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	Println(" - Bob KeyPair: ", bobKeyPair.GetJson())

	// ---------------
	Println("Alice creates a message for bob and encrypt them")
	// ---------------

	plainMsg := []byte("This is a secret Message")

	encryptedWireData, err := encrypt(aliceKeyPair, bobKeyPair.PublicKeys, plainMsg)
	if err != nil {
		panic(err)
	}

	// Sends encryptedWireData over the wire
	Println(encryptedWireData.GetJson())
	// Sends encryptedWireData over the wire

	// ---------------
	Println("Bob decrypt the message from Alice")
	// ---------------

	decryptedWireData, err := decrypt(encryptedWireData.SendersPublicKeys, bobKeyPair.PrivateKeys, encryptedWireData)
	if err != nil {
		panic(err)
	}

	return bytes.Equal(plainMsg, decryptedWireData)
}

func GenerateKeyPair() (KeyPair, error) {
	publicKey, privateKey, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		return KeyPair{}, err
	}

	privateRaw, _ := privateKey.MarshalBinary()
	publicRaw, _ := publicKey.MarshalBinary()

	return KeyPair{
		PublicKeys: PublicKeys{
			Hpke: publicRaw,
		},
		PrivateKeys: PrivateKeys{
			Hpke: privateRaw,
		},
	}, nil
}

func encrypt(private KeyPair, public PublicKeys, msg []byte) (WireData, error) {
	info := "Encrypted Content from Application XYZ"

	privateKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(private.PrivateKeys.Hpke)
	if err != nil {
		return WireData{}, err
	}

	publicKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(public.Hpke)
	if err != nil {
		return WireData{}, err
	}

	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	sender, err := suite.NewSender(publicKey, []byte(info))
	if err != nil {
		return WireData{}, err
	}

	enc, sealer, err := sender.SetupAuth(rand.Reader, privateKey)
	if err != nil {
		return WireData{}, err
	}

	// encrypts some plaintext and sends the ciphertext to Bob.
	aad := []byte("additional public data")
	ct, err := sealer.Seal(msg, aad)
	if err != nil {
		return WireData{}, err
	}

	return WireData{
		Info:              info,
		EncapsulatedKey:   enc,
		CipherText:        ct,
		AssociatedData:    aad,
		SendersPublicKeys: private.PublicKeys,
	}, nil
}

func decrypt(public PublicKeys, private PrivateKeys, wiredata WireData) ([]byte, error) {
	privateKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(private.Hpke)
	if err != nil {
		return []byte{}, err
	}

	publicKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(public.Hpke)
	if err != nil {
		return []byte{}, err
	}

	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	receiver, err := suite.NewReceiver(privateKey, []byte(wiredata.Info))
	if err != nil {
		return []byte{}, err
	}

	opener, err := receiver.SetupAuth(wiredata.EncapsulatedKey, publicKey)
	if err != nil {
		return []byte{}, err
	}

	plain, err := opener.Open(wiredata.CipherText, wiredata.AssociatedData)
	if err != nil {
		return []byte{}, err
	}

	return plain, nil
}

// WireData is the data which must be transferred.
// The HPKE does not specify a wire format encoding for HPKE messages.
// To protect the metadata see https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-08.html#name-metadata-protection
type WireData struct {
	// Info is a application-supplied information
	Info string
	// PskId is an identifier for the PSK
	PskId             string
	EncapsulatedKey   []byte
	CipherText        []byte
	AssociatedData    []byte
	SendersPublicKeys PublicKeys
}

type KeyPair struct {
	PublicKeys  PublicKeys
	PrivateKeys PrivateKeys
}

type PublicKeys struct {
	// kem.PublicKey
	Hpke []byte
}
type PrivateKeys struct {
	// kem.PrivateKey
	Hpke []byte
}

func (wd WireData) GetJson() string {
	j, err := json.MarshalIndent(wd, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(j)
}

func (hkp KeyPair) GetJson() string {
	j, err := json.MarshalIndent(hkp, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(j)
}

func Println(a ...interface{}) {
	if printMessages {
		fmt.Println(a...)
	}
}
