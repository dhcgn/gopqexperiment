package main

import (
	"bytes"
	"crypto/rand"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

var (
	printMessages = true

	kemID  = hpke.KEM_X448_HKDF_SHA512
	kdfID  = hpke.KDF_HKDF_SHA512
	aeadID = hpke.AEAD_AES256GCM

	// suite  = hpke.NewSuite(kemID, kdfID, aeadID)
	info = []byte("Encrypted Content from Application XYZ")
)

func main() {
	Println("Hello simple_use_case_hpke")

	Println("Success:", mainInternal())
}

func mainInternal() bool {
	// ---------------
	Println("Generation Public Keys")
	// ---------------

	alicePublic, alicePrivate, err := GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	Println(" - Alice Public: ", printKey(alicePublic))
	Println(" - Alice Private:", printKey(alicePrivate))

	bobPublic, bobPrivate, err := GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	Println(" - Bob Public: ", printKey(bobPublic))
	Println(" - Bob Private:", printKey(bobPrivate))

	// ---------------
	Println("Alice creates a message for bob")
	// ---------------

	alicePrivateRaw, _ := alicePrivate.MarshalBinary()
	bobPublicRaw, _ := bobPublic.MarshalBinary()
	plainMsg := []byte("This is a secret Message")

	encryptedWireData, _ := encrypt(alicePrivateRaw, bobPublicRaw, plainMsg)

	// Sends encryptedWireData over the wire
	j, err := json.MarshalIndent(encryptedWireData, "", "  ")
	if err != nil {
		panic(err)
	}
	Println(string(j))
	// Sends encryptedWireData over the wire

	alicePublicRaw, _ := alicePublic.MarshalBinary()
	bobPrivateRaw, _ := bobPrivate.MarshalBinary()
	decryptedWireData := decrypt(alicePublicRaw, bobPrivateRaw, encryptedWireData)

	return bytes.Equal(plainMsg, decryptedWireData)
}

func GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	return kemID.Scheme().GenerateKeyPair()
}

func decrypt(public, private []byte, wiredata WireData) []byte {
	privateKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(private)
	if err != nil {
		panic(err)
	}

	publicKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(public)
	if err != nil {
		panic(err)
	}

	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	receiver, err := suite.NewReceiver(privateKey, info)
	if err != nil {
		panic(err)
	}

	opener, err := receiver.SetupAuth(wiredata.EncapsulatedKey, publicKey)
	if err != nil {
		panic(err)
	}

	plain, err := opener.Open(wiredata.CipherText, wiredata.AssociatedData)
	if err != nil {
		panic(err)
	}

	return plain
}

func encrypt(private, public, msg []byte) (WireData, error) {
	privateKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(private)
	if err != nil {
		return WireData{}, err
	}

	publicKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(public)
	if err != nil {
		return WireData{}, err
	}

	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	sender, err := suite.NewSender(publicKey, info)
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

	// Println("encrypt")
	// Println(" - encapsulated key:", base64.StdEncoding.EncodeToString(enc))
	// Println(" - cipher text:", base64.StdEncoding.EncodeToString(ct))

	return WireData{
		EncapsulatedKey: enc,
		CipherText:      ct,
		AssociatedData:  aad,
	}, nil
}

func printKey(binaryMarshaler encoding.BinaryMarshaler) string {
	bobPublicRaw, _ := binaryMarshaler.MarshalBinary()
	base64 := base64.StdEncoding.EncodeToString(bobPublicRaw)
	return base64
}

type WireData struct {
	EncapsulatedKey []byte
	CipherText      []byte
	AssociatedData  []byte
}

func Println(a ...interface{}) {
	if printMessages {
		fmt.Println(a...)
	}
}
