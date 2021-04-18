package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cloudflare/circl/dh/csidh"
	"github.com/cloudflare/circl/hpke"
)

var (
	printMessages = true

	kemID  = hpke.KEM_X448_HKDF_SHA512
	kdfID  = hpke.KDF_HKDF_SHA512
	aeadID = hpke.AEAD_AES256GCM

	info = []byte("Encrypted Content from Application XYZ")
)

func main() {
	Println("Hello simple_use_case_hpke")

	Println("Success:", mainInternal())
}

func mainInternal() bool {
	Println("Hello simple_use_case_hpke_csidh")

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
	Println("Alice creates a message for bob")
	// ---------------

	plainMsg := []byte("This is a secret Message")

	encryptedWireData, err := encrypt(aliceKeyPair, bobKeyPair.PublicKeys, plainMsg)
	if err != nil {
		panic(err)
	}

	// Sends encryptedWireData over the wire
	j, err := json.MarshalIndent(encryptedWireData, "", "  ")
	if err != nil {
		panic(err)
	}
	Println(string(j))
	// Sends encryptedWireData over the wire

	decryptedWireData := decrypt(encryptedWireData.SendersPublicKeys, bobKeyPair.PrivateKeys, encryptedWireData)

	return bytes.Equal(plainMsg, decryptedWireData)
}

func GenerateKeyPair() (HybridKeyPair, error) {
	public, private, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		return HybridKeyPair{}, err
	}

	publicData, err := public.MarshalBinary()
	if err != nil {
		return HybridKeyPair{}, err
	}
	privateData, err := private.MarshalBinary()
	if err != nil {
		return HybridKeyPair{}, err
	}

	var privateCsidh csidh.PrivateKey
	var publicCsidh csidh.PublicKey
	csidh.GeneratePrivateKey(&privateCsidh, rand.Reader)
	csidh.GeneratePublicKey(&publicCsidh, &privateCsidh, rand.Reader)

	var privateCsidhData [37]byte
	privateCsidh.Export(privateCsidhData[:])

	var publicCsidhData [64]byte
	publicCsidh.Export(publicCsidhData[:])

	return HybridKeyPair{
		PublicKeys: PublicKeys{
			Hpke:  publicData,
			Csidh: publicCsidhData[:],
		},
		PrivateKeys: PrivateKeys{
			Hpke:  privateData,
			Csidh: privateCsidhData[:],
		},
	}, nil
}

func encrypt(private HybridKeyPair, public PublicKeys, msg []byte) (WireData, error) {
	privateKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(private.PrivateKeys.Hpke)
	if err != nil {
		return WireData{}, err
	}

	publicKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(public.Hpke)
	if err != nil {
		return WireData{}, err
	}

	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	sender, err := suite.NewSender(publicKey, info)
	if err != nil {
		return WireData{}, err
	}

	psk := DeriveSecret(public.Csidh, private.PrivateKeys.Csidh)
	pskId := []byte("My PSK")

	Println("Use PSK:", base64.StdEncoding.EncodeToString(psk))

	enc, sealer, err := sender.SetupAuthPSK(rand.Reader, privateKey, psk, pskId)
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
		EncapsulatedKey:   enc,
		CipherText:        ct,
		AssociatedData:    aad,
		SendersPublicKeys: private.PublicKeys,
	}, nil
}

func decrypt(public PublicKeys, private PrivateKeys, wiredata WireData) []byte {
	privateKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(private.Hpke)
	if err != nil {
		panic(err)
	}

	publicKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(public.Hpke)
	if err != nil {
		panic(err)
	}

	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	receiver, err := suite.NewReceiver(privateKey, info)
	if err != nil {
		panic(err)
	}

	psk := DeriveSecret(public.Csidh, private.Csidh)
	pskId := []byte("My PSK")

	Println("Use PSK:", base64.StdEncoding.EncodeToString(psk))

	opener, err := receiver.SetupAuthPSK(wiredata.EncapsulatedKey, psk, pskId, publicKey)
	if err != nil {
		panic(err)
	}

	plain, err := opener.Open(wiredata.CipherText, wiredata.AssociatedData)
	if err != nil {
		panic(err)
	}

	return plain
}

func DeriveSecret(publicKeyData, privateKeyData []byte) []byte {
	var ss [64]byte
	var privateKey csidh.PrivateKey
	var publicKey csidh.PublicKey

	privateKey.Import(privateKeyData)
	publicKey.Import(publicKeyData)

	success := csidh.DeriveSecret(&ss, &publicKey, &privateKey, rand.Reader)
	if !success {
		panic("DeriveSecret")
	}

	// weak bytes from DeriveSecret?
	shasum := sha512.Sum512(ss[:])
	return shasum[:]
}

type WireData struct {
	EncapsulatedKey   []byte
	CipherText        []byte
	AssociatedData    []byte
	SendersPublicKeys PublicKeys
}

type HybridKeyPair struct {
	PublicKeys  PublicKeys
	PrivateKeys PrivateKeys
}

type PublicKeys struct {
	// kem.PublicKey
	Hpke []byte
	// csidh.PublicKey
	Csidh []byte
}
type PrivateKeys struct {
	// kem.PrivateKey
	Hpke []byte
	// csidh.PrivateKey
	Csidh []byte
}

func (hkp HybridKeyPair) GetJson() string {
	j, err := json.MarshalIndent(hkp, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(j)
}

func (hkp PublicKeys) GetJson() string {
	j, err := json.MarshalIndent(hkp, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(j)
}

func (hkp PrivateKeys) GetJson() string {
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
