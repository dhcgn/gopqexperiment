package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cloudflare/circl/dh/csidh"
	"github.com/cloudflare/circl/hpke"
)

var (
	kemID  = hpke.KEM_P384_HKDF_SHA384
	kdfID  = hpke.KDF_HKDF_SHA384
	aeadID = hpke.AEAD_AES256GCM

	// suite  = hpke.NewSuite(kemID, kdfID, aeadID)
	info = []byte("Encrypted Content from Application XYZ")
)

func main() {
	fmt.Println("Hello simple_use_case_hpke")

	fmt.Println("Success:", mainInternal())
}
func mainInternal() bool {
	fmt.Println("Hello simple_use_case_hpke_csidh")

	// ---------------
	fmt.Println("Generation Public Keys")
	// ---------------

	aliceKeyPair := GenerateKeyPair()
	fmt.Println(" - Alice KeyPair: ", aliceKeyPair.GetJson())

	bobKeyPair := GenerateKeyPair()
	fmt.Println(" - Bob KeyPair: ", bobKeyPair.GetJson())

	// ---------------
	fmt.Println("Alice creates a message for bob")
	// ---------------

	plainMsg := []byte("This is a secret Message")

	encryptedWireData := encrypt(aliceKeyPair.PrivateKeys, bobKeyPair.PublicKeys, plainMsg)

	// Sends encryptedWireData over the wire
	j, err := json.MarshalIndent(encryptedWireData, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(j))
	// Sends encryptedWireData over the wire

	decryptedWireData := decrypt(aliceKeyPair.PublicKeys, bobKeyPair.PrivateKeys, encryptedWireData)

	return bytes.Equal(plainMsg, decryptedWireData)
}

func decrypt(public PublicKeys, private PrivateKeys, wiredata WireData) []byte {
	privateKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(private.PrivateKeyHpke)
	if err != nil {
		panic(err)
	}

	publicKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(public.PublicKeyHpke)
	if err != nil {
		panic(err)
	}

	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	receiver, err := suite.NewReceiver(privateKey, info)
	if err != nil {
		panic(err)
	}

	psk := DeriveSecret(public.PublicKeyCsidh, private.PrivateKeyCsidh)
	pskId := []byte("My PSK")

	fmt.Println("Use PSK:", base64.StdEncoding.EncodeToString(psk))

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

func encrypt(private PrivateKeys, public PublicKeys, msg []byte) WireData {
	privateKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(private.PrivateKeyHpke)
	if err != nil {
		panic(err)
	}

	publicKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(public.PublicKeyHpke)
	if err != nil {
		panic(err)
	}

	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	sender, err := suite.NewSender(publicKey, info)
	if err != nil {
		panic(err)
	}

	psk := DeriveSecret(public.PublicKeyCsidh, private.PrivateKeyCsidh)
	pskId := []byte("My PSK")

	fmt.Println("Use PSK:", base64.StdEncoding.EncodeToString(psk))

	enc, sealer, err := sender.SetupAuthPSK(rand.Reader, privateKey, psk, pskId)
	if err != nil {
		panic(err)
	}

	// encrypts some plaintext and sends the ciphertext to Bob.
	aad := []byte("additional public data")
	ct, err := sealer.Seal(msg, aad)
	if err != nil {
		panic(err)
	}

	// fmt.Println("encrypt")
	// fmt.Println(" - encapsulated key:", base64.StdEncoding.EncodeToString(enc))
	// fmt.Println(" - cipher text:", base64.StdEncoding.EncodeToString(ct))

	return WireData{
		EncapsulatedKey: enc,
		CipherText:      ct,
		AssociatedData:  aad,
	}
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

func GenerateKeyPair() HybridKeyPair {
	public, private, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	publicData, _ := public.MarshalBinary()
	privateData, _ := private.MarshalBinary()

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
			PublicKeyHpke:  publicData,
			PublicKeyCsidh: publicCsidhData[:],
		},
		PrivateKeys: PrivateKeys{
			PrivateKeyHpke:  privateData,
			PrivateKeyCsidh: privateCsidhData[:],
		},
	}
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

type HybridKeyPair struct {
	PublicKeys  PublicKeys
	PrivateKeys PrivateKeys
}

type PublicKeys struct {
	// kem.PublicKey
	PublicKeyHpke []byte
	// csidh.PublicKey
	PublicKeyCsidh []byte
}
type PrivateKeys struct {
	// kem.PrivateKey
	PrivateKeyHpke []byte
	// csidh.PrivateKey
	PrivateKeyCsidh []byte
}

func (hkp HybridKeyPair) GetJson() string {
	j, err := json.MarshalIndent(hkp, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(j)
}
