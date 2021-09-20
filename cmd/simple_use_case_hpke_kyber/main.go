package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
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
	schema        = kyber1024.Scheme()
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

	decryptedWireData, _ := decrypt(encryptedWireData.SendersPublicKeys, bobKeyPair.PrivateKeys, encryptedWireData)

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

	publicKyber, privateKyber, err := schema.GenerateKeyPair()

	privateKyberData, err := privateKyber.MarshalBinary()
	publicKyberData, err := publicKyber.MarshalBinary()

	return HybridKeyPair{
		PublicKeys: PublicKeys{
			Hpke:  publicData,
			Kyber: publicKyberData[:],
		},
		PrivateKeys: PrivateKeys{
			Hpke:  privateData,
			Kyber: privateKyberData[:],
		},
	}, nil
}

func encrypt(private HybridKeyPair, public PublicKeys, msg []byte) (WireData, error) {
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

	psk, dsct := DeriveSecret(public.Kyber, private.PrivateKeys.Kyber, nil)
	pskId := "The identifier for the PSK"

	enc, sealer, err := sender.SetupAuthPSK(rand.Reader, privateKey, psk, []byte(pskId))
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
		Info:                    info,
		PskId:                   pskId,
		EncapsulatedKey:         enc,
		CipherText:              ct,
		AssociatedData:          aad,
		DerivedSecretCipherText: dsct,
		SendersPublicKeys:       private.PublicKeys,
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

	psk, _ := DeriveSecret(public.Kyber, private.Kyber, wiredata.DerivedSecretCipherText)

	opener, err := receiver.SetupAuthPSK(wiredata.EncapsulatedKey, psk, []byte(wiredata.PskId), publicKey)
	if err != nil {
		return []byte{}, err
	}

	plain, err := opener.Open(wiredata.CipherText, wiredata.AssociatedData)
	if err != nil {
		return []byte{}, err
	}

	return plain, nil
}

func DeriveSecret(publicKeyData, privateKeyData, derivedSecretCipherText []byte) (ss []byte, ct []byte) {

	publicKey, err := schema.UnmarshalBinaryPublicKey(publicKeyData)
	if err != nil {
		panic("DeriveSecret")
	}
	privateKey, err := schema.UnmarshalBinaryPrivateKey(privateKeyData)
	if err != nil {
		panic("DeriveSecret")
	}

	if len(derivedSecretCipherText) == 0 {
		ct, ss, err = schema.Encapsulate(publicKey)

		// weak bytes from DeriveSecret?
		shasum := sha512.Sum512(ss[:])
		return shasum[:], ct
	} else {
		ss, err = schema.Decapsulate(privateKey, derivedSecretCipherText)

		// weak bytes from DeriveSecret?
		shasum := sha512.Sum512(ss[:])
		return shasum[:], ct
	}
}

// WireData is the data which must be transferred.
// The HPKE does not specify a wire format encoding for HPKE messages.
// To protect the metadata see https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-08.html#name-metadata-protection
type WireData struct {
	// Info is a application-supplied information
	Info string
	// PskId is an identifier for the PSK
	PskId                   string
	EncapsulatedKey         []byte
	CipherText              []byte
	AssociatedData          []byte
	DerivedSecretCipherText []byte
	SendersPublicKeys       PublicKeys
}

type HybridKeyPair struct {
	PublicKeys  PublicKeys
	PrivateKeys PrivateKeys
}

type PublicKeys struct {
	// kem.PublicKey
	Hpke []byte
	// csidh.PublicKey
	Kyber []byte
}
type PrivateKeys struct {
	// kem.PrivateKey
	Hpke []byte
	// csidh.PrivateKey
	Kyber []byte
}

func (wd WireData) GetJson() string {
	j, err := json.MarshalIndent(wd, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(j)
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
