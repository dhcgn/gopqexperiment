package hpkehelper

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/cloudflare/circl/hpke"
	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/shared"
	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/shared/protos"
	"google.golang.org/protobuf/proto"
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

func Decrypt(content protos.Content, privateHpkeKey []byte) ([]byte, error) {
	privateKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(privateHpkeKey)
	if err != nil {
		return []byte{}, err
	}

	publicKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(content.SendersHpkePublicKeys.Hpke)
	if err != nil {
		return []byte{}, err
	}

	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	receiver, err := suite.NewReceiver(privateKey, []byte(content.Info))
	if err != nil {
		return []byte{}, err
	}

	opener, err := receiver.SetupAuth(content.EncapsulatedKey, publicKey)
	if err != nil {
		return []byte{}, err
	}

	plain, err := opener.Open(content.CipherText, content.AssociatedData)
	if err != nil {
		return []byte{}, err
	}

	return plain, nil
}

func CreateEncryptedMessage(senderHpke HpkeEphemeralKeyPair, senderEd25519 shared.StaticKeyPair, recipientHpke PublicKeys, msg []byte) ([]byte, error) {
	info := "Encrypted Content from Application XYZ"

	privateKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(senderHpke.KeyPair.PrivateKeys.Hpke)
	if err != nil {
		return nil, err
	}

	publicKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(recipientHpke.Hpke)
	if err != nil {
		return nil, err
	}

	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	sender, err := suite.NewSender(publicKey, []byte(info))
	if err != nil {
		return nil, err
	}

	enc, sealer, err := sender.SetupAuth(rand.Reader, privateKey)
	if err != nil {
		return nil, err
	}

	// encrypts some plaintext and sends the ciphertext to Bob.
	aad := []byte("additional public data")
	ct, err := sealer.Seal(msg, aad)
	if err != nil {
		return nil, err
	}

	// return WireData{
	// 	Info:              info,
	// 	EncapsulatedKey:   enc,
	// 	CipherText:        ct,
	// 	AssociatedData:    aad,
	// 	SendersPublicKeys: private.PublicKeys,
	// }, nil

	content := &protos.Content{
		Version:         1,
		Info:            info,
		PskID:           "MyPSKID",
		EncapsulatedKey: enc,
		CipherText:      ct,
		AssociatedData:  aad,
		SendersHpkePublicKeys: &protos.PublicKeys{
			Version: 1,
			Hpke:    senderHpke.KeyPair.PublicKeys.Hpke,
			Ed25519: senderEd25519.PublicKey,
		},
	}

	contentData, err := proto.Marshal(content)
	if err != nil {
		return nil, err
	}

	signature := ed25519.Sign(senderEd25519.PrivateKey, contentData)

	protbufMessage := &protos.Message{
		Version:     1,
		Target:      "MyTarget",
		ContentData: contentData,
		Signature:   signature,
		SendersEd25519PublicKeys: &protos.PublicKeys{
			Version: 1,
			Hpke:    nil,
			Ed25519: senderEd25519.PublicKey,
		},
	}
	protbufMessage.ProtoMessage()

	data, err := proto.Marshal(protbufMessage)

	return data, err
}
