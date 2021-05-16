package client

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/hpkehelper"
	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/shared"
	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/shared/protos"
	"google.golang.org/protobuf/proto"
)

var ()

type Client hpkehelper.Node

func NewClient() *Client {
	hpkes := make(chan hpkehelper.HpkeEphemeralKeyPair, 3)
	return &Client{
		HpkeEphemeralKeyPairs: hpkes,
	}
}

func (c *Client) Prepair() {
	n := hpkehelper.Node(*c)
	n.GenerateStaticKeyPairs()

	c.HpkeStaticKeyPair = n.HpkeStaticKeyPair
	c.StaticSigningKeyPair = n.StaticSigningKeyPair

	go hpkehelper.GenerateHpkeEphemeralKeyPairsWorker(c.HpkeEphemeralKeyPairs)
}

func (c Client) SendMessages(transport chan<- shared.Message, pub hpkehelper.PublicKeys) {
	response := make(chan []byte)

	// Read a HpkeEphemeralKeyPair, so a new one is generated in the backgroudn
	//protobuf := hpkehelper.CreateEncryptedMessage(<-c.HpkeEphemeralKeyPairs, c.StaticSigningKemsgyPair, pub)
	msg := []byte(time.Now().Format(time.RFC3339Nano))
	keyPair := <-c.HpkeEphemeralKeyPairs
	protobuf, err := hpkehelper.CreateEncryptedMessage(keyPair, c.StaticSigningKeyPair, pub.Hpke, msg)
	if err != nil {
		panic(err)
	}

	transportData := shared.Message{
		Protobuf: protobuf,
		Respond:  response,
	}

	go func(privateHpke []byte) {
		resp := <-response

		_, plain := VerifyAndDecrypt(resp, privateHpke)

		fmt.Println("Client", "Got response", string(plain))

		startDateTime, _ := time.Parse(time.RFC3339Nano, string(plain))
		serverDateTime := time.Now()

		duration := serverDateTime.Sub(startDateTime)
		fmt.Println("Server", "Duration", duration)

	}(keyPair.KeyPair.PrivateKeys.Hpke)

	fmt.Println("Client", "Send message of length", len(transportData.Protobuf))
	transport <- transportData

	fmt.Println("Client", "Waiting ...")
}

func VerifyAndDecrypt(transportData []byte, privateHpke []byte) (hpke []byte, plain []byte) {
	fmt.Println("Client", "receive data with length", len(transportData))

	var protoMessage protos.Message
	err := proto.Unmarshal(transportData, &protoMessage)
	if err != nil {
		panic(err)
	}

	verifed := ed25519.Verify(protoMessage.GetSendersEd25519PublicKeys().Ed25519, protoMessage.ContentData, protoMessage.Signature)
	fmt.Println("Client", "verify", verifed)

	if !verifed {
		panic("Signature invalid")
	}

	var protoContent protos.Content
	if err := proto.Unmarshal(protoMessage.ContentData, &protoContent); err != nil {
		panic(err)
	}

	plain, err = hpkehelper.Decrypt(protoContent, privateHpke)
	if err != nil {
		panic(err)
	}
	return protoContent.SendersHpkePublicKeys.Hpke, plain
}
