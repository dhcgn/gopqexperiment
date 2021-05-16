package client

import (
	"fmt"
	"time"

	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/cryptohelper"
	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/shared"
)

var ()

type Client cryptohelper.Node

func NewClient() *Client {
	hpkes := make(chan cryptohelper.EphemeralKeyPair, 3)
	return &Client{
		EphemeralHpkeKeyPairs: hpkes,
	}
}

func (c *Client) Prepare() {
	n := cryptohelper.Node(*c)
	n.GenerateStaticKeyPairs()

	c.StaticHpkeKeyPair = n.StaticHpkeKeyPair
	c.StaticSigningKeyPair = n.StaticSigningKeyPair

	go cryptohelper.GenerateHpkeEphemeralKeyPairsWorker(c.EphemeralHpkeKeyPairs)
}

func (c Client) SendMessages(transport chan<- shared.Message, pub cryptohelper.PublicKeys) {
	response := make(chan []byte)

	// Read a EphemeralKeyPair, so a new one is generated in the backgroudn
	//protobuf := hpkehelper.CreateEncryptedMessage(<-c.EphemeralHpkeKeyPairs, c.StaticSigningKemsgyPair, pub)
	msg := []byte(time.Now().Format(time.RFC3339Nano))
	keyPair := <-c.EphemeralHpkeKeyPairs
	protobuf, err := cryptohelper.CreateEncryptedMessage(keyPair, c.StaticSigningKeyPair, pub.Hpke, msg)
	if err != nil {
		panic(err)
	}

	transportData := shared.Message{
		Protobuf: protobuf,
		Respond:  response,
	}

	go func(privateHpke []byte) {
		resp := <-response

		_, plain := cryptohelper.VerifyAndDecrypt(resp, privateHpke)

		fmt.Println("Client", "Got response", string(plain))

		startDateTime, _ := time.Parse(time.RFC3339Nano, string(plain))
		serverDateTime := time.Now()

		duration := serverDateTime.Sub(startDateTime)
		fmt.Println("Server", "Duration", duration)

	}(keyPair.EncryptionKeyPair.PrivateKeys.Hpke)

	fmt.Println("Client", "Send message of length", len(transportData.Protobuf))
	transport <- transportData

	fmt.Println("Client", "Waiting ...")
}
