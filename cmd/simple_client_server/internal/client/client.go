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
	hpkes := make(chan cryptohelper.HpkeEphemeralKeyPair, 3)
	return &Client{
		HpkeEphemeralKeyPairs: hpkes,
	}
}

func (c *Client) Prepair() {
	n := cryptohelper.Node(*c)
	n.GenerateStaticKeyPairs()

	c.HpkeStaticKeyPair = n.HpkeStaticKeyPair
	c.StaticSigningKeyPair = n.StaticSigningKeyPair

	go cryptohelper.GenerateHpkeEphemeralKeyPairsWorker(c.HpkeEphemeralKeyPairs)
}

func (c Client) SendMessages(transport chan<- shared.Message, pub cryptohelper.PublicKeys) {
	response := make(chan []byte)

	// Read a HpkeEphemeralKeyPair, so a new one is generated in the backgroudn
	//protobuf := hpkehelper.CreateEncryptedMessage(<-c.HpkeEphemeralKeyPairs, c.StaticSigningKemsgyPair, pub)
	msg := []byte(time.Now().Format(time.RFC3339Nano))
	keyPair := <-c.HpkeEphemeralKeyPairs
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

	}(keyPair.KeyPair.PrivateKeys.Hpke)

	fmt.Println("Client", "Send message of length", len(transportData.Protobuf))
	transport <- transportData

	fmt.Println("Client", "Waiting ...")
}
