package client

import (
	"fmt"

	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/hpkehelper"
	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/shared"
)

var ()

type Client hpkehelper.Node

func NewClient() *Client {
	hpkes := make(chan hpkehelper.HpkeEphemeralKeyPair, 3)
	return &Client{
		HpkeEphemeralKeyPairs: hpkes,
	}
}

func (c Client) Prepair() {
	n := hpkehelper.Node(c)
	n.GenerateStaticKeyPairs()

	go hpkehelper.GenerateHpkeEphemeralKeyPairsWorker(c.HpkeEphemeralKeyPairs)
}

func (c Client) SendMessages(transport chan<- shared.Message, pub hpkehelper.PublicKeys) {
	response := make(chan []byte)

	// Read a HpkeEphemeralKeyPair, so a new one is generated in the backgroudn
	//protobuf := hpkehelper.CreateEncryptedMessage(<-c.HpkeEphemeralKeyPairs, c.StaticSigningKeyPair, pub)
	protobuf := hpkehelper.CreateEncryptedMessage(<-c.HpkeEphemeralKeyPairs, c.StaticSigningKeyPair, pub)

	msg := shared.Message{
		Protobuf: protobuf,
		Respond:  response,
	}

	go func() {
		resp := <-response
		fmt.Println("Client", "Got response", string(resp))
	}()

	fmt.Println("Client", "Send message", string(msg.Protobuf))
	transport <- msg

	fmt.Println("Client", "Waiting ...")
}
