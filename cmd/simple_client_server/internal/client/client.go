package client

import (
	"fmt"

	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/shared"
)

var ()

type Client shared.Node

func NewClient() *Client {
	hpkes := make(chan shared.HpkeEphemeralKeyPair, 3)
	return &Client{
		HpkeEphemeralKeyPairs: hpkes,
	}
}

func (c Client) Prepair() {
	kp, err := shared.GeneratedStaticKey()
	if err != nil {
		panic(err)
	}
	c.StaticKeyPair = kp

	go shared.GenerateHpkeEphemeralKeyPairs(c.HpkeEphemeralKeyPairs)
}

func (c Client) SendMessages(transport chan<- shared.Message) {
	response := make(chan []byte)

	msg := shared.Message{
		Protobuf: []byte("Hello"),
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
