package client

import (
	"fmt"

	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/shared"
)

func SendMessages(transport chan<- shared.Message) {
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
