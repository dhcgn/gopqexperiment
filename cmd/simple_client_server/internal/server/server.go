package server

import (
	"fmt"

	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/shared"
)

func Listening(transport <-chan shared.Message) {
	for tran := range transport {
		fmt.Println("Server", "receive", string(tran.Protobuf))
		tran.Respond <- []byte("Thx, got your message")
	}
}
