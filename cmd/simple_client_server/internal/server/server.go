package server

import (
	"fmt"

	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/shared"
)

type Server shared.Node

func NewServer() *Server {
	hpkes := make(chan shared.HpkeEphemeralKeyPair, 3)
	return &Server{
		HpkeEphemeralKeyPairs: hpkes,
	}
}

func (s Server) Prepair() {
	n := shared.Node(s)
	n.GenerateStaticKeyPairs()

	go shared.GenerateHpkeEphemeralKeyPairsWorker(s.HpkeEphemeralKeyPairs)
}

func (s Server) Listening(transport <-chan shared.Message) {
	for tran := range transport {
		fmt.Println("Server", "receive", string(tran.Protobuf))
		tran.Respond <- []byte("Thx, got your message")
	}
}
