package server

import (
	"fmt"

	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/hpkehelper"
	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/shared"
)

type Server hpkehelper.Node

func NewServer() *Server {
	hpkes := make(chan hpkehelper.HpkeEphemeralKeyPair, 3)
	return &Server{
		HpkeEphemeralKeyPairs: hpkes,
	}
}

func (s *Server) Prepair() {
	n := hpkehelper.Node(*s)
	n.GenerateStaticKeyPairs()

	s.HpkeStaticKeyPair = n.HpkeStaticKeyPair

	go hpkehelper.GenerateHpkeEphemeralKeyPairsWorker(s.HpkeEphemeralKeyPairs)
}

func (s Server) Listening(transport <-chan shared.Message) {
	for tran := range transport {
		fmt.Println("Server", "receive", string(tran.Protobuf))
		tran.Respond <- []byte("Thx, got your message")
	}
}
