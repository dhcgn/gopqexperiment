package server

import (
	"fmt"
	"time"

	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/cryptohelper"
	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/shared"
)

type Server cryptohelper.Node

func NewServer() *Server {
	hpkes := make(chan cryptohelper.HpkeEphemeralKeyPair, 3)
	return &Server{
		HpkeEphemeralKeyPairs: hpkes,
	}
}

func (s *Server) Prepair() {
	n := cryptohelper.Node(*s)
	n.GenerateStaticKeyPairs()

	s.HpkeStaticKeyPair = n.HpkeStaticKeyPair
	s.StaticSigningKeyPair = n.StaticSigningKeyPair

	go cryptohelper.GenerateHpkeEphemeralKeyPairsWorker(s.HpkeEphemeralKeyPairs)
}

func (s Server) Listening(transport <-chan shared.Message) {
	for tran := range transport {
		hpke, plain := cryptohelper.VerifyAndDecrypt(tran.Protobuf, s.HpkeStaticKeyPair.PrivateKeys.Hpke)

		fmt.Println("Server", "Got Message", string(plain))

		startDateTime, _ := time.Parse(time.RFC3339Nano, string(plain))
		serverDateTime := time.Now()

		duration := serverDateTime.Sub(startDateTime)
		fmt.Println("Server", "Duration", duration)

		protobuf, err := cryptohelper.CreateEncryptedMessage(<-s.HpkeEphemeralKeyPairs, s.StaticSigningKeyPair, hpke, []byte(time.Now().Format(time.RFC3339Nano)))
		if err != nil {
			panic(err)
		}

		tran.Respond <- protobuf
	}
}
