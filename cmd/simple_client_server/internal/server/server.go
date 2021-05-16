package server

import (
	"crypto/ed25519"
	"fmt"

	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/hpkehelper"
	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/shared"
	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/shared/protos"
	"google.golang.org/protobuf/proto"
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
	s.StaticSigningKeyPair = n.StaticSigningKeyPair

	go hpkehelper.GenerateHpkeEphemeralKeyPairsWorker(s.HpkeEphemeralKeyPairs)
}

func (s Server) Listening(transport <-chan shared.Message) {
	for tran := range transport {
		fmt.Println("Server", "receive data with length", len(tran.Protobuf))

		var protoMessage protos.Message
		err := proto.Unmarshal(tran.Protobuf, &protoMessage)
		if err != nil {
			panic(err)
		}

		// protoMessage.Signature

		// pubKeys := protoMessage.GetSendersEd25519PublicKeys().Ed25519
		verifed := ed25519.Verify(protoMessage.GetSendersEd25519PublicKeys().Ed25519, protoMessage.ContentData, protoMessage.Signature)
		fmt.Println("Server", "verify", verifed)

		if !verifed {
			panic("Signature invalid")
		}

		var protoContent protos.Content
		if err := proto.Unmarshal(protoMessage.ContentData, &protoContent); err != nil {
			panic(err)
		}

		plain, err := hpkehelper.Decrypt(protoContent, s.HpkeStaticKeyPair.PrivateKeys.Hpke)
		if err != nil {
			panic(err)
		}

		fmt.Println("Server", "Got Message", string(plain))

		tran.Respond <- []byte("Thx, got your message:")
	}
}
