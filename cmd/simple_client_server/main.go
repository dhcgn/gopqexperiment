package main

import (
	"os"
	"os/signal"
	"sync"

	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/client"
	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/server"
	"github.com/dhcgn/gopqexperiment/cmd/simple_client_server/internal/shared"
)

func main() {
	transport := make(chan shared.Message)

	c := client.NewClient()
	c.Prepair()

	s := server.NewServer()
	s.Prepair()

	go s.Listening(transport)
	go c.SendMessages(transport, s.StaticHpkeKeyPair.PublicKeys)

	WaitForCtrlC()
}

func WaitForCtrlC() {
	var end_waiter sync.WaitGroup
	end_waiter.Add(1)
	var signal_channel chan os.Signal
	signal_channel = make(chan os.Signal, 1)
	signal.Notify(signal_channel, os.Interrupt)
	go func() {
		<-signal_channel
		end_waiter.Done()
	}()
	end_waiter.Wait()
}
