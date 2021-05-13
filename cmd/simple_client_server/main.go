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
	messages := make(chan shared.Message)

	c := client.NewClient()
	c.Prepair()

	s := server.NewServer()
	s.Prepair()

	go s.Listening(messages)
	go c.SendMessages(messages)

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
