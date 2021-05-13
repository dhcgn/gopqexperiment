package shared

type Message struct {
	Protobuf []byte
	Respond  chan<- []byte
}
