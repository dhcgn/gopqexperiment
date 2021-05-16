#!/bin/bash

SRC_DIR=/home/daniel/dev/gopqexperiment/cmd/simple_client_server/internal/shared/protos/
DST_DIR=/home/daniel/dev/gopqexperiment/cmd/simple_client_server/internal/shared/protos/
sudo protoc -I=$SRC_DIR --go_out=$DST_DIR $SRC_DIR/message.proto --plugin=/home/daniel/go/bin/protoc-gen-go