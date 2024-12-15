package client

import (
	"context"
	"time"

	"github.com/cryptix-network/cryptixd/cmd/cryptixwallet/daemon/server"

	"github.com/pkg/errors"

	"github.com/cryptix-network/cryptixd/cmd/cryptixwallet/daemon/pb"
	"google.golang.org/grpc"
)

// Connect connects to the cryptixwalletd server, and returns the client instance
func Connect(address string) (pb.CryptixwalletdClient, func(), error) {
	// Connection is local, so 1 second timeout is sufficient
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, address, grpc.WithInsecure(), grpc.WithBlock(), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(server.MaxDaemonSendMsgSize)))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, nil, errors.New("cryptixwallet daemon is not running, start it with `cryptixwallet start-daemon`")
		}
		return nil, nil, err
	}

	return pb.NewCryptixwalletdClient(conn), func() {
		conn.Close()
	}, nil
}
