package server

import (
	"context"

	"github.com/cryptix-network/cryptixd/cmd/cryptixwallet/daemon/pb"
	"github.com/cryptix-network/cryptixd/version"
)

func (s *server) GetVersion(_ context.Context, _ *pb.GetVersionRequest) (*pb.GetVersionResponse, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return &pb.GetVersionResponse{
		Version: version.Version(),
	}, nil
}
