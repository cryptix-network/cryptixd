package blockrelay

import (
	"errors"
	"testing"

	"github.com/cryptix-network/cryptixd/app/protocol/protocolerrors"
	"github.com/cryptix-network/cryptixd/domain"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
)

type samePruningPointTestConsensus struct {
	externalapi.Consensus
	pruningPoint *externalapi.DomainHash
}

func (c *samePruningPointTestConsensus) PruningPoint() (*externalapi.DomainHash, error) {
	return c.pruningPoint, nil
}

type samePruningPointTestDomain struct {
	domain.Domain
	consensus externalapi.Consensus
}

func (d *samePruningPointTestDomain) Consensus() externalapi.Consensus {
	return d.consensus
}

type samePruningPointTestContext struct {
	IBDContext
	domain domain.Domain
}

func (c *samePruningPointTestContext) Domain() domain.Domain {
	return c.domain
}

func TestValidateAndInsertPruningPointsTreatsCurrentPruningPointAsResume(t *testing.T) {
	pruningPoint := externalapi.NewZeroHash()
	flow := &handleIBDFlow{
		IBDContext: &samePruningPointTestContext{
			domain: &samePruningPointTestDomain{
				consensus: &samePruningPointTestConsensus{pruningPoint: pruningPoint},
			},
		},
	}

	err := flow.validateAndInsertPruningPoints(pruningPoint)
	if !errors.Is(err, errIBDPruningPointAlreadyCurrent) {
		t.Fatalf("expected current pruning point resume error, got %+v", err)
	}

	var protocolErr protocolerrors.ProtocolError
	if errors.As(err, &protocolErr) {
		t.Fatalf("current pruning point resume must not be treated as a peer protocol error")
	}
}
