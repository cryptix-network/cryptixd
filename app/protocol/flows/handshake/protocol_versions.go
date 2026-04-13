package handshake

import "github.com/pkg/errors"

const (
	legacyProtocolVersion   = uint32(5)
	hardforkProtocolVersion = uint32(8)
)

func minAcceptableProtocolVersionFor(context HandleHandshakeContext) (uint32, error) {
	virtualDAAScore, err := context.Domain().Consensus().GetVirtualDAAScore()
	if err != nil {
		return 0, errors.Wrap(err, "failed to get virtual DAA score for protocol version gate")
	}

	if virtualDAAScore >= context.Config().NetParams().PayloadHfActivationDAAScore {
		return hardforkProtocolVersion, nil
	}

	return legacyProtocolVersion, nil
}

func maxAcceptableProtocolVersion() uint32 {
	return hardforkProtocolVersion
}
