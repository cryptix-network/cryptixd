package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/pkg/errors"
)

func (x *CryptixdMessage_FastMicroblock) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_FastMicroblock is nil")
	}
	return x.FastMicroblock.toAppMessage()
}

func (x *FastMicroblockMessage) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "FastMicroblockMessage is nil")
	}
	intentIDs, err := protoHashesToDomain(x.IntentIds)
	if err != nil {
		return nil, err
	}
	return &appmessage.MsgFastMicroblock{
		MicroblockTimeMs: x.MicroblockTimeMs,
		IntentIDs:        intentIDs,
	}, nil
}

func (x *CryptixdMessage_FastMicroblock) fromAppMessage(message *appmessage.MsgFastMicroblock) error {
	if message == nil {
		return errors.Wrapf(errorNil, "MsgFastMicroblock is nil")
	}
	for i, intentID := range message.IntentIDs {
		if intentID == nil {
			return errors.Errorf("MsgFastMicroblock.IntentIDs[%d] is nil", i)
		}
	}

	x.FastMicroblock = &FastMicroblockMessage{
		MicroblockTimeMs: message.MicroblockTimeMs,
		IntentIds:        domainHashesToProto(message.IntentIDs),
	}
	return nil
}
