package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/pkg/errors"
)

func (x *CryptixdMessage_RequestFastIntents) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_RequestFastIntents is nil")
	}
	return x.RequestFastIntents.toAppMessage()
}

func (x *RequestFastIntentsMessage) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "RequestFastIntentsMessage is nil")
	}
	intentIDs, err := protoHashesToDomain(x.IntentIds)
	if err != nil {
		return nil, err
	}
	return &appmessage.MsgRequestFastIntents{IntentIDs: intentIDs}, nil
}

func (x *CryptixdMessage_RequestFastIntents) fromAppMessage(message *appmessage.MsgRequestFastIntents) error {
	if message == nil {
		return errors.Wrapf(errorNil, "MsgRequestFastIntents is nil")
	}
	for i, intentID := range message.IntentIDs {
		if intentID == nil {
			return errors.Errorf("MsgRequestFastIntents.IntentIDs[%d] is nil", i)
		}
	}

	x.RequestFastIntents = &RequestFastIntentsMessage{
		IntentIds: domainHashesToProto(message.IntentIDs),
	}
	return nil
}
