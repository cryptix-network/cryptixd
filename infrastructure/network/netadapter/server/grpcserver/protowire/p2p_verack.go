package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/pkg/errors"
)

func (x *CryptixdMessage_Verack) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_Verack is nil")
	}
	return &appmessage.MsgVerAck{}, nil
}

func (x *CryptixdMessage_Verack) fromAppMessage(_ *appmessage.MsgVerAck) error {
	return nil
}
