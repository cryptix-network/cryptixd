package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/pkg/errors"
)

func (x *CryptixdMessage_Ready) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_Ready is nil")
	}
	return &appmessage.MsgReady{}, nil
}

func (x *CryptixdMessage_Ready) fromAppMessage(_ *appmessage.MsgReady) error {
	return nil
}
