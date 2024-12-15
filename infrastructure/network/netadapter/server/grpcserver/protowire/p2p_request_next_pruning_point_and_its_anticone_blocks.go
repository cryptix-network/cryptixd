package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/pkg/errors"
)

func (x *CryptixdMessage_RequestNextPruningPointAndItsAnticoneBlocks) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_DonePruningPointAndItsAnticoneBlocks is nil")
	}
	return &appmessage.MsgRequestNextPruningPointAndItsAnticoneBlocks{}, nil
}

func (x *CryptixdMessage_RequestNextPruningPointAndItsAnticoneBlocks) fromAppMessage(_ *appmessage.MsgRequestNextPruningPointAndItsAnticoneBlocks) error {
	return nil
}
