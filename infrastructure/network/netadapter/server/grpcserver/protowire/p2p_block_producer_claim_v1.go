package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/pkg/errors"
)

func (x *CryptixdMessage_BlockProducerClaimV1) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_BlockProducerClaimV1 is nil")
	}
	if x.BlockProducerClaimV1 == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_BlockProducerClaimV1.BlockProducerClaimV1 is nil")
	}

	msg := x.BlockProducerClaimV1
	return &appmessage.MsgBlockProducerClaimV1{
		SchemaVersion:   msg.SchemaVersion,
		Network:         msg.Network,
		BlockHash:       append([]byte(nil), msg.BlockHash...),
		NodePubkeyXOnly: append([]byte(nil), msg.NodePubkeyXonly...),
		Signature:       append([]byte(nil), msg.Signature...),
	}, nil
}

func (x *CryptixdMessage_BlockProducerClaimV1) fromAppMessage(message *appmessage.MsgBlockProducerClaimV1) error {
	if message == nil {
		return errors.Wrapf(errorNil, "MsgBlockProducerClaimV1 is nil")
	}

	x.BlockProducerClaimV1 = &BlockProducerClaimV1Message{
		SchemaVersion:   message.SchemaVersion,
		Network:         message.Network,
		BlockHash:       append([]byte(nil), message.BlockHash...),
		NodePubkeyXonly: append([]byte(nil), message.NodePubkeyXOnly...),
		Signature:       append([]byte(nil), message.Signature...),
	}
	return nil
}
