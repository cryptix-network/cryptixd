package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/pkg/errors"
)

func (x *CryptixdMessage_FastIntent) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_FastIntent is nil")
	}
	return x.FastIntent.toAppMessage()
}

func (x *FastIntentMessage) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "FastIntentMessage is nil")
	}
	if x.IntentId == nil {
		return nil, errors.Wrapf(errorNil, "FastIntentMessage.IntentId is nil")
	}
	if x.BaseTransaction == nil {
		return nil, errors.Wrapf(errorNil, "FastIntentMessage.BaseTransaction is nil")
	}

	intentID, err := x.IntentId.toDomain()
	if err != nil {
		return nil, err
	}

	baseTransactionMessage, err := x.BaseTransaction.toAppMessage()
	if err != nil {
		return nil, err
	}
	baseTransaction, ok := baseTransactionMessage.(*appmessage.MsgTx)
	if !ok {
		return nil, errors.Errorf("expected *appmessage.MsgTx for FastIntentMessage.BaseTransaction, got %T", baseTransactionMessage)
	}

	return &appmessage.MsgFastIntent{
		IntentID:          intentID,
		BaseTransaction:   baseTransaction,
		IntentNonce:       x.IntentNonce,
		ClientCreatedAtMs: x.ClientCreatedAtMs,
		MaxFee:            x.MaxFee,
	}, nil
}

func (x *CryptixdMessage_FastIntent) fromAppMessage(message *appmessage.MsgFastIntent) error {
	if message == nil {
		return errors.Wrapf(errorNil, "MsgFastIntent is nil")
	}
	if message.IntentID == nil {
		return errors.Wrapf(errorNil, "MsgFastIntent.IntentID is nil")
	}
	if message.BaseTransaction == nil {
		return errors.Wrapf(errorNil, "MsgFastIntent.BaseTransaction is nil")
	}

	protoBaseTransaction := new(TransactionMessage)
	protoBaseTransaction.fromAppMessage(message.BaseTransaction)

	x.FastIntent = &FastIntentMessage{
		IntentId:          domainHashToProto(message.IntentID),
		BaseTransaction:   protoBaseTransaction,
		IntentNonce:       message.IntentNonce,
		ClientCreatedAtMs: message.ClientCreatedAtMs,
		MaxFee:            message.MaxFee,
	}

	return nil
}
