package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/pkg/errors"
)

func (x *CryptixdMessage_RequestAntiFraudSnapshotV1) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_RequestAntiFraudSnapshotV1 is nil")
	}
	return &appmessage.MsgRequestAntiFraudSnapshotV1{}, nil
}

func (x *CryptixdMessage_RequestAntiFraudSnapshotV1) fromAppMessage(_ *appmessage.MsgRequestAntiFraudSnapshotV1) error {
	x.RequestAntiFraudSnapshotV1 = &RequestAntiFraudSnapshotV1Message{}
	return nil
}
