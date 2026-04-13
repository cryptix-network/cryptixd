package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/pkg/errors"
)

func (x *CryptixdMessage_Ready) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_Ready is nil")
	}
	if x.Ready == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_Ready.Ready is nil")
	}
	return &appmessage.MsgReady{
		NodeAuthSignature:     append([]byte(nil), x.Ready.NodeAuthSignature...),
		PQMLKEM1024Ciphertext: append([]byte(nil), x.Ready.PqMlKem1024Ciphertext...),
		PQHandshakeProof:      append([]byte(nil), x.Ready.PqHandshakeProof...),
	}, nil
}

func (x *CryptixdMessage_Ready) fromAppMessage(message *appmessage.MsgReady) error {
	if message == nil {
		return errors.Wrapf(errorNil, "MsgReady is nil")
	}
	x.Ready = &ReadyMessage{
		NodeAuthSignature:     append([]byte(nil), message.NodeAuthSignature...),
		PqMlKem1024Ciphertext: append([]byte(nil), message.PQMLKEM1024Ciphertext...),
		PqHandshakeProof:      append([]byte(nil), message.PQHandshakeProof...),
	}
	return nil
}
