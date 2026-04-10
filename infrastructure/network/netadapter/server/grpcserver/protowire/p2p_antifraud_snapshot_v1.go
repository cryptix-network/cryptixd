package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/pkg/errors"
)

func (x *CryptixdMessage_AntiFraudSnapshotV1) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_AntiFraudSnapshotV1 is nil")
	}
	if x.AntiFraudSnapshotV1 == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_AntiFraudSnapshotV1.AntiFraudSnapshotV1 is nil")
	}

	msg := x.AntiFraudSnapshotV1
	bannedIPs := make([][]byte, 0, len(msg.BannedIps))
	for _, entry := range msg.BannedIps {
		copied := make([]byte, len(entry))
		copy(copied, entry)
		bannedIPs = append(bannedIPs, copied)
	}
	bannedNodeIDs := make([][]byte, 0, len(msg.BannedNodeIds))
	for _, entry := range msg.BannedNodeIds {
		copied := make([]byte, len(entry))
		copy(copied, entry)
		bannedNodeIDs = append(bannedNodeIDs, copied)
	}
	signature := make([]byte, len(msg.Signature))
	copy(signature, msg.Signature)

	return &appmessage.MsgAntiFraudSnapshotV1{
		SchemaVersion: msg.SchemaVersion,
		Network:       msg.Network,
		SnapshotSeq:   msg.SnapshotSeq,
		GeneratedAtMs: msg.GeneratedAtMs,
		SigningKeyID:  msg.SigningKeyId,
		BannedIPs:     bannedIPs,
		BannedNodeIDs: bannedNodeIDs,
		Signature:     signature,
	}, nil
}

func (x *CryptixdMessage_AntiFraudSnapshotV1) fromAppMessage(message *appmessage.MsgAntiFraudSnapshotV1) error {
	if message == nil {
		return errors.Wrapf(errorNil, "MsgAntiFraudSnapshotV1 is nil")
	}

	bannedIPs := make([][]byte, 0, len(message.BannedIPs))
	for _, entry := range message.BannedIPs {
		copied := make([]byte, len(entry))
		copy(copied, entry)
		bannedIPs = append(bannedIPs, copied)
	}
	bannedNodeIDs := make([][]byte, 0, len(message.BannedNodeIDs))
	for _, entry := range message.BannedNodeIDs {
		copied := make([]byte, len(entry))
		copy(copied, entry)
		bannedNodeIDs = append(bannedNodeIDs, copied)
	}
	signature := make([]byte, len(message.Signature))
	copy(signature, message.Signature)

	x.AntiFraudSnapshotV1 = &AntiFraudSnapshotV1Message{
		SchemaVersion: message.SchemaVersion,
		Network:       message.Network,
		SnapshotSeq:   message.SnapshotSeq,
		GeneratedAtMs: message.GeneratedAtMs,
		SigningKeyId:  message.SigningKeyID,
		BannedIps:     bannedIPs,
		BannedNodeIds: bannedNodeIDs,
		Signature:     signature,
	}
	return nil
}
