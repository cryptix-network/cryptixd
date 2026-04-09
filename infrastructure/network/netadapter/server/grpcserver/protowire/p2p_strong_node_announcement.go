package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/pkg/errors"
)

func (x *CryptixdMessage_StrongNodeAnnouncement) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_StrongNodeAnnouncement is nil")
	}
	if x.StrongNodeAnnouncement == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_StrongNodeAnnouncement.StrongNodeAnnouncement is nil")
	}

	msg := x.StrongNodeAnnouncement
	return &appmessage.MsgStrongNodeAnnouncement{
		SchemaVersion:  msg.SchemaVersion,
		Network:        msg.Network,
		StaticIDRaw:    append([]byte(nil), msg.StaticIdRaw...),
		PubKeyXOnly:    append([]byte(nil), msg.PubkeyXonly...),
		SeqNo:          msg.SeqNo,
		WindowStartMs:  msg.WindowStartMs,
		WindowEndMs:    msg.WindowEndMs,
		FoundBlocks10m: msg.FoundBlocks10M,
		TotalBlocks10m: msg.TotalBlocks10M,
		SentAtMs:       msg.SentAtMs,
		ClaimedIP:      append([]byte(nil), msg.ClaimedIp...),
		Signature:      append([]byte(nil), msg.Signature...),
	}, nil
}

func (x *CryptixdMessage_StrongNodeAnnouncement) fromAppMessage(message *appmessage.MsgStrongNodeAnnouncement) error {
	if message == nil {
		return errors.Wrapf(errorNil, "MsgStrongNodeAnnouncement is nil")
	}

	x.StrongNodeAnnouncement = &StrongNodeAnnouncementMessage{
		SchemaVersion:  message.SchemaVersion,
		Network:        message.Network,
		StaticIdRaw:    append([]byte(nil), message.StaticIDRaw...),
		PubkeyXonly:    append([]byte(nil), message.PubKeyXOnly...),
		SeqNo:          message.SeqNo,
		WindowStartMs:  message.WindowStartMs,
		WindowEndMs:    message.WindowEndMs,
		FoundBlocks10M: message.FoundBlocks10m,
		TotalBlocks10M: message.TotalBlocks10m,
		SentAtMs:       message.SentAtMs,
		ClaimedIp:      append([]byte(nil), message.ClaimedIP...),
		Signature:      append([]byte(nil), message.Signature...),
	}
	return nil
}
