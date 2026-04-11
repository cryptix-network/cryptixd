package appmessage

import (
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
)

// MsgFastIntent carries a fast intent and its base transaction.
type MsgFastIntent struct {
	baseMessage
	IntentID          *externalapi.DomainHash
	BaseTransaction   *MsgTx
	IntentNonce       uint64
	ClientCreatedAtMs uint64
	MaxFee            uint64
}

// Command returns the protocol command string for the message.
func (msg *MsgFastIntent) Command() MessageCommand {
	return CmdFastIntent
}
