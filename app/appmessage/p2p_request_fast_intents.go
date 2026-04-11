package appmessage

import (
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
)

// MsgRequestFastIntents requests fast intents by their intent IDs.
type MsgRequestFastIntents struct {
	baseMessage
	IntentIDs []*externalapi.DomainHash
}

// Command returns the protocol command string for the message.
func (msg *MsgRequestFastIntents) Command() MessageCommand {
	return CmdRequestFastIntents
}

// NewMsgRequestFastIntents creates a new request for fast intents.
func NewMsgRequestFastIntents(intentIDs []*externalapi.DomainHash) *MsgRequestFastIntents {
	return &MsgRequestFastIntents{IntentIDs: intentIDs}
}
