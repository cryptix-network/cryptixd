package appmessage

import (
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
)

// MsgFastMicroblock carries fast intent IDs that were included in a microblock.
type MsgFastMicroblock struct {
	baseMessage
	MicroblockTimeMs uint64
	IntentIDs        []*externalapi.DomainHash
}

// Command returns the protocol command string for the message.
func (msg *MsgFastMicroblock) Command() MessageCommand {
	return CmdFastMicroblock
}
