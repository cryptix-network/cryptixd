package appmessage

import (
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
)

// MaxBlockLocatorsPerMsg is the maximum number of block locator hashes allowed
// per message.
const MaxBlockLocatorsPerMsg = 500

// MsgBlockLocator implements the Message interface and represents a cryptix
// locator message. It is used to find the blockLocator of a peer that is
// syncing with you.
type MsgBlockLocator struct {
	baseMessage
	BlockLocatorHashes []*externalapi.DomainHash
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (msg *MsgBlockLocator) Command() MessageCommand {
	return CmdBlockLocator
}

// NewMsgBlockLocator returns a new cryptix locator message that conforms to
// the Message interface. See MsgBlockLocator for details.
func NewMsgBlockLocator(locatorHashes []*externalapi.DomainHash) *MsgBlockLocator {
	return &MsgBlockLocator{
		BlockLocatorHashes: locatorHashes,
	}
}
