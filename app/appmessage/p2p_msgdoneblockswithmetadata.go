package appmessage

// MsgDoneBlocksWithTrustedData implements the Message interface and represents a cryptix
// DoneBlocksWithTrustedData message
//
// This message has no payload.
type MsgDoneBlocksWithTrustedData struct {
	baseMessage
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (msg *MsgDoneBlocksWithTrustedData) Command() MessageCommand {
	return CmdDoneBlocksWithTrustedData
}

// NewMsgDoneBlocksWithTrustedData returns a new cryptix DoneBlocksWithTrustedData message that conforms to the
// Message interface.
func NewMsgDoneBlocksWithTrustedData() *MsgDoneBlocksWithTrustedData {
	return &MsgDoneBlocksWithTrustedData{}
}
