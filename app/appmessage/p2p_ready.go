package appmessage

// MsgReady implements the Message interface and represents a cryptix
// Ready message. It is used to notify that the peer is ready to receive
// messages.
type MsgReady struct {
	baseMessage
	// NodeAuthSignature is a 64-byte BIP340 Schnorr signature proving ownership
	// of the unified node identity for this specific handshake.
	NodeAuthSignature []byte
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (msg *MsgReady) Command() MessageCommand {
	return CmdReady
}

// NewMsgReady returns a new cryptix Ready message that conforms to the
// Message interface.
func NewMsgReady() *MsgReady {
	return &MsgReady{}
}
