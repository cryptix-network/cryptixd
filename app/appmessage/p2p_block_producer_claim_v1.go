package appmessage

// MsgBlockProducerClaimV1 implements the claimant gossip payload.
type MsgBlockProducerClaimV1 struct {
	baseMessage

	SchemaVersion   uint32
	Network         uint32
	BlockHash       []byte
	NodePubkeyXOnly []byte
	Signature       []byte
}

// Command returns the protocol command string for the message.
func (msg *MsgBlockProducerClaimV1) Command() MessageCommand {
	return CmdBlockProducerClaimV1
}
