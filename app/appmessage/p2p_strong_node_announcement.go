package appmessage

// MsgStrongNodeAnnouncement implements the Message interface and carries
// strong-node announcement metadata emitted by peers.
type MsgStrongNodeAnnouncement struct {
	baseMessage

	SchemaVersion  uint32
	Network        string
	StaticIDRaw    []byte
	PubKeyXOnly    []byte
	SeqNo          uint64
	WindowStartMs  uint64
	WindowEndMs    uint64
	FoundBlocks10m uint32
	TotalBlocks10m uint32
	SentAtMs       uint64
	ClaimedIP      []byte
	Signature      []byte
}

// Command returns the protocol command string for the message.
func (msg *MsgStrongNodeAnnouncement) Command() MessageCommand {
	return CmdStrongNodeAnnouncement
}
