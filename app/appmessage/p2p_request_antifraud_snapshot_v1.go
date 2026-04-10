package appmessage

// MsgRequestAntiFraudSnapshotV1 requests the latest anti-fraud snapshot from a peer.
// This message has no payload.
type MsgRequestAntiFraudSnapshotV1 struct {
	baseMessage
}

// Command returns the protocol command string for the message.
func (msg *MsgRequestAntiFraudSnapshotV1) Command() MessageCommand {
	return CmdRequestAntiFraudSnapshotV1
}

// NewMsgRequestAntiFraudSnapshotV1 creates a new anti-fraud snapshot request message.
func NewMsgRequestAntiFraudSnapshotV1() *MsgRequestAntiFraudSnapshotV1 {
	return &MsgRequestAntiFraudSnapshotV1{}
}
