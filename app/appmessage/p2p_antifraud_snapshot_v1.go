package appmessage

// MsgAntiFraudSnapshotV1 carries the canonical signed anti-fraud snapshot.
type MsgAntiFraudSnapshotV1 struct {
	baseMessage
	SchemaVersion uint32
	Network       uint32
	SnapshotSeq   uint64
	GeneratedAtMs uint64
	SigningKeyID  uint32
	BannedIPs     [][]byte
	BannedNodeIDs [][]byte
	Signature     []byte
}

// Command returns the protocol command string for the message.
func (msg *MsgAntiFraudSnapshotV1) Command() MessageCommand {
	return CmdAntiFraudSnapshotV1
}
