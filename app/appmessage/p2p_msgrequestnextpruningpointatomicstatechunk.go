package appmessage

// MsgRequestNextPruningPointAtomicStateChunk is used to request the next batch of pruning-point Atomic state chunks.
type MsgRequestNextPruningPointAtomicStateChunk struct {
	baseMessage
}

// Command returns the protocol command string for the message
func (msg *MsgRequestNextPruningPointAtomicStateChunk) Command() MessageCommand {
	return CmdRequestNextPruningPointAtomicStateChunk
}

// NewMsgRequestNextPruningPointAtomicStateChunk returns a new MsgRequestNextPruningPointAtomicStateChunk.
func NewMsgRequestNextPruningPointAtomicStateChunk() *MsgRequestNextPruningPointAtomicStateChunk {
	return &MsgRequestNextPruningPointAtomicStateChunk{}
}
