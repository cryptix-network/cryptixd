package appmessage

// MsgTrustedAtomicStateChunk represents a pruning-point Atomic consensus state chunk carried with trusted data.
type MsgTrustedAtomicStateChunk struct {
	baseMessage

	StateHash   []byte
	ChunkIndex  uint64
	TotalChunks uint64
	TotalBytes  uint64
	Chunk       []byte
}

// Command returns the protocol command string for the message
func (msg *MsgTrustedAtomicStateChunk) Command() MessageCommand {
	return CmdTrustedAtomicStateChunk
}

// NewMsgTrustedAtomicStateChunk returns a new MsgTrustedAtomicStateChunk.
func NewMsgTrustedAtomicStateChunk(stateHash []byte, chunkIndex, totalChunks, totalBytes uint64, chunk []byte) *MsgTrustedAtomicStateChunk {
	return &MsgTrustedAtomicStateChunk{
		StateHash:   append([]byte(nil), stateHash...),
		ChunkIndex:  chunkIndex,
		TotalChunks: totalChunks,
		TotalBytes:  totalBytes,
		Chunk:       append([]byte(nil), chunk...),
	}
}
