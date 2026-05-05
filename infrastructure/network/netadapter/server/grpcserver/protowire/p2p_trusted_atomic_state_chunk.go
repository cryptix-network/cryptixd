package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/pkg/errors"
)

func (x *CryptixdMessage_TrustedAtomicStateChunk) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_TrustedAtomicStateChunk is nil")
	}
	return &appmessage.MsgTrustedAtomicStateChunk{
		StateHash:   append([]byte(nil), x.TrustedAtomicStateChunk.StateHash...),
		ChunkIndex:  x.TrustedAtomicStateChunk.ChunkIndex,
		TotalChunks: x.TrustedAtomicStateChunk.TotalChunks,
		TotalBytes:  x.TrustedAtomicStateChunk.TotalBytes,
		Chunk:       append([]byte(nil), x.TrustedAtomicStateChunk.Chunk...),
	}, nil
}

func (x *CryptixdMessage_TrustedAtomicStateChunk) fromAppMessage(message *appmessage.MsgTrustedAtomicStateChunk) error {
	x.TrustedAtomicStateChunk = &TrustedAtomicStateChunkMessage{
		StateHash:   append([]byte(nil), message.StateHash...),
		ChunkIndex:  message.ChunkIndex,
		TotalChunks: message.TotalChunks,
		TotalBytes:  message.TotalBytes,
		Chunk:       append([]byte(nil), message.Chunk...),
	}
	return nil
}
