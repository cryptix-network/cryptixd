package appmessage

import "github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"

type MsgRequestConsensusAtomicStateHash struct {
	baseMessage

	BlockHash      *externalapi.DomainHash
	AnchorDAAScore uint64
}

func (msg *MsgRequestConsensusAtomicStateHash) Command() MessageCommand {
	return CmdRequestConsensusAtomicStateHash
}

func NewMsgRequestConsensusAtomicStateHash(blockHash *externalapi.DomainHash, anchorDAAScore uint64) *MsgRequestConsensusAtomicStateHash {
	return &MsgRequestConsensusAtomicStateHash{BlockHash: blockHash, AnchorDAAScore: anchorDAAScore}
}

type MsgConsensusAtomicStateHash struct {
	baseMessage

	BlockHash      *externalapi.DomainHash
	StateHash      []byte
	HasState       bool
	AnchorDAAScore uint64
}

func (msg *MsgConsensusAtomicStateHash) Command() MessageCommand {
	return CmdConsensusAtomicStateHash
}

func NewMsgConsensusAtomicStateHash(blockHash *externalapi.DomainHash, stateHash []byte, hasState bool, anchorDAAScore uint64) *MsgConsensusAtomicStateHash {
	return &MsgConsensusAtomicStateHash{
		BlockHash:      blockHash,
		StateHash:      append([]byte(nil), stateHash...),
		HasState:       hasState,
		AnchorDAAScore: anchorDAAScore,
	}
}

type MsgRequestAtomicTokenStateHash struct {
	baseMessage

	BlockHash      *externalapi.DomainHash
	AnchorDAAScore uint64
}

func (msg *MsgRequestAtomicTokenStateHash) Command() MessageCommand {
	return CmdRequestAtomicTokenStateHash
}

func NewMsgRequestAtomicTokenStateHash(blockHash *externalapi.DomainHash, anchorDAAScore uint64) *MsgRequestAtomicTokenStateHash {
	return &MsgRequestAtomicTokenStateHash{BlockHash: blockHash, AnchorDAAScore: anchorDAAScore}
}

type MsgAtomicTokenStateHash struct {
	baseMessage

	BlockHash      *externalapi.DomainHash
	StateHash      []byte
	HasState       bool
	AnchorDAAScore uint64
}

func (msg *MsgAtomicTokenStateHash) Command() MessageCommand {
	return CmdAtomicTokenStateHash
}

func NewMsgAtomicTokenStateHash(blockHash *externalapi.DomainHash, stateHash []byte, hasState bool, anchorDAAScore uint64) *MsgAtomicTokenStateHash {
	return &MsgAtomicTokenStateHash{
		BlockHash:      blockHash,
		StateHash:      append([]byte(nil), stateHash...),
		HasState:       hasState,
		AnchorDAAScore: anchorDAAScore,
	}
}
