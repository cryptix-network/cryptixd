package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/pkg/errors"
)

func (x *CryptixdMessage_RequestConsensusAtomicStateHash) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_RequestConsensusAtomicStateHash is nil")
	}
	blockHash, err := x.RequestConsensusAtomicStateHash.BlockHash.toDomain()
	if err != nil {
		return nil, err
	}
	return appmessage.NewMsgRequestConsensusAtomicStateHash(blockHash, x.RequestConsensusAtomicStateHash.AnchorDaaScore), nil
}

func (x *CryptixdMessage_RequestConsensusAtomicStateHash) fromAppMessage(message *appmessage.MsgRequestConsensusAtomicStateHash) error {
	x.RequestConsensusAtomicStateHash = &RequestConsensusAtomicStateHashMessage{
		BlockHash:      domainHashToProto(message.BlockHash),
		AnchorDaaScore: message.AnchorDAAScore,
	}
	return nil
}

func (x *CryptixdMessage_ConsensusAtomicStateHash) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_ConsensusAtomicStateHash is nil")
	}
	blockHash, err := x.ConsensusAtomicStateHash.BlockHash.toDomain()
	if err != nil {
		return nil, err
	}
	return appmessage.NewMsgConsensusAtomicStateHash(
		blockHash,
		x.ConsensusAtomicStateHash.StateHash,
		x.ConsensusAtomicStateHash.HasState,
		x.ConsensusAtomicStateHash.AnchorDaaScore,
	), nil
}

func (x *CryptixdMessage_ConsensusAtomicStateHash) fromAppMessage(message *appmessage.MsgConsensusAtomicStateHash) error {
	x.ConsensusAtomicStateHash = &ConsensusAtomicStateHashMessage{
		BlockHash:      domainHashToProto(message.BlockHash),
		StateHash:      append([]byte(nil), message.StateHash...),
		HasState:       message.HasState,
		AnchorDaaScore: message.AnchorDAAScore,
	}
	return nil
}

func (x *CryptixdMessage_RequestAtomicTokenStateHash) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_RequestAtomicTokenStateHash is nil")
	}
	blockHash, err := x.RequestAtomicTokenStateHash.BlockHash.toDomain()
	if err != nil {
		return nil, err
	}
	return appmessage.NewMsgRequestAtomicTokenStateHash(blockHash, x.RequestAtomicTokenStateHash.AnchorDaaScore), nil
}

func (x *CryptixdMessage_RequestAtomicTokenStateHash) fromAppMessage(message *appmessage.MsgRequestAtomicTokenStateHash) error {
	x.RequestAtomicTokenStateHash = &RequestAtomicTokenStateHashMessage{
		BlockHash:      domainHashToProto(message.BlockHash),
		AnchorDaaScore: message.AnchorDAAScore,
	}
	return nil
}

func (x *CryptixdMessage_AtomicTokenStateHash) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_AtomicTokenStateHash is nil")
	}
	blockHash, err := x.AtomicTokenStateHash.BlockHash.toDomain()
	if err != nil {
		return nil, err
	}
	return appmessage.NewMsgAtomicTokenStateHash(
		blockHash,
		x.AtomicTokenStateHash.StateHash,
		x.AtomicTokenStateHash.HasState,
		x.AtomicTokenStateHash.AnchorDaaScore,
	), nil
}

func (x *CryptixdMessage_AtomicTokenStateHash) fromAppMessage(message *appmessage.MsgAtomicTokenStateHash) error {
	x.AtomicTokenStateHash = &AtomicTokenStateHashMessage{
		BlockHash:      domainHashToProto(message.BlockHash),
		StateHash:      append([]byte(nil), message.StateHash...),
		HasState:       message.HasState,
		AnchorDaaScore: message.AnchorDAAScore,
	}
	return nil
}
