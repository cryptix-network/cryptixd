package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/pkg/errors"
)

func (x *CryptixdMessage_GetVirtualSelectedParentChainFromBlockRequest) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_GetVirtualSelectedParentChainFromBlockRequest is nil")
	}
	return x.GetVirtualSelectedParentChainFromBlockRequest.toAppMessage()
}

func (x *CryptixdMessage_GetVirtualSelectedParentChainFromBlockRequest) fromAppMessage(message *appmessage.GetVirtualSelectedParentChainFromBlockRequestMessage) error {
	x.GetVirtualSelectedParentChainFromBlockRequest = &GetVirtualSelectedParentChainFromBlockRequestMessage{
		StartHash:                     message.StartHash,
		IncludeAcceptedTransactionIds: message.IncludeAcceptedTransactionIDs,
	}
	return nil
}

func (x *GetVirtualSelectedParentChainFromBlockRequestMessage) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "GetVirtualSelectedParentChainFromBlockRequestMessage is nil")
	}
	return &appmessage.GetVirtualSelectedParentChainFromBlockRequestMessage{
		StartHash:                     x.StartHash,
		IncludeAcceptedTransactionIDs: x.IncludeAcceptedTransactionIds,
	}, nil
}

func (x *CryptixdMessage_GetVirtualSelectedParentChainFromBlockResponse) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_GetVirtualSelectedParentChainFromBlockResponse is nil")
	}
	return x.GetVirtualSelectedParentChainFromBlockResponse.toAppMessage()
}

func (x *CryptixdMessage_GetVirtualSelectedParentChainFromBlockResponse) fromAppMessage(message *appmessage.GetVirtualSelectedParentChainFromBlockResponseMessage) error {
	var err *RPCError
	if message.Error != nil {
		err = &RPCError{Message: message.Error.Message}
	}
	x.GetVirtualSelectedParentChainFromBlockResponse = &GetVirtualSelectedParentChainFromBlockResponseMessage{
		RemovedChainBlockHashes: message.RemovedChainBlockHashes,
		AddedChainBlockHashes:   message.AddedChainBlockHashes,
		AcceptedTransactionIds:  make([]*AcceptedTransactionIds, len(message.AcceptedTransactionIDs)),
		Error:                   err,
	}
	for i, acceptedTransactionIDs := range message.AcceptedTransactionIDs {
		x.GetVirtualSelectedParentChainFromBlockResponse.AcceptedTransactionIds[i] = &AcceptedTransactionIds{}
		x.GetVirtualSelectedParentChainFromBlockResponse.AcceptedTransactionIds[i].fromAppMessage(acceptedTransactionIDs)
	}
	return nil
}

func (x *GetVirtualSelectedParentChainFromBlockResponseMessage) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "GetVirtualSelectedParentChainFromBlockResponseMessage is nil")
	}
	rpcErr, err := x.Error.toAppMessage()
	// Error is an optional field
	if err != nil && !errors.Is(err, errorNil) {
		return nil, err
	}

	if rpcErr != nil && (len(x.AddedChainBlockHashes) != 0 || len(x.RemovedChainBlockHashes) != 0) {
		return nil, errors.New("GetVirtualSelectedParentChainFromBlockResponseMessage contains both an error and a response")
	}

	message := &appmessage.GetVirtualSelectedParentChainFromBlockResponseMessage{
		RemovedChainBlockHashes: x.RemovedChainBlockHashes,
		AddedChainBlockHashes:   x.AddedChainBlockHashes,
		AcceptedTransactionIDs:  make([]*appmessage.AcceptedTransactionIDs, len(x.AcceptedTransactionIds)),
		Error:                   rpcErr,
	}

	for i, acceptedTransactionIds := range x.AcceptedTransactionIds {
		message.AcceptedTransactionIDs[i] = acceptedTransactionIds.toAppMessage()
	}

	return message, nil
}

func (x *AcceptedTransactionIds) fromAppMessage(acceptedTransactionIDs *appmessage.AcceptedTransactionIDs) {
	x.AcceptingBlockHash = acceptedTransactionIDs.AcceptingBlockHash
	x.AcceptedTransactionIds = acceptedTransactionIDs.AcceptedTransactionIDs
}

func (x *AcceptedTransactionIds) toAppMessage() *appmessage.AcceptedTransactionIDs {
	return &appmessage.AcceptedTransactionIDs{
		AcceptingBlockHash:     x.AcceptingBlockHash,
		AcceptedTransactionIDs: x.AcceptedTransactionIds,
	}
}
