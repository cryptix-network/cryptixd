package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/id"
	"github.com/cryptix-network/cryptixd/util/mstime"
	"github.com/pkg/errors"
)

const pqMLKEM1024PublicKeySize = 1568

func (x *CryptixdMessage_Version) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_Version is nil")
	}
	return x.Version.toAppMessage()
}

func (x *VersionMessage) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "VersionMessage is nil")
	}
	address, err := x.Address.toAppMessage()
	// Address is optional for non-listening nodes
	if err != nil && !errors.Is(err, errorNil) {
		return nil, err
	}

	subnetworkID, err := x.SubnetworkId.toDomain()
	//  Full cryptix nodes set SubnetworkId==nil
	if err != nil && !errors.Is(err, errorNil) {
		return nil, err
	}

	err = appmessage.ValidateUserAgent(x.UserAgent)
	if err != nil {
		return nil, err
	}

	if x.Id == nil {
		return nil, errors.Wrapf(errorNil, "VersionMessage.Id is nil")
	}

	appMsgID, err := id.FromBytes(x.Id)
	if err != nil {
		return nil, err
	}

	if len(x.AntiFraudHashes) > 3 {
		return nil, errors.Errorf("VersionMessage.AntiFraudHashes count %d exceeds max 3", len(x.AntiFraudHashes))
	}
	antiFraudHashes := make([][32]byte, 0, len(x.AntiFraudHashes))
	for _, raw := range x.AntiFraudHashes {
		if len(raw) != 32 {
			return nil, errors.Errorf("VersionMessage.AntiFraudHashes entry length %d is invalid (expected 32)", len(raw))
		}
		var hash [32]byte
		copy(hash[:], raw)
		antiFraudHashes = append(antiFraudHashes, hash)
	}

	var nodePubkeyXOnly []byte
	if len(x.NodePubkeyXonly) > 0 {
		if len(x.NodePubkeyXonly) != 32 {
			return nil, errors.Errorf("VersionMessage.NodePubkeyXonly length %d is invalid (expected 32)", len(x.NodePubkeyXonly))
		}
		nodePubkeyXOnly = make([]byte, 32)
		copy(nodePubkeyXOnly, x.NodePubkeyXonly)
	}

	var nodePowNonce *uint64
	if x.NodePowNonce != nil {
		value := *x.NodePowNonce
		nodePowNonce = &value
	}
	var nodeChallengeNonce *uint64
	if x.NodeChallengeNonce != nil {
		value := *x.NodeChallengeNonce
		nodeChallengeNonce = &value
	}
	var pqMLKEM1024PubKey []byte
	if len(x.PqMlKem1024Pubkey) > 0 {
		if len(x.PqMlKem1024Pubkey) != pqMLKEM1024PublicKeySize {
			return nil, errors.Errorf("VersionMessage.PqMlKem1024Pubkey length %d is invalid (expected %d)", len(x.PqMlKem1024Pubkey), pqMLKEM1024PublicKeySize)
		}
		pqMLKEM1024PubKey = append([]byte(nil), x.PqMlKem1024Pubkey...)
	}

	return &appmessage.MsgVersion{
		ProtocolVersion:    x.ProtocolVersion,
		Network:            x.Network,
		Services:           appmessage.ServiceFlag(x.Services),
		Timestamp:          mstime.UnixMilliseconds(x.Timestamp),
		Address:            address,
		ID:                 appMsgID,
		UserAgent:          x.UserAgent,
		DisableRelayTx:     x.DisableRelayTx,
		SubnetworkID:       subnetworkID,
		AntiFraudHashes:    antiFraudHashes,
		NodePubkeyXOnly:    nodePubkeyXOnly,
		NodePowNonce:       nodePowNonce,
		NodeChallengeNonce: nodeChallengeNonce,
		PQMLKEM1024PubKey:  pqMLKEM1024PubKey,
	}, nil
}

func (x *CryptixdMessage_Version) fromAppMessage(msgVersion *appmessage.MsgVersion) error {
	err := appmessage.ValidateUserAgent(msgVersion.UserAgent)
	if err != nil {
		return err
	}

	versionID, err := msgVersion.ID.SerializeToBytes()
	if err != nil {
		return err
	}

	// Address is optional for non-listening nodes
	var address *NetAddress
	if msgVersion.Address != nil {
		address = appMessageNetAddressToProto(msgVersion.Address)
	}

	if len(msgVersion.AntiFraudHashes) > 3 {
		return errors.Errorf("MsgVersion.AntiFraudHashes count %d exceeds max 3", len(msgVersion.AntiFraudHashes))
	}
	antiFraudHashes := make([][]byte, 0, len(msgVersion.AntiFraudHashes))
	for _, hash := range msgVersion.AntiFraudHashes {
		entry := make([]byte, 32)
		copy(entry, hash[:])
		antiFraudHashes = append(antiFraudHashes, entry)
	}
	if len(msgVersion.NodePubkeyXOnly) != 0 && len(msgVersion.NodePubkeyXOnly) != 32 {
		return errors.Errorf("MsgVersion.NodePubkeyXOnly length %d is invalid (expected 32)", len(msgVersion.NodePubkeyXOnly))
	}
	nodePubkeyXOnly := append([]byte(nil), msgVersion.NodePubkeyXOnly...)
	var nodePowNonce *uint64
	if msgVersion.NodePowNonce != nil {
		value := *msgVersion.NodePowNonce
		nodePowNonce = &value
	}
	var nodeChallengeNonce *uint64
	if msgVersion.NodeChallengeNonce != nil {
		value := *msgVersion.NodeChallengeNonce
		nodeChallengeNonce = &value
	}
	if len(msgVersion.PQMLKEM1024PubKey) != 0 && len(msgVersion.PQMLKEM1024PubKey) != pqMLKEM1024PublicKeySize {
		return errors.Errorf(
			"MsgVersion.PQMLKEM1024PubKey length %d is invalid (expected %d)",
			len(msgVersion.PQMLKEM1024PubKey),
			pqMLKEM1024PublicKeySize,
		)
	}
	pqMLKEM1024PubKey := append([]byte(nil), msgVersion.PQMLKEM1024PubKey...)

	x.Version = &VersionMessage{
		ProtocolVersion:    msgVersion.ProtocolVersion,
		Network:            msgVersion.Network,
		Services:           uint64(msgVersion.Services),
		Timestamp:          msgVersion.Timestamp.UnixMilliseconds(),
		Address:            address,
		Id:                 versionID,
		UserAgent:          msgVersion.UserAgent,
		DisableRelayTx:     msgVersion.DisableRelayTx,
		SubnetworkId:       domainSubnetworkIDToProto(msgVersion.SubnetworkID),
		AntiFraudHashes:    antiFraudHashes,
		NodePubkeyXonly:    nodePubkeyXOnly,
		NodePowNonce:       nodePowNonce,
		NodeChallengeNonce: nodeChallengeNonce,
		PqMlKem1024Pubkey:  pqMLKEM1024PubKey,
	}
	return nil
}
