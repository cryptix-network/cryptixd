package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/pkg/errors"
)

func (x *CryptixdMessage_RequestAddresses) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_RequestAddresses is nil")
	}
	return x.RequestAddresses.toAppMessage()
}

func (x *RequestAddressesMessage) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "RequestAddressesMessage is nil")
	}
	subnetworkID, err := x.SubnetworkId.toDomain()
	//  Full cryptix nodes set SubnetworkId==nil
	if err != nil && !errors.Is(err, errorNil) {
		return nil, err
	}

	return &appmessage.MsgRequestAddresses{
		IncludeAllSubnetworks: x.IncludeAllSubnetworks,
		SubnetworkID:          subnetworkID,
	}, nil

}

func (x *CryptixdMessage_RequestAddresses) fromAppMessage(msgGetAddresses *appmessage.MsgRequestAddresses) error {
	x.RequestAddresses = &RequestAddressesMessage{
		IncludeAllSubnetworks: msgGetAddresses.IncludeAllSubnetworks,
		SubnetworkId:          domainSubnetworkIDToProto(msgGetAddresses.SubnetworkID),
	}
	return nil
}
