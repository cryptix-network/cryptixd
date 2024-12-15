package main

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/server/grpcserver/protowire"
)

var commandTypes = []reflect.Type{
	reflect.TypeOf(protowire.CryptixdMessage_AddPeerRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_GetConnectedPeerInfoRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_GetPeerAddressesRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_GetCurrentNetworkRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_GetInfoRequest{}),

	reflect.TypeOf(protowire.CryptixdMessage_GetBlockRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_GetBlocksRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_GetHeadersRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_GetBlockCountRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_GetBlockDagInfoRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_GetSelectedTipHashRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_GetVirtualSelectedParentBlueScoreRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_GetVirtualSelectedParentChainFromBlockRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_ResolveFinalityConflictRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_EstimateNetworkHashesPerSecondRequest{}),

	reflect.TypeOf(protowire.CryptixdMessage_GetBlockTemplateRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_SubmitBlockRequest{}),

	reflect.TypeOf(protowire.CryptixdMessage_GetMempoolEntryRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_GetMempoolEntriesRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_GetMempoolEntriesByAddressesRequest{}),

	reflect.TypeOf(protowire.CryptixdMessage_SubmitTransactionRequest{}),

	reflect.TypeOf(protowire.CryptixdMessage_GetUtxosByAddressesRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_GetBalanceByAddressRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_GetCoinSupplyRequest{}),

	reflect.TypeOf(protowire.CryptixdMessage_BanRequest{}),
	reflect.TypeOf(protowire.CryptixdMessage_UnbanRequest{}),
}

type commandDescription struct {
	name       string
	parameters []*parameterDescription
	typeof     reflect.Type
}

type parameterDescription struct {
	name   string
	typeof reflect.Type
}

func commandDescriptions() []*commandDescription {
	commandDescriptions := make([]*commandDescription, len(commandTypes))

	for i, commandTypeWrapped := range commandTypes {
		commandType := unwrapCommandType(commandTypeWrapped)

		name := strings.TrimSuffix(commandType.Name(), "RequestMessage")
		numFields := commandType.NumField()

		var parameters []*parameterDescription
		for i := 0; i < numFields; i++ {
			field := commandType.Field(i)

			if !isFieldExported(field) {
				continue
			}

			parameters = append(parameters, &parameterDescription{
				name:   field.Name,
				typeof: field.Type,
			})
		}
		commandDescriptions[i] = &commandDescription{
			name:       name,
			parameters: parameters,
			typeof:     commandTypeWrapped,
		}
	}

	return commandDescriptions
}

func (cd *commandDescription) help() string {
	sb := &strings.Builder{}
	sb.WriteString(cd.name)
	for _, parameter := range cd.parameters {
		_, _ = fmt.Fprintf(sb, " [%s]", parameter.name)
	}
	return sb.String()
}
