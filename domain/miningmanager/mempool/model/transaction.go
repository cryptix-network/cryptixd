package model

import "github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"

// Transaction represents a generic transaction either in the mempool's main TransactionPool or OrphanPool
type Transaction interface {
	TransactionID() *externalapi.DomainTransactionID
	Transaction() *externalapi.DomainTransaction
}
