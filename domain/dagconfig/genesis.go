// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package dagconfig

import (
	"math/big"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/blockheader"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/transactionhelper"
	"github.com/cryptix-network/go-muhash"
)

var genesisTxOuts = []*externalapi.DomainTransactionOutput{}

var genesisTxPayload = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Blue score
	0x00, 0xE1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00, // Subsidy
	0x00, 0x00, //script version
	0x01,                                           // Varint
	0x00,                                           // OP-FALSE
	0xd7, 0x95, 0xd7, 0x9e, 0xd7, 0x94, 0x20, 0xd7, //

}

// genesisCoinbaseTx is the coinbase transaction for the genesis blocks for
// the main network.
var genesisCoinbaseTx = transactionhelper.NewSubnetworkTransaction(0, []*externalapi.DomainTransactionInput{}, genesisTxOuts,
	&subnetworks.SubnetworkIDCoinbase, 0, genesisTxPayload)

// genesisHash is the hash of the first block in the block DAG for the main
// network (genesis block).
var genesisHash = externalapi.NewDomainHashFromByteArray(&[externalapi.DomainHashSize]byte{
	0x46,
	0x66,
	0xac,
	0x06,
	0x8d,
	0x09,
	0x0f,
	0x3f,
	0x1c,
	0x2b,
	0x68,
	0x56,
	0xdf,
	0x0a,
	0x3f,
	0x9d,
	0x0e,
	0x84,
	0xe4,
	0xd0,
	0xc8,
	0x8a,
	0x8b,
	0x1e,
	0xe4,
	0x30,
	0xa4,
	0x48,
	0xfc,
	0x95,
	0x01,
	0xaa,
})

// genesisMerkleRoot is the hash of the first transaction in the genesis block
// for the main network.
var genesisMerkleRoot = externalapi.NewDomainHashFromByteArray(&[externalapi.DomainHashSize]byte{
	0xec,
	0xc4,
	0x29,
	0x28,
	0xf2,
	0xa8,
	0x87,
	0x02,
	0xf8,
	0x1f,
	0xe7,
	0x3e,
	0x9c,
	0x0a,
	0x00,
	0x6d,
	0xc0,
	0xa1,
	0x8c,
	0x41,
	0xd8,
	0x8a,
	0x81,
	0xe7,
	0x7f,
	0xf4,
	0x97,
	0x3d,
	0x5d,
	0xab,
	0x41,
	0xbc,
})

// genesisBlock defines the genesis block of the block DAG which serves as the
// public transaction ledger for the main network.
var genesisBlock = externalapi.DomainBlock{
	Header: blockheader.NewImmutableBlockHeader(
		0,
		[]externalapi.BlockLevelParents{},
		genesisMerkleRoot,
		&externalapi.DomainHash{},
		externalapi.NewDomainHashFromByteArray(muhash.EmptyMuHashHash.AsArray()),
		1747339735779,
		486962709,
		0x3392c,
		0, // Checkpoint DAA score
		0,
		big.NewInt(0),
		&externalapi.DomainHash{},
	),
	Transactions: []*externalapi.DomainTransaction{genesisCoinbaseTx},
}

var devnetGenesisTxOuts = []*externalapi.DomainTransactionOutput{}

var devnetGenesisTxPayload = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Blue score
	0x00, 0xE1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00, // Subsidy
	0x00, 0x00, // Script version
	0x01,                                                                   // Varint
	0x00,                                                                   // OP-FALSE
	0x6b, 0x61, 0x73, 0x70, 0x61, 0x2d, 0x64, 0x65, 0x76, 0x6e, 0x65, 0x74, // cryptix-devnet
}

// devnetGenesisCoinbaseTx is the coinbase transaction for the genesis blocks for
// the development network.
var devnetGenesisCoinbaseTx = transactionhelper.NewSubnetworkTransaction(0,
	[]*externalapi.DomainTransactionInput{}, devnetGenesisTxOuts,
	&subnetworks.SubnetworkIDCoinbase, 0, devnetGenesisTxPayload)

// devGenesisHash is the hash of the first block in the block DAG for the development
// network (genesis block).
var devnetGenesisHash = externalapi.NewDomainHashFromByteArray(&[externalapi.DomainHashSize]byte{
	0xb3, 0x13, 0x87, 0x0a, 0x32, 0xc7, 0x04, 0xbd, 0xf1, 0x21, 0x4a, 0x3b, 0x27, 0x0c, 0xc4, 0x75, 0xd9, 0x42, 0xc2, 0x09, 0x2d, 0x37, 0x9b, 0xc8, 0x70, 0x0a, 0xb0, 0x43, 0x31, 0x9e, 0xf8, 0x46,
})

// devnetGenesisMerkleRoot is the hash of the first transaction in the genesis block
// for the devopment network.
var devnetGenesisMerkleRoot = externalapi.NewDomainHashFromByteArray(&[externalapi.DomainHashSize]byte{
	0x58, 0xab, 0xf2, 0x03, 0x21, 0xd7, 0x07, 0x16,
	0x16, 0x2b, 0x6b, 0xf8, 0xd9, 0xf5, 0x89, 0xca,
	0x33, 0xae, 0x6e, 0x32, 0xb3, 0xb1, 0x9a, 0xbb,
	0x7f, 0xa6, 0x5d, 0x11, 0x41, 0xa3, 0xf9, 0x4d,
})

// devnetGenesisBlock defines the genesis block of the block DAG which serves as the
// public transaction ledger for the development network.
var devnetGenesisBlock = externalapi.DomainBlock{
	Header: blockheader.NewImmutableBlockHeader(
		0,
		[]externalapi.BlockLevelParents{},
		devnetGenesisMerkleRoot,
		&externalapi.DomainHash{},
		externalapi.NewDomainHashFromByteArray(muhash.EmptyMuHashHash.AsArray()),
		0x11e9db49828,
		525264379,
		0x48e5e,
		0,
		0,
		big.NewInt(0),
		&externalapi.DomainHash{},
	),
	Transactions: []*externalapi.DomainTransaction{devnetGenesisCoinbaseTx},
}

var simnetGenesisTxOuts = []*externalapi.DomainTransactionOutput{}

var simnetGenesisTxPayload = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Blue score
	0x00, 0xE1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00, // Subsidy
	0x00, 0x00, // Script version
	0x01,                                                                   // Varint
	0x00,                                                                   // OP-FALSE
	0x6b, 0x61, 0x73, 0x70, 0x61, 0x2d, 0x73, 0x69, 0x6d, 0x6e, 0x65, 0x74, // cryptix-simnet
}

// simnetGenesisCoinbaseTx is the coinbase transaction for the simnet genesis block.
var simnetGenesisCoinbaseTx = transactionhelper.NewSubnetworkTransaction(0,
	[]*externalapi.DomainTransactionInput{}, simnetGenesisTxOuts,
	&subnetworks.SubnetworkIDCoinbase, 0, simnetGenesisTxPayload)

// simnetGenesisHash is the hash of the first block in the block DAG for
// the simnet (genesis block).
var simnetGenesisHash = externalapi.NewDomainHashFromByteArray(&[externalapi.DomainHashSize]byte{
	0x41, 0x1f, 0x8c, 0xd2, 0x6f, 0x3d, 0x41, 0xae,
	0xa3, 0x9e, 0x78, 0x57, 0x39, 0x27, 0xda, 0x24,
	0xd2, 0x39, 0x95, 0x70, 0x5b, 0x57, 0x9f, 0x30,
	0x95, 0x9b, 0x91, 0x27, 0xe9, 0x6b, 0x79, 0xe3,
})

// simnetGenesisMerkleRoot is the hash of the first transaction in the genesis block
// for the devopment network.
var simnetGenesisMerkleRoot = externalapi.NewDomainHashFromByteArray(&[externalapi.DomainHashSize]byte{
	0x19, 0x46, 0xd6, 0x29, 0xf7, 0xe9, 0x22, 0xa7,
	0xbc, 0xed, 0x59, 0x19, 0x05, 0x21, 0xc3, 0x77,
	0x1f, 0x73, 0xd3, 0x52, 0xdd, 0xbb, 0xb6, 0x86,
	0x56, 0x4a, 0xd7, 0xfd, 0x56, 0x85, 0x7c, 0x1b,
})

// simnetGenesisBlock defines the genesis block of the block DAG which serves as the
// public transaction ledger for the development network.
var simnetGenesisBlock = externalapi.DomainBlock{
	Header: blockheader.NewImmutableBlockHeader(
		0,
		[]externalapi.BlockLevelParents{},
		simnetGenesisMerkleRoot,
		&externalapi.DomainHash{},
		externalapi.NewDomainHashFromByteArray(muhash.EmptyMuHashHash.AsArray()),
		0x17c5f62fbb6,
		0x207fffff,
		0x2,
		0,
		0,
		big.NewInt(0),
		&externalapi.DomainHash{},
	),
	Transactions: []*externalapi.DomainTransaction{simnetGenesisCoinbaseTx},
}

var testnetGenesisTxOuts = []*externalapi.DomainTransactionOutput{}

var testnetGenesisTxPayload = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Blue score
	0x00, 0xE1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00, // Subsidy
	0x00, 0x00, // Script version
	0x01,                                                                         // Varint
	0x00,                                                                         // OP-FALSE
	0x6b, 0x61, 0x73, 0x70, 0x61, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x6e, 0x65, 0x74, // cryptix-testnet
}

// testnetGenesisCoinbaseTx is the coinbase transaction for the testnet genesis block.
var testnetGenesisCoinbaseTx = transactionhelper.NewSubnetworkTransaction(0,
	[]*externalapi.DomainTransactionInput{}, testnetGenesisTxOuts,
	&subnetworks.SubnetworkIDCoinbase, 0, testnetGenesisTxPayload)

// testnetGenesisHash is the hash of the first block in the block DAG for the test
// network (genesis block).
var testnetGenesisHash = externalapi.NewDomainHashFromByteArray(&[externalapi.DomainHashSize]byte{
	0xf8, 0x96, 0xa3, 0x03, 0x48, 0x73, 0xbe, 0x17,
	0x39, 0xfc, 0x43, 0x59, 0x23, 0x68, 0x99, 0xfd,
	0x3d, 0x65, 0xd2, 0xbc, 0x94, 0xf9, 0x78, 0x0d,
	0xf0, 0xd0, 0xda, 0x3e, 0xb1, 0xcc, 0x43, 0x70,
})

// testnetGenesisMerkleRoot is the hash of the first transaction in the genesis block
// for testnet.
var testnetGenesisMerkleRoot = externalapi.NewDomainHashFromByteArray(&[externalapi.DomainHashSize]byte{
	0x17, 0x34, 0x14, 0x08, 0xa5, 0x72, 0x45, 0x56,
	0x50, 0x4d, 0xf4, 0xd6, 0xcf, 0x51, 0x5c, 0xbf,
	0xbb, 0x22, 0x04, 0x30, 0xdc, 0x45, 0x1c, 0x74,
	0x3c, 0x22, 0xd5, 0xe9, 0x11, 0x72, 0x0c, 0x2a,
})

// testnetGenesisBlock defines the genesis block of the block DAG which serves as the
// public transaction ledger for testnet.
var testnetGenesisBlock = externalapi.DomainBlock{
	Header: blockheader.NewImmutableBlockHeader(
		0,
		[]externalapi.BlockLevelParents{},
		testnetGenesisMerkleRoot,
		&externalapi.DomainHash{},
		externalapi.NewDomainHashFromByteArray(muhash.EmptyMuHashHash.AsArray()),
		0x17c5f62fbb6,
		0x1e7fffff,
		0x14582,
		0,
		0,
		big.NewInt(0),
		&externalapi.DomainHash{},
	),
	Transactions: []*externalapi.DomainTransaction{testnetGenesisCoinbaseTx},
}
