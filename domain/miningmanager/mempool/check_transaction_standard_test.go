// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mempool

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensusreference"

	"github.com/cryptix-network/cryptixd/domain/consensus/utils/testutils"

	"github.com/cryptix-network/cryptixd/domain/consensus"

	"github.com/cryptix-network/cryptixd/domain/consensus/utils/constants"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/txscript"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/utxo"
	"github.com/cryptix-network/cryptixd/util"
	"github.com/pkg/errors"
)

func TestCalcMinRequiredTxRelayFee(t *testing.T) {
	tests := []struct {
		name                       string      // test description.
		size                       uint64      // Transaction size in bytes.
		minimumRelayTransactionFee util.Amount // minimum relay transaction fee.
		want                       uint64      // Expected fee.
	}{
		{
			// Ensure combination of size and fee that are less than 1000
			// produce a non-zero fee.
			"250 bytes with relay fee of 3",
			250,
			3,
			3,
		},
		{
			"100 bytes with default minimum relay fee",
			100,
			defaultMinimumRelayTransactionFee,
			100,
		},
		{
			"max standard tx size with default minimum relay fee",
			MaximumStandardTransactionMass,
			defaultMinimumRelayTransactionFee,
			100000,
		},
		{
			"1500 bytes with 5000 relay fee",
			1500,
			5000,
			7500,
		},
		{
			"1500 bytes with 3000 relay fee",
			1500,
			3000,
			4500,
		},
		{
			"782 bytes with 5000 relay fee",
			782,
			5000,
			3910,
		},
		{
			"782 bytes with 3000 relay fee",
			782,
			3000,
			2346,
		},
		{
			"782 bytes with 2550 relay fee",
			782,
			2550,
			1994,
		},
	}

	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		factory := consensus.NewFactory()
		tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestCalcMinRequiredTxRelayFee")
		if err != nil {
			t.Fatalf("Error setting up consensus: %+v", err)
		}
		defer teardown(false)

		for _, test := range tests {
			mempoolConfig := DefaultConfig(tc.DAGParams())
			mempoolConfig.MinimumRelayTransactionFee = test.minimumRelayTransactionFee
			tcAsConsensus := tc.(externalapi.Consensus)
			tcAsConsensusPointer := &tcAsConsensus
			mempool := New(mempoolConfig, consensusreference.NewConsensusReference(&tcAsConsensusPointer)).(*mempool)

			got := mempool.minimumRequiredTransactionRelayFee(test.size)
			if got != test.want {
				t.Errorf("TestCalcMinRequiredTxRelayFee test '%s' "+
					"failed: got %v want %v", test.name, got,
					test.want)
			}
		}
	})
}

func TestIsTransactionOutputDust(t *testing.T) {
	scriptPublicKey := &externalapi.ScriptPublicKey{
		[]byte{0x76, 0xa9, 0x21, 0x03, 0x2f, 0x7e, 0x43,
			0x0a, 0xa4, 0xc9, 0xd1, 0x59, 0x43, 0x7e, 0x84, 0xb9,
			0x75, 0xdc, 0x76, 0xd9, 0x00, 0x3b, 0xf0, 0x92, 0x2c,
			0xf3, 0xaa, 0x45, 0x28, 0x46, 0x4b, 0xab, 0x78, 0x0d,
			0xba, 0x5e}, 0}

	tests := []struct {
		name                       string // test description
		txOut                      externalapi.DomainTransactionOutput
		minimumRelayTransactionFee util.Amount // minimum relay transaction fee.
		isDust                     bool
	}{
		{
			// Any value is allowed with a zero relay fee.
			"zero value with zero relay fee",
			externalapi.DomainTransactionOutput{Value: 0, ScriptPublicKey: scriptPublicKey},
			0,
			false,
		},
		{
			// Zero value is dust with any relay fee"
			"zero value with very small tx fee",
			externalapi.DomainTransactionOutput{Value: 0, ScriptPublicKey: scriptPublicKey},
			1,
			true,
		},
		{
			"36 byte public key script with value 605",
			externalapi.DomainTransactionOutput{Value: 605, ScriptPublicKey: scriptPublicKey},
			1000,
			true,
		},
		{
			"36 byte public key script with value 606",
			externalapi.DomainTransactionOutput{Value: 606, ScriptPublicKey: scriptPublicKey},
			1000,
			false,
		},
		{
			// Maximum allowed value is never dust.
			"max sompi amount is never dust",
			externalapi.DomainTransactionOutput{Value: constants.MaxSompi, ScriptPublicKey: scriptPublicKey},
			util.Amount(1000),
			false,
		},
		{
			// Maximum uint64 value causes overflow.
			"maximum uint64 value",
			externalapi.DomainTransactionOutput{Value: math.MaxUint64, ScriptPublicKey: scriptPublicKey},
			math.MaxUint64,
			true,
		},
		{
			// Unspendable ScriptPublicKey due to an invalid public key
			// script.
			"unspendable ScriptPublicKey",
			externalapi.DomainTransactionOutput{Value: 5000, ScriptPublicKey: &externalapi.ScriptPublicKey{[]byte{0x01}, 0}},
			0, // no relay fee
			true,
		},
	}

	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		factory := consensus.NewFactory()
		tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestIsTransactionOutputDust")
		if err != nil {
			t.Fatalf("Error setting up consensus: %+v", err)
		}
		defer teardown(false)

		for _, test := range tests {
			mempoolConfig := DefaultConfig(tc.DAGParams())
			mempoolConfig.MinimumRelayTransactionFee = test.minimumRelayTransactionFee
			tcAsConsensus := tc.(externalapi.Consensus)
			tcAsConsensusPointer := &tcAsConsensus
			mempool := New(mempoolConfig, consensusreference.NewConsensusReference(&tcAsConsensusPointer)).(*mempool)

			res := mempool.IsTransactionOutputDust(&test.txOut)
			if res != test.isDust {
				t.Errorf("Dust test '%s' failed: want %v got %v",
					test.name, test.isDust, res)
			}
		}
	})
}

func TestCheckTransactionStandardInIsolation(t *testing.T) {
	// Create some dummy, but otherwise standard, data for transactions.
	prevOutTxID := &externalapi.DomainTransactionID{}
	dummyPrevOut := externalapi.DomainOutpoint{TransactionID: *prevOutTxID, Index: 1}
	dummySigScript := bytes.Repeat([]byte{0x00}, 65)
	dummyTxIn := externalapi.DomainTransactionInput{
		PreviousOutpoint: dummyPrevOut,
		SignatureScript:  dummySigScript,
		Sequence:         constants.MaxTxInSequenceNum,
	}
	addrHash := [32]byte{0x01}
	addr, err := util.NewAddressPublicKey(addrHash[:], util.Bech32PrefixCryptixTest)
	if err != nil {
		t.Fatalf("NewAddressPublicKey: unexpected error: %v", err)
	}
	dummyScriptPublicKey, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("PayToAddrScript: unexpected error: %v", err)
	}
	dummyTxOut := externalapi.DomainTransactionOutput{
		Value:           100000000, // 1 CPAY
		ScriptPublicKey: dummyScriptPublicKey,
	}
	liquidityVaultTxOut := externalapi.DomainTransactionOutput{
		Value:           constants.SompiPerCryptix,
		ScriptPublicKey: testCATLiquidityVaultScriptPublicKey(),
	}

	tests := []struct {
		name       string
		tx         *externalapi.DomainTransaction
		height     uint64
		isStandard bool
		code       RejectCode
	}{
		{
			name:       "Typical pay-to-pubkey transaction",
			tx:         &externalapi.DomainTransaction{Version: 0, Inputs: []*externalapi.DomainTransactionInput{&dummyTxIn}, Outputs: []*externalapi.DomainTransactionOutput{&dummyTxOut}},
			height:     300000,
			isStandard: true,
		},
		{
			name:       "Transaction version too high",
			tx:         &externalapi.DomainTransaction{Version: constants.MaxTransactionVersion + 1, Inputs: []*externalapi.DomainTransactionInput{&dummyTxIn}, Outputs: []*externalapi.DomainTransactionOutput{&dummyTxOut}},
			height:     300000,
			isStandard: false,
			code:       RejectNonstandard,
		},

		{
			name: "Transaction size is too large",
			tx: &externalapi.DomainTransaction{Version: 0, Inputs: []*externalapi.DomainTransactionInput{&dummyTxIn}, Outputs: []*externalapi.DomainTransactionOutput{{
				Value:           0,
				ScriptPublicKey: &externalapi.ScriptPublicKey{bytes.Repeat([]byte{0x00}, MaximumStandardTransactionMass+1), 0},
			}}},
			height:     300000,
			isStandard: false,
			code:       RejectNonstandard,
		},
		{
			name: "Signature script size is too large",
			tx: &externalapi.DomainTransaction{Version: 0, Inputs: []*externalapi.DomainTransactionInput{{
				PreviousOutpoint: dummyPrevOut,
				SignatureScript:  bytes.Repeat([]byte{0x00}, maximumStandardSignatureScriptSize+1),
				Sequence:         constants.MaxTxInSequenceNum,
			}}, Outputs: []*externalapi.DomainTransactionOutput{&dummyTxOut}},
			height:     300000,
			isStandard: false,
			code:       RejectNonstandard,
		},
		{
			name: "Payload subnetwork payload exceeds standard limit",
			tx: &externalapi.DomainTransaction{
				Version:      0,
				Inputs:       []*externalapi.DomainTransactionInput{&dummyTxIn},
				Outputs:      []*externalapi.DomainTransactionOutput{&dummyTxOut},
				SubnetworkID: subnetworks.SubnetworkIDPayload,
				Payload:      bytes.Repeat([]byte{0x01}, 2049),
			},
			height:     300000,
			isStandard: false,
			code:       RejectNonstandard,
		},
		{
			name: "Valid but non standard public key script",
			tx: &externalapi.DomainTransaction{Version: 0, Inputs: []*externalapi.DomainTransactionInput{&dummyTxIn}, Outputs: []*externalapi.DomainTransactionOutput{{
				Value:           100000000,
				ScriptPublicKey: &externalapi.ScriptPublicKey{[]byte{txscript.OpTrue}, 0},
			}}},
			height:     300000,
			isStandard: false,
			code:       RejectNonstandard,
		},
		{ //Todo : check on ScriptPublicKey type.
			name: "Dust output",
			tx: &externalapi.DomainTransaction{Version: 0, Inputs: []*externalapi.DomainTransactionInput{&dummyTxIn}, Outputs: []*externalapi.DomainTransactionOutput{{
				Value:           0,
				ScriptPublicKey: dummyScriptPublicKey,
			}}},
			height:     300000,
			isStandard: false,
			code:       RejectDust,
		},
		{
			name: "Nulldata transaction",
			tx: &externalapi.DomainTransaction{Version: 0, Inputs: []*externalapi.DomainTransactionInput{&dummyTxIn}, Outputs: []*externalapi.DomainTransactionOutput{{
				Value:           0,
				ScriptPublicKey: &externalapi.ScriptPublicKey{[]byte{txscript.OpReturn}, 0},
			}}},
			height:     300000,
			isStandard: false,
			code:       RejectNonstandard,
		},
		{
			name: "CAT liquidity vault output",
			tx: &externalapi.DomainTransaction{
				Version:      0,
				Inputs:       []*externalapi.DomainTransactionInput{&dummyTxIn},
				Outputs:      []*externalapi.DomainTransactionOutput{&liquidityVaultTxOut},
				SubnetworkID: subnetworks.SubnetworkIDPayload,
				Payload:      testCATSellLiquidityExactInPayload(),
			},
			height:     300000,
			isStandard: true,
		},
		{
			name: "Native liquidity vault output",
			tx: &externalapi.DomainTransaction{
				Version: 0,
				Inputs:  []*externalapi.DomainTransactionInput{&dummyTxIn},
				Outputs: []*externalapi.DomainTransactionOutput{&liquidityVaultTxOut},
			},
			height:     300000,
			isStandard: false,
			code:       RejectNonstandard,
		},
	}

	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		factory := consensus.NewFactory()
		tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestCheckTransactionStandardInIsolation")
		if err != nil {
			t.Fatalf("Error setting up consensus: %+v", err)
		}
		defer teardown(false)

		for _, test := range tests {
			mempoolConfig := DefaultConfig(tc.DAGParams())
			tcAsConsensus := tc.(externalapi.Consensus)
			tcAsConsensusPointer := &tcAsConsensus
			consensusReference := consensusreference.NewConsensusReference(&tcAsConsensusPointer)
			mempool := New(mempoolConfig, consensusReference).(*mempool)

			// Ensure standardness is as expected.
			err := mempool.checkTransactionStandardInIsolation(test.tx)
			if err == nil && test.isStandard {
				// Test passes since function returned standard for a
				// transaction which is intended to be standard.
				continue
			}
			if err == nil && !test.isStandard {
				t.Errorf("checkTransactionStandardInIsolation (%s): standard when "+
					"it should not be", test.name)
				continue
			}
			if err != nil && test.isStandard {
				t.Errorf("checkTransactionStandardInIsolation (%s): nonstandard "+
					"when it should not be: %v", test.name, err)
				continue
			}

			// Ensure error type is a TxRuleError inside of a RuleError.
			var ruleErr RuleError
			if !errors.As(err, &ruleErr) {
				t.Errorf("checkTransactionStandardInIsolation (%s): unexpected "+
					"error type - got %T", test.name, err)
				continue
			}
			txRuleErr, ok := ruleErr.Err.(TxRuleError)
			if !ok {
				t.Errorf("checkTransactionStandardInIsolation (%s): unexpected "+
					"error type - got %T", test.name, ruleErr.Err)
				continue
			}

			// Ensure the reject code is the expected one.
			if txRuleErr.RejectCode != test.code {
				t.Errorf("checkTransactionStandardInIsolation (%s): unexpected "+
					"error code - got %v, want %v", test.name,
					txRuleErr.RejectCode, test.code)
				continue
			}
		}
	})
}

func TestCheckTransactionStandardInContextAllowsCATLiquidityVaultInput(t *testing.T) {
	liquidityVaultScriptPublicKey := testCATLiquidityVaultScriptPublicKey()
	tx := &externalapi.DomainTransaction{
		Version: 0,
		Inputs: []*externalapi.DomainTransactionInput{{
			PreviousOutpoint: externalapi.DomainOutpoint{TransactionID: externalapi.DomainTransactionID{}, Index: 0},
			UTXOEntry:        utxo.NewUTXOEntry(constants.SompiPerCryptix, liquidityVaultScriptPublicKey, false, 1),
			Sequence:         constants.MaxTxInSequenceNum,
		}},
		Outputs: []*externalapi.DomainTransactionOutput{{
			Value:           constants.SompiPerCryptix,
			ScriptPublicKey: liquidityVaultScriptPublicKey,
		}},
		SubnetworkID: subnetworks.SubnetworkIDPayload,
		Payload:      testCATSellLiquidityExactInPayload(),
		Mass:         100,
		Fee:          1000,
	}

	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		factory := consensus.NewFactory()
		tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestCheckTransactionStandardInContextAllowsCATLiquidityVaultInput")
		if err != nil {
			t.Fatalf("Error setting up consensus: %+v", err)
		}
		defer teardown(false)

		mempoolConfig := DefaultConfig(tc.DAGParams())
		tcAsConsensus := tc.(externalapi.Consensus)
		tcAsConsensusPointer := &tcAsConsensus
		mempool := New(mempoolConfig, consensusreference.NewConsensusReference(&tcAsConsensusPointer)).(*mempool)

		if err := mempool.checkTransactionStandardInContext(tx); err != nil {
			t.Fatalf("checkTransactionStandardInContext returned an unexpected error: %v", err)
		}

		nonCATTx := *tx
		nonCATTx.SubnetworkID = subnetworks.SubnetworkIDNative
		nonCATTx.Payload = nil
		err = mempool.checkTransactionStandardInContext(&nonCATTx)
		if err == nil {
			t.Fatalf("checkTransactionStandardInContext accepted a native transaction spending a liquidity vault input")
		}
		var ruleErr RuleError
		if !errors.As(err, &ruleErr) {
			t.Fatalf("checkTransactionStandardInContext returned unexpected error type %T", err)
		}
		txRuleErr, ok := ruleErr.Err.(TxRuleError)
		if !ok {
			t.Fatalf("checkTransactionStandardInContext returned unexpected rule error type %T", ruleErr.Err)
		}
		if txRuleErr.RejectCode != RejectNonstandard {
			t.Fatalf("checkTransactionStandardInContext returned reject code %s, expected %s", txRuleErr.RejectCode, RejectNonstandard)
		}
	})
}

func testCATLiquidityVaultScriptPublicKey() *externalapi.ScriptPublicKey {
	return &externalapi.ScriptPublicKey{
		Script: []byte{txscript.OpData4, 'C', 'L', 'V', '1', txscript.OpDrop, txscript.OpTrue},
	}
}

func testCATSellLiquidityExactInPayload() []byte {
	payload := make([]byte, 16)
	copy(payload[0:3], []byte("CAT"))
	payload[3] = 1
	payload[4] = 7
	binary.LittleEndian.PutUint64(payload[8:16], 1)

	payload = append(payload, make([]byte, externalapi.DomainHashSize)...)
	payload = appendUint64LE(payload, 1)
	payload = appendUint128LE(payload, 1)
	payload = appendUint64LE(payload, 1)
	payload = appendUint16LE(payload, 0)
	return payload
}

func appendUint64LE(payload []byte, value uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], value)
	return append(payload, buf[:]...)
}

func appendUint128LE(payload []byte, value uint64) []byte {
	var buf [16]byte
	binary.LittleEndian.PutUint64(buf[:8], value)
	return append(payload, buf[:]...)
}

func appendUint16LE(payload []byte, value uint16) []byte {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], value)
	return append(payload, buf[:]...)
}
