package transactionvalidator

import (
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/ruleerrors"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/constants"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/transactionhelper"
	"github.com/pkg/errors"
)

// ValidateTransactionInIsolation validates the parts of the transaction that can be validated context-free
func (v *transactionValidator) ValidateTransactionInIsolation(tx *externalapi.DomainTransaction, povDAAScore uint64) error {
	payloadHfActivated := povDAAScore >= v.payloadHfActivationDAAScore

	err := v.checkTransactionInputCount(tx)
	if err != nil {
		return err
	}
	err = v.checkTransactionAmountRanges(tx)
	if err != nil {
		return err
	}
	err = v.checkDuplicateTransactionInputs(tx)
	if err != nil {
		return err
	}
	err = v.checkCoinbaseInIsolation(tx)
	if err != nil {
		return err
	}
	err = v.checkGas(tx)
	if err != nil {
		return err
	}
	err = v.checkSubnetworkRegistryTransaction(tx)
	if err != nil {
		return err
	}

	err = v.checkTransactionSubnetwork(tx, nil, payloadHfActivated)
	if err != nil {
		return err
	}

	err = v.checkTransactionPayload(tx, payloadHfActivated)
	if err != nil {
		return err
	}

	if tx.Version > constants.MaxTransactionVersion {
		return errors.Wrapf(ruleerrors.ErrTransactionVersionIsUnknown, "validation failed: unknown transaction version. ")
	}

	return nil
}

func (v *transactionValidator) checkTransactionInputCount(tx *externalapi.DomainTransaction) error {
	// A non-coinbase transaction must have at least one input.
	if !transactionhelper.IsCoinBase(tx) && len(tx.Inputs) == 0 {
		return errors.Wrapf(ruleerrors.ErrNoTxInputs, "transaction has no inputs")
	}
	return nil
}

func (v *transactionValidator) checkTransactionAmountRanges(tx *externalapi.DomainTransaction) error {
	// Ensure the transaction amounts are in range. Each transaction
	// output must not be negative or more than the max allowed per
	// transaction. Also, the total of all outputs must abide by the same
	// restrictions. All amounts in a transaction are in a unit value known
	// as a sompi. One cryptix is a quantity of sompi as defined by the
	// sompiPerCryptix constant.
	var totalSompi uint64
	for _, txOut := range tx.Outputs {
		sompi := txOut.Value
		if sompi == 0 {
			return errors.Wrap(ruleerrors.ErrTxOutValueZero, "zero value outputs are forbidden")
		}

		if sompi > constants.MaxSompi {
			return errors.Wrapf(ruleerrors.ErrBadTxOutValue, "transaction output value of %d is "+
				"higher than max allowed value of %d", sompi, constants.MaxSompi)
		}

		// Binary arithmetic guarantees that any overflow is detected and reported.
		// This is impossible for Cryptix, but perhaps possible if an alt increases
		// the total money supply.
		newTotalSompi := totalSompi + sompi
		if newTotalSompi < totalSompi {
			return errors.Wrapf(ruleerrors.ErrBadTxOutValue, "total value of all transaction "+
				"outputs exceeds max allowed value of %d",
				constants.MaxSompi)
		}
		totalSompi = newTotalSompi
		if totalSompi > constants.MaxSompi {
			return errors.Wrapf(ruleerrors.ErrBadTxOutValue, "total value of all transaction "+
				"outputs is %d which is higher than max "+
				"allowed value of %d", totalSompi,
				constants.MaxSompi)
		}
	}

	return nil
}

func (v *transactionValidator) checkDuplicateTransactionInputs(tx *externalapi.DomainTransaction) error {
	existingTxOut := make(map[externalapi.DomainOutpoint]struct{})
	for _, txIn := range tx.Inputs {
		if _, exists := existingTxOut[txIn.PreviousOutpoint]; exists {
			return errors.Wrapf(ruleerrors.ErrDuplicateTxInputs, "transaction "+
				"contains duplicate inputs")
		}
		existingTxOut[txIn.PreviousOutpoint] = struct{}{}
	}
	return nil
}

func (v *transactionValidator) checkCoinbaseInIsolation(tx *externalapi.DomainTransaction) error {
	if !transactionhelper.IsCoinBase(tx) {
		return nil
	}

	// Coinbase payload length must not exceed the max length.
	payloadLen := len(tx.Payload)
	if uint64(payloadLen) > v.maxCoinbasePayloadLength {
		return errors.Wrapf(ruleerrors.ErrBadCoinbasePayloadLen, "coinbase transaction payload length "+
			"of %d is out of range (max: %d)",
			payloadLen, v.maxCoinbasePayloadLength)
	}

	if len(tx.Inputs) != 0 {
		return errors.Wrap(ruleerrors.ErrCoinbaseWithInputs, "coinbase has inputs")
	}

	outputsLimit := uint64(v.ghostdagK) + 2
	if uint64(len(tx.Outputs)) > outputsLimit {
		return errors.Wrapf(ruleerrors.ErrCoinbaseTooManyOutputs, "coinbase has too many outputs: got %d where the limit is %d", len(tx.Outputs), outputsLimit)
	}

	for i, output := range tx.Outputs {
		if len(output.ScriptPublicKey.Script) > int(v.coinbasePayloadScriptPublicKeyMaxLength) {
			return errors.Wrapf(ruleerrors.ErrCoinbaseTooLongScriptPublicKey, "coinbase output %d has a too long script public key", i)

		}
	}

	return nil
}

func (v *transactionValidator) checkGas(tx *externalapi.DomainTransaction) error {
	// Keep this aligned with Rust consensus: non-coinbase gas is currently disabled.
	if tx.Gas > 0 {
		return errors.Wrapf(ruleerrors.ErrInvalidGas, "transaction has gas > 0")
	}
	return nil
}

func (v *transactionValidator) checkSubnetworkRegistryTransaction(tx *externalapi.DomainTransaction) error {
	if tx.SubnetworkID != subnetworks.SubnetworkIDRegistry {
		return nil
	}

	if len(tx.Payload) != 8 {
		return errors.Wrapf(ruleerrors.ErrSubnetworkRegistry, "validation failed: subnetwork registry "+
			"tx has an invalid payload")
	}
	return nil
}

func (v *transactionValidator) checkTransactionPayload(tx *externalapi.DomainTransaction, payloadHfActivated bool) error {
	if transactionhelper.IsCoinBase(tx) {
		return nil
	}

	if !payloadHfActivated {
		if len(tx.Payload) > 0 {
			return errors.Wrapf(ruleerrors.ErrInvalidPayload, "non-coinbase transaction includes a payload before payload hardfork activation")
		}
		return nil
	}

	if subnetworks.IsPayload(tx.SubnetworkID) {
		if len(tx.Payload) == 0 {
			return errors.Wrapf(ruleerrors.ErrInvalidPayload, "payload subnetwork transaction must have a non-empty payload")
		}
		if uint64(len(tx.Payload)) > v.payloadMaxLengthConsensus {
			return errors.Wrapf(ruleerrors.ErrInvalidPayload, "payload length %d exceeds max allowed %d",
				len(tx.Payload), v.payloadMaxLengthConsensus)
		}
		return nil
	}

	if len(tx.Payload) > 0 {
		return errors.Wrapf(ruleerrors.ErrInvalidPayload, "payload is only allowed in the payload subnetwork")
	}

	return nil
}

func (v *transactionValidator) checkTransactionSubnetwork(tx *externalapi.DomainTransaction,
	localNodeSubnetworkID *externalapi.DomainSubnetworkID, payloadHfActivated bool) error {
	if !payloadHfActivated {
		if tx.SubnetworkID != subnetworks.SubnetworkIDNative && tx.SubnetworkID != subnetworks.SubnetworkIDCoinbase {
			return errors.Wrapf(ruleerrors.ErrSubnetworksDisabled, "transaction has disabled subnetwork ID before payload hardfork activation")
		}
	} else {
		if tx.SubnetworkID != subnetworks.SubnetworkIDNative &&
			tx.SubnetworkID != subnetworks.SubnetworkIDCoinbase &&
			tx.SubnetworkID != subnetworks.SubnetworkIDPayload {
			return errors.Wrapf(ruleerrors.ErrSubnetworksDisabled, "transaction has disabled subnetwork ID")
		}
	}

	// If we are a partial node, only transactions on built in subnetworks
	// or our own subnetwork may have a payload
	isLocalNodeFull := localNodeSubnetworkID == nil
	shouldTxBeFull := subnetworks.IsBuiltIn(tx.SubnetworkID) ||
		subnetworks.IsPayload(tx.SubnetworkID) ||
		tx.SubnetworkID.Equal(localNodeSubnetworkID)
	if !isLocalNodeFull && !shouldTxBeFull && len(tx.Payload) > 0 {
		return errors.Wrapf(ruleerrors.ErrInvalidPayload,
			"transaction that was expected to be partial has a payload "+
				"with length > 0")
	}
	return nil
}
