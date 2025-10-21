package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/cryptix-network/cryptixd/cmd/cryptixwallet/daemon/server"
	"github.com/cryptix-network/cryptixd/cmd/cryptixwallet/keys"
	"github.com/cryptix-network/cryptixd/cmd/cryptixwallet/libcryptixwallet"
	"github.com/pkg/errors"
)

func sign(conf *signConfig) error {
	if conf.Transaction == "" && conf.TransactionFile == "" {
		return errors.Errorf("Either --transaction or --transaction-file is required")
	}
	if conf.Transaction != "" && conf.TransactionFile != "" {
		return errors.Errorf("Both --transaction and --transaction-file cannot be passed at the same time")
	}

	keysFile, err := keys.ReadKeysFile(conf.NetParams(), conf.KeysFile)
	if err != nil {
		return err
	}

	cmdLinePassword := ""
	if conf.PasswordFile != "" {
		b, err := os.ReadFile(conf.PasswordFile)
		if err != nil {
			return fmt.Errorf("reading password file: %w", err)
		}
		cmdLinePassword = strings.TrimRight(string(b), "\r\n")
	} else if conf.Password != "" {
		cmdLinePassword = conf.Password
	} else if env := os.Getenv("CRYPTIX_WALLET_PASSWORD"); env != "" {
		cmdLinePassword = env
	} else {
		cmdLinePassword = keys.GetPassword("Password:")
	}
	conf.Password = cmdLinePassword

	privateKeys, err := keysFile.DecryptMnemonics(conf.Password)
	if err != nil {
		return err
	}

	transactionsHex := conf.Transaction
	if conf.TransactionFile != "" {
		transactionHexBytes, err := ioutil.ReadFile(conf.TransactionFile)
		if err != nil {
			return errors.Wrapf(err, "Could not read hex from %s", conf.TransactionFile)
		}
		transactionsHex = strings.TrimSpace(string(transactionHexBytes))
	}
	partiallySignedTransactions, err := server.DecodeTransactionsFromHex(transactionsHex)
	if err != nil {
		return err
	}

	updatedPartiallySignedTransactions := make([][]byte, len(partiallySignedTransactions))
	for i, partiallySignedTransaction := range partiallySignedTransactions {
		updatedPartiallySignedTransactions[i], err =
			libcryptixwallet.Sign(conf.NetParams(), privateKeys, partiallySignedTransaction, keysFile.ECDSA)
		if err != nil {
			return err
		}
	}

	areAllTransactionsFullySigned := true
	for _, updatedPartiallySignedTransaction := range updatedPartiallySignedTransactions {
		isFullySigned, err := libcryptixwallet.IsTransactionFullySigned(updatedPartiallySignedTransaction)
		if err != nil {
			return err
		}
		if !isFullySigned {
			areAllTransactionsFullySigned = false
		}
	}

	if areAllTransactionsFullySigned {
		fmt.Fprintln(os.Stderr, "The transaction is signed and ready to broadcast")
	} else {
		fmt.Fprintln(os.Stderr, "Successfully signed transaction")
	}

	fmt.Println(server.EncodeTransactionsToHex(updatedPartiallySignedTransactions))
	return nil
}
