package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/cryptix-network/cryptixd/cmd/cryptixwallet/libcryptixwallet"
	"github.com/cryptix-network/cryptixd/cmd/cryptixwallet/libcryptixwallet/bip32"
	"github.com/cryptix-network/cryptixd/cmd/cryptixwallet/utils"
	"github.com/pkg/errors"

	"github.com/cryptix-network/cryptixd/cmd/cryptixwallet/keys"
)

func create(conf *createConfig) error {
	var encryptedMnemonics []*keys.EncryptedMnemonic
	var signerExtendedPublicKeys []string
	var err error
	isMultisig := conf.NumPublicKeys > 1

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
	}

	if !conf.Import {
		encryptedMnemonics, signerExtendedPublicKeys, err = keys.CreateMnemonics(conf.NetParams(), conf.NumPrivateKeys, cmdLinePassword, isMultisig)
	} else {
		encryptedMnemonics, signerExtendedPublicKeys, err = keys.ImportMnemonics(conf.NetParams(), conf.NumPrivateKeys, cmdLinePassword, isMultisig)
	}
	if err != nil {
		return err
	}

	for i, extendedPublicKey := range signerExtendedPublicKeys {
		fmt.Printf("Extended public key of mnemonic #%d:\n%s\n\n", i+1, extendedPublicKey)
	}

	fmt.Printf("Notice: Above keys are not wallet addresses or secret seeds.\n" +
		"Use \"cryptixwallet dump-unencrypted-data\" for secret seed phrases\n" +
		"and \"cryptixwallet new-address\" for wallet addresses.\n\n")

	extendedPublicKeys := make([]string, conf.NumPrivateKeys, conf.NumPublicKeys)
	copy(extendedPublicKeys, signerExtendedPublicKeys)
	reader := bufio.NewReader(os.Stdin)
	for i := conf.NumPrivateKeys; i < conf.NumPublicKeys; i++ {
		fmt.Printf("Enter public key #%d here:\n", i+1)
		extendedPublicKey, err := utils.ReadLine(reader)
		if err != nil {
			return err
		}

		_, err = bip32.DeserializeExtendedKey(string(extendedPublicKey))
		if err != nil {
			return errors.Wrapf(err, "%s is invalid extended public key", string(extendedPublicKey))
		}

		fmt.Println()
		extendedPublicKeys = append(extendedPublicKeys, string(extendedPublicKey))
	}

	cosignerIndex := uint32(0)
	if len(signerExtendedPublicKeys) > 0 {
		cosignerIndex, err = libcryptixwallet.MinimumCosignerIndex(signerExtendedPublicKeys, extendedPublicKeys)
		if err != nil {
			return err
		}
	}

	file := keys.File{
		Version:            keys.LastVersion,
		EncryptedMnemonics: encryptedMnemonics,
		ExtendedPublicKeys: extendedPublicKeys,
		MinimumSignatures:  conf.MinimumSignatures,
		CosignerIndex:      cosignerIndex,
		ECDSA:              conf.ECDSA,
	}

	err = file.SetPath(conf.NetParams(), conf.KeysFile, conf.Yes)
	if err != nil {
		return err
	}

	err = file.TryLock()
	if err != nil {
		return err
	}

	err = file.Save()
	if err != nil {
		return err
	}

	fmt.Printf("Wrote the keys into %s\n", file.Path())
	return nil
}
