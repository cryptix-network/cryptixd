/*
Package util provides cryptix-specific convenience functions and types.

# Block Overview

A Block defines a cryptix block that provides easier and more efficient
manipulation of raw blocks. It also memoizes hashes for the
block and its transactions on their first access so subsequent accesses don't
have to repeat the relatively expensive hashing operations.

# Tx Overview

A Tx defines a cryptix transaction that provides more efficient manipulation of
raw transactions. It memoizes the hash for the transaction on its
first access so subsequent accesses don't have to repeat the relatively
expensive hashing operations.

# Address Overview

The Address interface provides an abstraction for a cryptix address. While the
most common type is a pay-to-pubkey, cryptix already supports others and
may well support more in the future. This package currently provides
implementations for the pay-to-pubkey, and pay-to-script-hash address
types.

To decode/encode an address:

	addrString := "cryptix:qrjefk2r8wp607rmyvxmgjansqcwugjazpu2kk2r7057gltxetdvk8gl9fs0w"
	defaultPrefix := util.Bech32PrefixCryptix
	addr, err := util.DecodeAddress(addrString, defaultPrefix)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(addr.EncodeAddress())
*/
package util
