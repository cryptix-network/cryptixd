package bip32

import "github.com/pkg/errors"

// BitcoinMainnetPrivate is the version that is used for
// bitcoin mainnet bip32 private extended keys.
// Ecnodes to xprv in base58.
var BitcoinMainnetPrivate = [4]byte{
	0x04,
	0x88,
	0xad,
	0xe4,
}

// BitcoinMainnetPublic is the version that is used for
// bitcoin mainnet bip32 public extended keys.
// Ecnodes to xpub in base58.
var BitcoinMainnetPublic = [4]byte{
	0x04,
	0x88,
	0xb2,
	0x1e,
}

// CryptixMainnetPrivate is the version that is used for
// cryptix mainnet bip32 private extended keys.
// Ecnodes to xprv in base58.
var CryptixMainnetPrivate = [4]byte{
	0x03,
	0x8f,
	0x2e,
	0xf4,
}

// CryptixMainnetPublic is the version that is used for
// cryptix mainnet bip32 public extended keys.
// Ecnodes to kpub in base58.
var CryptixMainnetPublic = [4]byte{
	0x03,
	0x8f,
	0x33,
	0x2e,
}

// CryptixTestnetPrivate is the version that is used for
// cryptix testnet bip32 public extended keys.
// Ecnodes to ktrv in base58.
var CryptixTestnetPrivate = [4]byte{
	0x03,
	0x90,
	0x9e,
	0x07,
}

// CryptixTestnetPublic is the version that is used for
// cryptix testnet bip32 public extended keys.
// Ecnodes to ktub in base58.
var CryptixTestnetPublic = [4]byte{
	0x03,
	0x90,
	0xa2,
	0x41,
}

// CryptixDevnetPrivate is the version that is used for
// cryptix devnet bip32 public extended keys.
// Ecnodes to kdrv in base58.
var CryptixDevnetPrivate = [4]byte{
	0x03,
	0x8b,
	0x3d,
	0x80,
}

// CryptixDevnetPublic is the version that is used for
// cryptix devnet bip32 public extended keys.
// Ecnodes to xdub in base58.
var CryptixDevnetPublic = [4]byte{
	0x03,
	0x8b,
	0x41,
	0xba,
}

// CryptixSimnetPrivate is the version that is used for
// cryptix simnet bip32 public extended keys.
// Ecnodes to ksrv in base58.
var CryptixSimnetPrivate = [4]byte{
	0x03,
	0x90,
	0x42,
	0x42,
}

// CryptixSimnetPublic is the version that is used for
// cryptix simnet bip32 public extended keys.
// Ecnodes to xsub in base58.
var CryptixSimnetPublic = [4]byte{
	0x03,
	0x90,
	0x46,
	0x7d,
}

func toPublicVersion(version [4]byte) ([4]byte, error) {
	switch version {
	case BitcoinMainnetPrivate:
		return BitcoinMainnetPublic, nil
	case CryptixMainnetPrivate:
		return CryptixMainnetPublic, nil
	case CryptixTestnetPrivate:
		return CryptixTestnetPublic, nil
	case CryptixDevnetPrivate:
		return CryptixDevnetPublic, nil
	case CryptixSimnetPrivate:
		return CryptixSimnetPublic, nil
	}

	return [4]byte{}, errors.Errorf("unknown version %x", version)
}

func isPrivateVersion(version [4]byte) bool {
	switch version {
	case BitcoinMainnetPrivate:
		return true
	case CryptixMainnetPrivate:
		return true
	case CryptixTestnetPrivate:
		return true
	case CryptixDevnetPrivate:
		return true
	case CryptixSimnetPrivate:
		return true
	}

	return false
}
