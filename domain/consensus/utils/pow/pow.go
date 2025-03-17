package pow

import (
	"encoding/binary"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/hashes"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/serialization"
	"github.com/cryptix-network/cryptixd/util/difficulty"

	"math/big"
	"math/bits"

	"github.com/pkg/errors"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/sha3"
)

// State is an intermediate data structure with pre-computed values to speed up mining.
type State struct {
	mat        matrix
	Timestamp  int64
	Nonce      uint64
	Target     big.Int
	prePowHash externalapi.DomainHash
}

// NewState creates a new state with pre-computed values to speed up mining
// It takes the target from the Bits field
func NewState(header externalapi.MutableBlockHeader) *State {
	target := difficulty.CompactToBig(header.Bits())
	// Zero out the time and nonce.
	timestamp, nonce := header.TimeInMilliseconds(), header.Nonce()
	header.SetTimeInMilliseconds(0)
	header.SetNonce(0)
	prePowHash := consensushashing.HeaderHash(header)
	header.SetTimeInMilliseconds(timestamp)
	header.SetNonce(nonce)

	return &State{
		Target:     *target,
		prePowHash: *prePowHash,
		mat:        *generateMatrix(prePowHash),
		Timestamp:  timestamp,
		Nonce:      nonce,
	}
}

/*
func (state *State) CalculateProofOfWorkValue() *big.Int {
	// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
	writer := hashes.NewPoWHashWriter()
	writer.InfallibleWrite(state.prePowHash.ByteSlice())
	err := serialization.WriteElement(writer, state.Timestamp)
	if err != nil {
		panic(errors.Wrap(err, "this should never happen. Hash digest should never return an error"))
	}
	zeroes := [32]byte{}
	writer.InfallibleWrite(zeroes[:])
	err = serialization.WriteElement(writer, state.Nonce)
	if err != nil {
		panic(errors.Wrap(err, "this should never happen. Hash digest should never return an error"))
	}
	powHash := writer.Finalize()

	sha3Hasher := sha3.New256()
	sha3Hasher.Write(powHash.ByteSlice())
	sha3HashBytes := sha3Hasher.Sum(nil)

	sha3DomainHash, err := externalapi.NewDomainHashFromByteSlice(sha3HashBytes)
	if err != nil {
		panic(errors.Wrap(err, "failed to create DomainHash from SHA3 hash bytes"))
	}

	heavyHash := state.mat.HeavyHash(sha3DomainHash)

	return toBig(heavyHash)
}
*/

// Constants for the offsets
const SHA3_ROUND_OFFSET = 8
const B3_ROUND_OFFSET = 4
const ROUND_RANGE_SIZE = 4

func (state *State) CalculateProofOfWorkValue() *big.Int {
	// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
	writer := hashes.NewPoWHashWriter()
	writer.InfallibleWrite(state.prePowHash.ByteSlice())
	err := serialization.WriteElement(writer, state.Timestamp)
	if err != nil {
		panic(errors.Wrap(err, "this should never happen. Hash digest should never return an error"))
	}
	zeroes := [32]byte{}
	writer.InfallibleWrite(zeroes[:])
	err = serialization.WriteElement(writer, state.Nonce)
	if err != nil {
		panic(errors.Wrap(err, "this should never happen. Hash digest should never return an error"))
	}
	powHash := writer.Finalize()

	// Calculate SHA3-256 hash
	sha3HashBytes := sha3Hash(powHash.ByteSlice())

	// Calculate BLAKE3 hash
	b3Hash := state.blake3Hash(sha3HashBytes)

	// Calculate dynamic rounds for BLAKE3 and SHA3
	b3Rounds := state.calculateB3Rounds(sha3HashBytes)
	sha3Rounds := state.calculateSha3Rounds(sha3HashBytes)

	// Additional dynamic rounds based on byte 0
	extraRounds := int(sha3HashBytes[0] % 6)

	// Dynamic number of rounds for BLAKE3
	for i := 0; i < b3Rounds+extraRounds; i++ {
		b3Hash = state.blake3Hash(b3Hash)
		// Additional manipulation based on hash value
		if b3Hash[5]%2 == 0 {
			b3Hash[10] ^= 0xAA
		} else {
			b3Hash[15] += 23
		}
	}

	// Dynamic number of rounds for SHA3
	for i := 0; i < sha3Rounds+extraRounds; i++ {
		sha3HashBytes = sha3Hash(sha3HashBytes)
		// ASIC-unfriendly conditions
		if sha3HashBytes[3]%3 == 0 {
			sha3HashBytes[20] ^= 0x55
		} else if sha3HashBytes[7]%5 == 0 {
			sha3HashBytes[25] = bits.RotateLeft8(sha3HashBytes[25], 7)
		}
	}

	// ** Branches for byte manipulation **
	for i := 0; i < 32; i++ {
		condition := (sha3HashBytes[i] ^ byte(state.Nonce)) % 6
		switch condition {
		case 0:
			sha3HashBytes[i] = sha3HashBytes[i] + 13
			sha3HashBytes[i] = bits.RotateLeft8(sha3HashBytes[i], 3)
		case 1:
			sha3HashBytes[i] = sha3HashBytes[i] - 7
			sha3HashBytes[i] = bits.RotateLeft8(sha3HashBytes[i], 5)
		case 2:
			sha3HashBytes[i] ^= 0x5A
			sha3HashBytes[i] += 0xAC
		case 3:
			sha3HashBytes[i] *= 17
			sha3HashBytes[i] ^= 0xAA
		case 4:
			sha3HashBytes[i] -= 29
			sha3HashBytes[i] = bits.RotateLeft8(sha3HashBytes[i], 1)
		case 5:
			sha3HashBytes[i] += (0xAA ^ byte(state.Nonce))
			sha3HashBytes[i] ^= 0x45
		}
	}

	// **  Bitwise-Manipulations-Function **
	state.bitManipulations(sha3HashBytes)

	// ** Byte Mixing after the manipulations **
	mixedHash := state.byteMixing(sha3HashBytes, b3Hash)

	// Convert mixedHash to *externalapi.DomainHash
	domainHash, err := externalapi.NewDomainHashFromByteSlice(mixedHash)
	if err != nil {
		panic(errors.Wrap(err, "Error while creating DomainHash"))
	}

	// Apply HeavyHash to the mixed hash
	heavyHash := state.mat.HeavyHash(domainHash)

	// Return the result as a BigInt
	return toBig(heavyHash)
}

// ** SHA3-256 Hash Function **
func sha3Hash(input []byte) []byte {
	sha3Hasher := sha3.New256()
	sha3Hasher.Write(input)
	return sha3Hasher.Sum(nil)
}

// BLAKE3 Hash Function
func (state *State) blake3Hash(input []byte) []byte {
	// BLAKE3 hash calculation (32 byte output value)
	hash := blake3.New()
	hash.Write(input)
	return hash.Sum(nil)
}

// Calculating the BLAKE3 rounds
func (state *State) calculateB3Rounds(input []byte) int {
	slice := input[B3_ROUND_OFFSET : B3_ROUND_OFFSET+ROUND_RANGE_SIZE]
	value := binary.LittleEndian.Uint32(slice)
	return int(value%5 + 1) // Rounds from 1 to 5
}

// Calculating the SHA3 rounds
func (state *State) calculateSha3Rounds(input []byte) int {
	slice := input[SHA3_ROUND_OFFSET : SHA3_ROUND_OFFSET+ROUND_RANGE_SIZE]
	value := binary.LittleEndian.Uint32(slice)
	return int(value%4 + 1) // Rounds from 1 to 4
}

// ** Byte Mixing Funktion **
func (state *State) byteMixing(sha3Hash []byte, b3Hash []byte) []byte {
	var tempBuf [32]byte
	for i := 0; i < 32; i++ {
		a := sha3Hash[i]
		b := b3Hash[i]

		// bitwise AND and OR
		andResult := a & b
		orResult := a | b

		// bitwise Rotation and Shift
		rotated := orResult<<5 | orResult>>(8-5) // Rotation 5 Bits
		shifted := andResult << 3                // Shift 3 Bits

		// Combining the results
		mixed := rotated ^ shifted

		// Save in temporary buffer
		tempBuf[i] = mixed
	}
	return tempBuf[:]
}

// Bitwise manipulations on data
func (state *State) bitManipulations(data []byte) {
	for i := 0; i < 32; i++ {
		// Non-linear manipulations with pseudo-random patterns
		b := data[(i+1)%32]

		// XOR with next byte
		data[i] ^= b

		// Rotation left by 3 bits
		data[i] = bits.RotateLeft8(data[i], 3)

		// Add random constant and apply mask
		data[i] = (data[i] + 0x9F) & 0xFF

		// AND with mask to set certain bits (0xFE will clear the least significant bit)
		data[i] &= 0xFE

		// XOR with index shifted by 2 bits
		data[i] ^= byte(i<<2) & 0xFF
	}
}

/*

























 */

// IncrementNonce the nonce in State by 1
func (state *State) IncrementNonce() {
	state.Nonce++
}

// CheckProofOfWork check's if the block has a valid PoW according to the provided target
// it does not check if the difficulty itself is valid or less than the maximum for the appropriate network
func (state *State) CheckProofOfWork() bool {
	// The block pow must be less than the claimed target
	powNum := state.CalculateProofOfWorkValue()

	// The block hash must be less or equal than the claimed target.
	return powNum.Cmp(&state.Target) <= 0
}

// CheckProofOfWorkByBits check's if the block has a valid PoW according to its Bits field
// it does not check if the difficulty itself is valid or less than the maximum for the appropriate network
func CheckProofOfWorkByBits(header externalapi.MutableBlockHeader) bool {
	return NewState(header).CheckProofOfWork()
}

// ToBig converts a externalapi.DomainHash into a big.Int treated as a little endian string.
func toBig(hash *externalapi.DomainHash) *big.Int {
	// We treat the Hash as little-endian for PoW purposes, but the big package wants the bytes in big-endian, so reverse them.
	buf := hash.ByteSlice()
	blen := len(buf)
	for i := 0; i < blen/2; i++ {
		buf[i], buf[blen-1-i] = buf[blen-1-i], buf[i]
	}

	return new(big.Int).SetBytes(buf)
}

// BlockLevel returns the block level of the given header.
func BlockLevel(header externalapi.BlockHeader, maxBlockLevel int) int {
	// Genesis is defined to be the root of all blocks at all levels, so we define it to be the maximal
	// block level.
	if len(header.DirectParents()) == 0 {
		return maxBlockLevel
	}

	proofOfWorkValue := NewState(header.ToMutable()).CalculateProofOfWorkValue()
	level := maxBlockLevel - proofOfWorkValue.BitLen()
	// If the block has a level lower than genesis make it zero.
	if level < 0 {
		level = 0
	}
	return level
}
