package pow

import (
	"math"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/hashes"
)

const eps float64 = 1e-9

type matrix [64][64]uint16

func generateMatrix(hash *externalapi.DomainHash) *matrix {
	var mat matrix
	generator := newxoShiRo256PlusPlus(hash)
	for {
		for i := range mat {
			for j := 0; j < 64; j += 16 {
				val := generator.Uint64()
				for shift := 0; shift < 16; shift++ {
					mat[i][j+shift] = uint16(val >> (4 * shift) & 0x0F)
				}
			}
		}
		if mat.computeRank() == 64 {
			return &mat
		}
	}
}

func (mat *matrix) computeRank() int {
	var B [64][64]float64
	for i := range B {
		for j := range B[0] {
			B[i][j] = float64(mat[i][j])
		}
	}
	var rank int
	var rowSelected [64]bool
	for i := 0; i < 64; i++ {
		var j int
		for j = 0; j < 64; j++ {
			if !rowSelected[j] && math.Abs(B[j][i]) > eps {
				break
			}
		}
		if j != 64 {
			rank++
			rowSelected[j] = true
			for p := i + 1; p < 64; p++ {
				B[j][p] /= B[j][i]
			}
			for k := 0; k < 64; k++ {
				if k != j && math.Abs(B[k][i]) > eps {
					for p := i + 1; p < 64; p++ {
						B[k][p] -= B[j][p] * B[k][i]
					}
				}
			}
		}
	}
	return rank
}

// FINAL_CRYPTIX constant
var FINAL_CRYPTIX = [32]byte{
	0xE4, 0x7F, 0x3F, 0x73,
	0xB4, 0xF2, 0xD2, 0x8C,
	0x55, 0xD1, 0xE7, 0x6B,
	0xE0, 0xAD, 0x70, 0x55,
	0xCB, 0x3F, 0x8C, 0x8F,
	0xF5, 0xA0, 0xE2, 0x60,
	0x81, 0xC2, 0x5A, 0x84,
	0x32, 0x81, 0xE4, 0x92,
}

// non-linear S-box transformation
func generateNonLinearSBox(input, key byte) byte {
	result := input * key
	result = (result >> 3) | (result << 5)
	result ^= 0x5A
	return result
}

// Heavyhash function
func (mat *matrix) HeavyHash(hash *externalapi.DomainHash) *externalapi.DomainHash {
	hashBytes := hash.ByteArray()
	var nibbles [64]uint16
	var product [32]byte

	for i := 0; i < 32; i++ {
		nibbles[2*i] = uint16(hashBytes[i] >> 4)
		nibbles[2*i+1] = uint16(hashBytes[i] & 0x0F)
	}

	for i := 0; i < 32; i++ {
		var sum1, sum2 uint16
		for j := 0; j < 64; j++ {
			sum1 += mat[2*i][j] * nibbles[j]
			sum2 += mat[2*i+1][j] * nibbles[j]
		}

		aNibble := (sum1 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum1 >> 8) & 0xF)
		bNibble := (sum2 & 0xF) ^ ((sum1 >> 4) & 0xF) ^ ((sum2 >> 8) & 0xF)

		product[i] = byte((aNibble << 4) | bNibble)
	}

	// XOR with hashBytes
	for i := 0; i < 32; i++ {
		product[i] ^= hashBytes[i]
	}

	// Memory-Hard Operation (16 KB Table)
	var memoryTable [16 * 1024]byte
	index := 0

	for i := 0; i < 32; i++ {
		var sum uint16
		for j := 0; j < 64; j++ {
			sum += uint16(nibbles[j]) * uint16(mat[2*i][j])
		}

		// Memory access with non-linear operations
		for k := 0; k < 12; k++ {
			index ^= (int(memoryTable[(index*7+i)%len(memoryTable)]) * 19) ^ ((i * 53) % 13)
			index = (index*73 + i*41) % len(memoryTable)

			shifted := (index + i*13) % len(memoryTable)
			memoryTable[shifted] ^= byte(sum & 0xFF)
		}
	}

	// Final XOR with the memory table
	for i := 0; i < 32; i++ {
		shiftVal := (int(product[i])*47 + i) % len(memoryTable)
		product[i] ^= memoryTable[shiftVal]
	}

	// XOR with FINAL_CRYPTIX
	for i := 0; i < 32; i++ {
		product[i] ^= FINAL_CRYPTIX[i]
	}

	// **Anti-ASIC Cache**
	var cache [4096]byte
	cacheIndex := 0
	hashValue := byte(0)

	// Initialize the cache
	for i := 0; i < len(cache); i++ {
		hashValue = (product[i%32] ^ byte(i)) + hashValue
		cache[i] = hashValue
	}

	for iteration := 0; iteration < 8; iteration++ {
		for i := 0; i < 32; i++ {
			cacheIndex = (cacheIndex<<5 ^ (int(product[i]) * 17)) % len(cache)
			cache[cacheIndex] ^= product[i]

			safeIndex := ((cacheIndex * 7) % len(cache))
			cacheIndex = (cacheIndex + int(product[i])*23) ^ int(cache[safeIndex])%len(cache)
			cache[cacheIndex] ^= product[(i+11)%32]

			dynamicOffset := ((int(cache[cacheIndex]) * 37) ^ (int(product[i]) * 19)) % len(cache)
			cache[dynamicOffset] ^= product[(i+3)%32]
		}
	}

	// Incorporate cache into the product
	for i := 0; i < 32; i++ {
		shiftVal := (int(product[i])*47 + i) % len(cache)
		product[i] ^= cache[shiftVal]
	}

	// **S-Box Transformation** (aligned with Rust)
	var sbox [256]byte
	for iter := 0; iter < 6; iter++ {
		for i := 0; i < 256; i++ {
			value := byte(i)
			value = generateNonLinearSBox(value, hashBytes[i%len(hashBytes)])
			value ^= value<<4 | value>>2
			sbox[i] = value
		}
	}

	// Apply the S-Box
	for i := 0; i < 32; i++ {
		product[i] = sbox[product[i]]
	}

	// Final hash calculation
	writer := hashes.NewHeavyHashWriter()
	writer.InfallibleWrite(product[:])
	return writer.Finalize()
}
