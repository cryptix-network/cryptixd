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

var final_x = [32]byte{
	0x3F, 0xC2, 0xF2, 0xE2,
	0xD1, 0x55, 0x81, 0x92,
	0xA0, 0x6B, 0xF5, 0x3F,
	0x5A, 0x70, 0x32, 0xB4,
	0xE4, 0x84, 0xE4, 0xCB,
	0x81, 0x73, 0xE7, 0xE0,
	0xD2, 0x7F, 0x8C, 0x55,
	0xAD, 0x8C, 0x60, 0x8F,
}

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

	for i := 0; i < 32; i++ {
		product[i] ^= hashBytes[i] ^ final_x[i]
	}

	// Hash again
	writer := hashes.NewHeavyHashWriter()
	writer.InfallibleWrite(product[:])
	return writer.Finalize()
}
