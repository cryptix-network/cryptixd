package pow

import (
	"math"
	"math/bits"

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

// ***Anti-FPGA Sidedoor***
func chaoticRandom(x uint32) uint32 {
	return (x * 362605) ^ 0xA5A5A5A5
}

func memoryIntensiveMix(seed uint32) uint32 {
	acc := seed
	for i := 0; i < 32; i++ {
		acc = (acc * 16625) ^ uint32(i)
	}
	return acc
}

func recursiveFibonacciModulated(x uint32, depth uint8) uint32 {
	a := uint32(1)
	b := x | 1
	actualDepth := depth
	if depth > 8 {
		actualDepth = 8
	}

	xMod := x
	for i := uint8(0); i < actualDepth; i++ {
		temp := b
		b = b + (a ^ bits.RotateLeft32(xMod, int(b%17)))
		a = temp
		xMod = rotateRight32(xMod, a%13) ^ b
	}

	return xMod
}

func rotateRight32(x uint32, n uint32) uint32 {
	return bits.RotateLeft32(x, -int(n))
}

func antiFPGAHash(input uint32) uint32 {
	x := input
	noise := memoryIntensiveMix(x)
	depth := uint8((noise & 0x0F) + 10)

	primeFactorSum := uint32(bits.OnesCount32(x))
	x ^= primeFactorSum

	x = recursiveFibonacciModulated(x^noise, depth)
	x ^= memoryIntensiveMix(bits.RotateLeft32(x, 9))

	return x
}

func computeAfterCompProduct(preCompProduct [32]byte) [32]byte {
	var afterCompProduct [32]byte

	for i := 0; i < 32; i++ {
		input := uint32(preCompProduct[i]) ^ (uint32(i) << 8)
		normalizedInput := input % 256
		modifiedInput := chaoticRandom(normalizedInput)

		hashed := antiFPGAHash(modifiedInput)
		afterCompProduct[i] = byte(hashed & 0xFF)
	}

	return afterCompProduct
}

// Otionion

// Octonion Multiply
func octonionMultiply(a, b [8]int64) [8]int64 {
	var result [8]int64

	// e0
	result[0] = a[0]*b[0] - a[1]*b[1] - a[2]*b[2] - a[3]*b[3] - a[4]*b[4] - a[5]*b[5] - a[6]*b[6] - a[7]*b[7]

	// e1
	result[1] = a[0]*b[1] + a[1]*b[0] + a[2]*b[3] - a[3]*b[2] + a[4]*b[5] - a[5]*b[4] - a[6]*b[7] + a[7]*b[6]

	// e2
	result[2] = a[0]*b[2] - a[1]*b[3] + a[2]*b[0] + a[3]*b[1] + a[4]*b[6] - a[5]*b[7] + a[6]*b[4] - a[7]*b[5]

	// e3
	result[3] = a[0]*b[3] + a[1]*b[2] - a[2]*b[1] + a[3]*b[0] + a[4]*b[7] + a[5]*b[6] - a[6]*b[5] + a[7]*b[4]

	// e4
	result[4] = a[0]*b[4] - a[1]*b[5] - a[2]*b[6] - a[3]*b[7] + a[4]*b[0] + a[5]*b[1] + a[6]*b[2] + a[7]*b[3]

	// e5
	result[5] = a[0]*b[5] + a[1]*b[4] - a[2]*b[7] + a[3]*b[6] - a[4]*b[1] + a[5]*b[0] + a[6]*b[3] + a[7]*b[2]

	// e6
	result[6] = a[0]*b[6] + a[1]*b[7] + a[2]*b[4] - a[3]*b[5] - a[4]*b[2] + a[5]*b[3] + a[6]*b[0] + a[7]*b[1]

	// e7
	result[7] = a[0]*b[7] - a[1]*b[6] + a[2]*b[5] + a[3]*b[4] - a[4]*b[3] + a[5]*b[2] + a[6]*b[1] + a[7]*b[0]

	return result
}

// Octonion Hash
func octonionHash(inputHash [32]byte) [8]int64 {
	var oct [8]int64

	for i := 0; i < 8; i++ {
		oct[i] = int64(inputHash[i])
	}

	for i := 8; i < len(inputHash); i++ {
		var rotation [8]int64
		for j := 0; j < 8; j++ {
			rotation[j] = int64(inputHash[(i+j)%32])
		}
		oct = octonionMultiply(oct, rotation)
	}

	return oct
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
		product[i] ^= hashBytes[i]
	}

	// Hash again
	writer := hashes.NewHeavyHashWriter()
	writer.InfallibleWrite(product[:])
	return writer.Finalize()
}

func (mat *matrix) CryptixHash(hash *externalapi.DomainHash) *externalapi.DomainHash {
	hashBytes := hash.ByteArray()

	// Nibbles extraction
	var nibbles [64]uint16
	var product [32]byte
	var nibbleProduct [32]byte

	for i := 0; i < 32; i++ {
		nibbles[2*i] = uint16(hashBytes[i] >> 4)
		nibbles[2*i+1] = uint16(hashBytes[i] & 0x0F)
	}

	// Matrix and vector multiplication
	for i := 0; i < 32; i++ {
		var sum1, sum2, sum3, sum4 uint32
		for j := 0; j < 64; j++ {
			elem := nibbles[j]
			sum1 += uint32(mat[2*i][j]) * uint32(elem)
			sum2 += uint32(mat[2*i+1][j]) * uint32(elem)
			sum3 += uint32(mat[1*i+2][j]) * uint32(elem)
			sum4 += uint32(mat[1*i+3][j]) * uint32(elem)
		}

		// Nibble calculations
		aNibble := (sum1 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum3 >> 8) & 0xF) ^
			((sum1*0xABCD)>>12)&0xF ^
			((sum1*0x1234)>>8)&0xF ^
			((sum2*0x5678)>>16)&0xF ^
			((sum3*0x9ABC)>>4)&0xF ^
			((sum1 << 3) & 0xF) ^ (sum3>>5)&0xF

		bNibble := (sum2 & 0xF) ^ ((sum1 >> 4) & 0xF) ^ ((sum4 >> 8) & 0xF) ^
			((sum2*0xDCBA)>>14)&0xF ^
			((sum2*0x8765)>>10)&0xF ^
			((sum1*0x4321)>>6)&0xF ^
			((sum4<<2)^sum1>>1)&0xF

		cNibble := (sum3 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum2 >> 8) & 0xF) ^
			((sum3*0xF135)>>10)&0xF ^
			((sum3*0x2468)>>12)&0xF ^
			((sum4*0xACEF)>>8)&0xF ^
			((sum2*0x1357)>>4)&0xF ^
			((sum3 << 5) & 0xF) ^ (sum1>>7)&0xF

		dNibble := (sum1 & 0xF) ^ ((sum4 >> 4) & 0xF) ^ ((sum1 >> 8) & 0xF) ^
			((sum4*0x57A3)>>6)&0xF ^
			((sum3*0xD4E3)>>12)&0xF ^
			((sum1*0x9F8B)>>10)&0xF ^
			((sum4<<4)^sum1+sum2)&0xF

		nibbleProduct[i] = byte((cNibble << 4) | dNibble)
		product[i] = byte((aNibble << 4) | bNibble)
	}

	// XOR with original hash
	for i := 0; i < 32; i++ {
		product[i] ^= hashBytes[i]
		nibbleProduct[i] ^= hashBytes[i]
	}

	// Octonion transformation
	var productBeforeOct []byte
	productBeforeOct = append([]byte(nil), product[:]...)
	octonionResult := octonionHash(product)

	for i := 0; i < 32; i++ {
		octValue := octonionResult[i/8]
		octValueU8 := byte((octValue >> (8 * (i % 8))) & 0xFF)
		product[i] ^= octValueU8
	}

	// Final hash after the transformation
	writer := hashes.NewHeavyHashWriter()
	writer.InfallibleWrite(product[:])
	return writer.Finalize()
}
