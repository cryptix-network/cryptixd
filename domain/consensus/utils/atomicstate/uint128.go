package atomicstate

import (
	"encoding/binary"
	"math/big"
	"math/bits"
)

type Uint128 struct {
	Lo uint64
	Hi uint64
}

var maxUint128Big = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))

func Uint128FromUint64(value uint64) Uint128 {
	return Uint128{Lo: value}
}

func Uint128FromLE(bytes []byte) (Uint128, bool) {
	if len(bytes) != 16 {
		return Uint128{}, false
	}
	return Uint128{
		Lo: binary.LittleEndian.Uint64(bytes[:8]),
		Hi: binary.LittleEndian.Uint64(bytes[8:16]),
	}, true
}

func uint128FromBig(value *big.Int) (Uint128, bool) {
	if value.Sign() < 0 || value.Cmp(maxUint128Big) > 0 {
		return Uint128{}, false
	}
	bytes := value.FillBytes(make([]byte, 16))
	for i := 0; i < 8; i++ {
		bytes[i], bytes[15-i] = bytes[15-i], bytes[i]
	}
	out, ok := Uint128FromLE(bytes)
	return out, ok
}

func (value Uint128) IsZero() bool {
	return value.Lo == 0 && value.Hi == 0
}

func (value Uint128) Compare(other Uint128) int {
	if value.Hi < other.Hi {
		return -1
	}
	if value.Hi > other.Hi {
		return 1
	}
	if value.Lo < other.Lo {
		return -1
	}
	if value.Lo > other.Lo {
		return 1
	}
	return 0
}

func (value Uint128) Add(other Uint128) (Uint128, bool) {
	lo, carry := bits.Add64(value.Lo, other.Lo, 0)
	hi, overflow := bits.Add64(value.Hi, other.Hi, carry)
	if overflow != 0 {
		return Uint128{}, false
	}
	return Uint128{Lo: lo, Hi: hi}, true
}

func (value Uint128) Sub(other Uint128) (Uint128, bool) {
	lo, borrow := bits.Sub64(value.Lo, other.Lo, 0)
	hi, overflow := bits.Sub64(value.Hi, other.Hi, borrow)
	if overflow != 0 {
		return Uint128{}, false
	}
	return Uint128{Lo: lo, Hi: hi}, true
}

func (value Uint128) ToLE() [16]byte {
	var out [16]byte
	binary.LittleEndian.PutUint64(out[:8], value.Lo)
	binary.LittleEndian.PutUint64(out[8:], value.Hi)
	return out
}

func (value Uint128) Big() *big.Int {
	var be [16]byte
	binary.BigEndian.PutUint64(be[:8], value.Hi)
	binary.BigEndian.PutUint64(be[8:], value.Lo)
	return new(big.Int).SetBytes(be[:])
}

func (value Uint128) Uint64() (uint64, bool) {
	if value.Hi != 0 {
		return 0, false
	}
	return value.Lo, true
}
