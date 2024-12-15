// Copyright (c) 2013, 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"math"
	"strconv"

	"github.com/cryptix-network/cryptixd/domain/consensus/utils/constants"
	"github.com/pkg/errors"
)

// AmountUnit describes a method of converting an Amount to something
// other than the base unit of a cryptix. The value of the AmountUnit
// is the exponent component of the decadic multiple to convert from
// an amount in cryptix to an amount counted in units.
type AmountUnit int

// These constants define various units used when describing a cryptix
// monetary amount.
const (
	AmountMegaCYTX  AmountUnit = 6
	AmountKiloCYTX  AmountUnit = 3
	AmountCYTX      AmountUnit = 0
	AmountMilliCYTX AmountUnit = -3
	AmountMicroCYTX AmountUnit = -6
	AmountSompi     AmountUnit = -8
)

// String returns the unit as a string. For recognized units, the SI
// prefix is used, or "Sompi" for the base unit. For all unrecognized
// units, "1eN CYTX" is returned, where N is the AmountUnit.
func (u AmountUnit) String() string {
	switch u {
	case AmountMegaCYTX:
		return "MCYTX"
	case AmountKiloCYTX:
		return "kCYTX"
	case AmountCYTX:
		return "CYTX"
	case AmountMilliCYTX:
		return "mCYTX"
	case AmountMicroCYTX:
		return "μCYTX"
	case AmountSompi:
		return "Sompi"
	default:
		return "1e" + strconv.FormatInt(int64(u), 10) + " CYTX"
	}
}

// Amount represents the base cryptix monetary unit (colloquially referred
// to as a `Sompi'). A single Amount is equal to 1e-8 of a cryptix.
type Amount uint64

// round converts a floating point number, which may or may not be representable
// as an integer, to the Amount integer type by rounding to the nearest integer.
// This is performed by adding or subtracting 0.5 depending on the sign, and
// relying on integer truncation to round the value to the nearest Amount.
func round(f float64) Amount {
	if f < 0 {
		return Amount(f - 0.5)
	}
	return Amount(f + 0.5)
}

// NewAmount creates an Amount from a floating point value representing
// some value in cryptix. NewAmount errors if f is NaN or +-Infinity, but
// does not check that the amount is within the total amount of cryptix
// producible as f may not refer to an amount at a single moment in time.
//
// NewAmount is for specifically for converting CYTX to Sompi.
// For creating a new Amount with an int64 value which denotes a quantity of Sompi,
// do a simple type conversion from type int64 to Amount.
// TODO: Refactor NewAmount. When amounts are more than 1e9 CYTX, the precision
// can be higher than one sompi (1e9 and 1e9+1e-8 will result as the same number)
func NewAmount(f float64) (Amount, error) {
	// The amount is only considered invalid if it cannot be represented
	// as an integer type. This may happen if f is NaN or +-Infinity.
	switch {
	case math.IsNaN(f):
		fallthrough
	case math.IsInf(f, 1):
		fallthrough
	case math.IsInf(f, -1):
		return 0, errors.New("invalid cryptix amount")
	}

	return round(f * constants.SompiPerCryptix), nil
}

// ToUnit converts a monetary amount counted in cryptix base units to a
// floating point value representing an amount of cryptix.
func (a Amount) ToUnit(u AmountUnit) float64 {
	return float64(a) / math.Pow10(int(u+8))
}

// ToCYTX is the equivalent of calling ToUnit with AmountCYTX.
func (a Amount) ToCYTX() float64 {
	return a.ToUnit(AmountCYTX)
}

// Format formats a monetary amount counted in cryptix base units as a
// string for a given unit. The conversion will succeed for any unit,
// however, known units will be formated with an appended label describing
// the units with SI notation, or "Sompi" for the base unit.
func (a Amount) Format(u AmountUnit) string {
	units := " " + u.String()
	return strconv.FormatFloat(a.ToUnit(u), 'f', -int(u+8), 64) + units
}

// String is the equivalent of calling Format with AmountCYTX.
func (a Amount) String() string {
	return a.Format(AmountCYTX)
}

// MulF64 multiplies an Amount by a floating point value. While this is not
// an operation that must typically be done by a full node or wallet, it is
// useful for services that build on top of cryptix (for example, calculating
// a fee by multiplying by a percentage).
func (a Amount) MulF64(f float64) Amount {
	return round(float64(a) * f)
}
