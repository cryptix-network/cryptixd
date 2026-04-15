// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blocktemplatebuilder

const (
	defaultPayloadSoftCapPerBlockBytes     = uint64(32_768)
	defaultPayloadOvercapFeerateMultiplier = 2.0
)

// policy houses the policy (configuration parameters) which is used to control
// the generation of block templates. See the documentation for
// NewBlockTemplate for more details on each of these parameters are used.
type policy struct {
	// BlockMaxMass is the maximum block mass to be used when generating a
	// block template.
	BlockMaxMass uint64
	// PayloadSoftCapPerBlockBytes is a non-consensus payload-byte soft cap
	// applied during block template selection.
	PayloadSoftCapPerBlockBytes uint64
	// PayloadOvercapFeerateMultiplier derives the minimum feerate required
	// once the payload soft cap has been exceeded.
	PayloadOvercapFeerateMultiplier float64
	// MinimumRelayFeerate is the minimum relay feerate in sompi per gram.
	MinimumRelayFeerate float64
}

func (p policy) payloadOvercapFeerateFloor() float64 {
	return p.MinimumRelayFeerate * p.PayloadOvercapFeerateMultiplier
}
