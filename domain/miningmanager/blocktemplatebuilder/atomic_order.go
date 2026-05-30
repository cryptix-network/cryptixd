package blocktemplatebuilder

import (
	"bytes"
	"sort"

	consensusexternalapi "github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
)

type templateAtomicOrderPriority struct {
	nonceKey    atomicstate.NonceKey
	nonce       uint64
	poolAssetID [consensusexternalapi.DomainHashSize]byte
	poolNonce   uint64
	txID        [consensusexternalapi.DomainHashSize]byte
}

type templateAtomicOrderInfo struct {
	priority templateAtomicOrderPriority
	nonceKey atomicstate.NonceKey
	nonce    uint64

	hasPool     bool
	poolAssetID [consensusexternalapi.DomainHashSize]byte
	poolNonce   uint64

	hasCreatedAsset bool
	createdAssetID  [consensusexternalapi.DomainHashSize]byte

	hasReferencedAsset bool
	referencedAssetID  [consensusexternalapi.DomainHashSize]byte
}

type templateAtomicItem struct {
	index int
	info  templateAtomicOrderInfo
}

type templateAtomicNonceSlot struct {
	key   atomicstate.NonceKey
	nonce uint64
}

type templateAtomicPoolSlot struct {
	assetID [consensusexternalapi.DomainHashSize]byte
	nonce   uint64
}

func orderAtomicCandidateTransactions(candidateTxs []*candidateTx) {
	if len(candidateTxs) <= 1 {
		return
	}

	atomicItems := make([]templateAtomicItem, 0, len(candidateTxs))
	nonAtomicIndices := make([]int, 0, len(candidateTxs))
	for index, candidate := range candidateTxs {
		info, ok := templateAtomicOrderInfoForCandidate(candidate)
		if !ok {
			nonAtomicIndices = append(nonAtomicIndices, index)
			continue
		}
		atomicItems = append(atomicItems, templateAtomicItem{index: index, info: info})
	}
	if len(atomicItems) <= 1 {
		return
	}

	orderedIndices := orderAtomicCandidateIndices(atomicItems)
	orderedIndices = append(orderedIndices, nonAtomicIndices...)
	if len(orderedIndices) != len(candidateTxs) {
		return
	}

	ordered := make([]*candidateTx, 0, len(candidateTxs))
	for _, index := range orderedIndices {
		ordered = append(ordered, candidateTxs[index])
	}
	copy(candidateTxs, ordered)
}

func orderAtomicCandidateIndices(atomicItems []templateAtomicItem) []int {
	if len(atomicItems) <= 1 {
		indices := make([]int, 0, len(atomicItems))
		for _, item := range atomicItems {
			indices = append(indices, item.index)
		}
		return indices
	}

	byNonce := make(map[templateAtomicNonceSlot][]int)
	byPool := make(map[templateAtomicPoolSlot][]int)
	byCreatedAsset := make(map[[consensusexternalapi.DomainHashSize]byte][]int)
	for position, item := range atomicItems {
		info := item.info
		nonceSlot := templateAtomicNonceSlot{key: info.nonceKey, nonce: info.nonce}
		byNonce[nonceSlot] = append(byNonce[nonceSlot], position)
		if info.hasPool {
			poolSlot := templateAtomicPoolSlot{assetID: info.poolAssetID, nonce: info.poolNonce}
			byPool[poolSlot] = append(byPool[poolSlot], position)
		}
		if info.hasCreatedAsset {
			byCreatedAsset[info.createdAssetID] = append(byCreatedAsset[info.createdAssetID], position)
		}
	}

	dependents := make([][]int, len(atomicItems))
	dependencyCounts := make([]int, len(atomicItems))
	addDependency := func(parent, child int) {
		dependents[parent] = append(dependents[parent], child)
		dependencyCounts[child]++
	}

	for childPosition, item := range atomicItems {
		info := item.info
		if info.nonce > 1 {
			parents := byNonce[templateAtomicNonceSlot{key: info.nonceKey, nonce: info.nonce - 1}]
			for _, parent := range parents {
				addDependency(parent, childPosition)
			}
		}
		if info.hasPool && info.poolNonce > 1 {
			parents := byPool[templateAtomicPoolSlot{assetID: info.poolAssetID, nonce: info.poolNonce - 1}]
			for _, parent := range parents {
				addDependency(parent, childPosition)
			}
		}
		if info.hasReferencedAsset {
			parents := byCreatedAsset[info.referencedAssetID]
			for _, parent := range parents {
				addDependency(parent, childPosition)
			}
		}
	}

	ready := make([]int, 0, len(atomicItems))
	for position, count := range dependencyCounts {
		if count == 0 {
			ready = append(ready, position)
		}
	}

	emitted := make([]bool, len(atomicItems))
	orderedPositions := make([]int, 0, len(atomicItems))
	for len(ready) > 0 {
		sort.Slice(ready, func(i, j int) bool {
			return compareAtomicOrderPriority(atomicItems[ready[i]].info.priority, atomicItems[ready[j]].info.priority) < 0
		})

		position := ready[0]
		ready = ready[1:]
		if emitted[position] {
			continue
		}
		emitted[position] = true
		orderedPositions = append(orderedPositions, position)

		newlyReady := make([]int, 0)
		for _, child := range dependents[position] {
			if dependencyCounts[child] > 0 {
				dependencyCounts[child]--
			}
			if dependencyCounts[child] == 0 {
				newlyReady = append(newlyReady, child)
			}
		}
		ready = append(ready, newlyReady...)
	}

	if len(orderedPositions) < len(atomicItems) {
		remaining := make([]int, 0, len(atomicItems)-len(orderedPositions))
		for position := range atomicItems {
			if !emitted[position] {
				remaining = append(remaining, position)
			}
		}
		sort.Slice(remaining, func(i, j int) bool {
			return compareAtomicOrderPriority(atomicItems[remaining[i]].info.priority, atomicItems[remaining[j]].info.priority) < 0
		})
		orderedPositions = append(orderedPositions, remaining...)
	}

	orderedIndices := make([]int, 0, len(orderedPositions))
	for _, position := range orderedPositions {
		orderedIndices = append(orderedIndices, atomicItems[position].index)
	}
	return orderedIndices
}

func templateAtomicOrderInfoForCandidate(candidate *candidateTx) (templateAtomicOrderInfo, bool) {
	if candidate == nil || candidate.DomainTransaction == nil {
		return templateAtomicOrderInfo{}, false
	}
	tx := candidate.DomainTransaction
	if !subnetworks.IsPayload(tx.SubnetworkID) || len(tx.Payload) == 0 {
		return templateAtomicOrderInfo{}, false
	}

	parsed, err := atomicstate.ParsePayload(tx.Payload)
	if err != nil || parsed == nil {
		return templateAtomicOrderInfo{}, false
	}

	authInputIndex := int(parsed.AuthInputIndex)
	if authInputIndex >= len(tx.Inputs) || tx.Inputs[authInputIndex] == nil || tx.Inputs[authInputIndex].UTXOEntry == nil {
		return templateAtomicOrderInfo{}, false
	}
	ownerID, ok := atomicstate.OwnerIDFromScript(tx.Inputs[authInputIndex].UTXOEntry.ScriptPublicKey())
	if !ok {
		return templateAtomicOrderInfo{}, false
	}

	nonceKey, ok := catNonceKey(parsed, ownerID)
	if !ok {
		return templateAtomicOrderInfo{}, false
	}

	txID := *consensushashing.TransactionID(tx).ByteArray()
	return templateAtomicOrderInfoForOp(nonceKey, parsed.Nonce, txID, parsed.Op), true
}

func templateAtomicOrderInfoForOp(
	nonceKey atomicstate.NonceKey,
	nonce uint64,
	txID [consensusexternalapi.DomainHashSize]byte,
	op atomicstate.PayloadOp,
) templateAtomicOrderInfo {
	info := templateAtomicOrderInfo{
		nonceKey: nonceKey,
		nonce:    nonce,
	}

	switch typedOp := op.(type) {
	case atomicstate.TransferOp:
		info.hasReferencedAsset = true
		info.referencedAssetID = typedOp.AssetID
	case atomicstate.MintOp:
		info.hasReferencedAsset = true
		info.referencedAssetID = typedOp.AssetID
	case atomicstate.BurnOp:
		info.hasReferencedAsset = true
		info.referencedAssetID = typedOp.AssetID
	case atomicstate.BuyLiquidityExactInOp:
		info.hasPool = true
		info.poolAssetID = typedOp.AssetID
		info.poolNonce = typedOp.ExpectedPoolNonce
		info.hasReferencedAsset = true
		info.referencedAssetID = typedOp.AssetID
	case atomicstate.SellLiquidityExactInOp:
		info.hasPool = true
		info.poolAssetID = typedOp.AssetID
		info.poolNonce = typedOp.ExpectedPoolNonce
		info.hasReferencedAsset = true
		info.referencedAssetID = typedOp.AssetID
	case atomicstate.ClaimLiquidityFeesOp:
		info.hasPool = true
		info.poolAssetID = typedOp.AssetID
		info.poolNonce = typedOp.ExpectedPoolNonce
		info.hasReferencedAsset = true
		info.referencedAssetID = typedOp.AssetID
	case atomicstate.CreateAssetOp, atomicstate.CreateAssetWithMintOp, atomicstate.CreateLiquidityAssetOp:
		info.hasCreatedAsset = true
		info.createdAssetID = txID
	}

	info.priority = templateAtomicOrderPriority{
		nonceKey:    nonceKey,
		nonce:       nonce,
		poolAssetID: info.poolAssetID,
		poolNonce:   info.poolNonce,
		txID:        txID,
	}
	return info
}

func compareAtomicOrderPriority(left, right templateAtomicOrderPriority) int {
	if cmp := compareAtomicNonceKey(left.nonceKey, right.nonceKey); cmp != 0 {
		return cmp
	}
	if left.nonce < right.nonce {
		return -1
	}
	if left.nonce > right.nonce {
		return 1
	}
	if cmp := bytes.Compare(left.poolAssetID[:], right.poolAssetID[:]); cmp != 0 {
		return cmp
	}
	if left.poolNonce < right.poolNonce {
		return -1
	}
	if left.poolNonce > right.poolNonce {
		return 1
	}
	return bytes.Compare(left.txID[:], right.txID[:])
}

func compareAtomicNonceKey(left, right atomicstate.NonceKey) int {
	if cmp := bytes.Compare(left.OwnerID[:], right.OwnerID[:]); cmp != 0 {
		return cmp
	}
	if left.ScopeKind < right.ScopeKind {
		return -1
	}
	if left.ScopeKind > right.ScopeKind {
		return 1
	}
	return bytes.Compare(left.ScopeID[:], right.ScopeID[:])
}
