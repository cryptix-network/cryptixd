package strongnodeclaims

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter"
	"github.com/pkg/errors"
)

const (
	flushMinInterval = 5 * time.Second
)

type IngestStatus uint8

const (
	IngestIgnored IngestStatus = iota
	IngestDropped
	IngestAccepted
	IngestStrike
)

type IngestOutcome struct {
	Status  IngestStatus
	Pending bool
	Reason  string
	NodeID  *[32]byte
}

type ClaimEntrySnapshot struct {
	NodeID             string
	PublicKeyXOnly     string
	ClaimedBlocks      uint32
	ShareBPS           uint32
	LastClaimBlockHash string
	LastClaimTimeMs    uint64
}

type RuntimeSnapshot struct {
	Enabled          bool
	HardforkActive   bool
	RuntimeAvailable bool
	WindowSize       uint32
	ConflictTotal    uint64
	Entries          []ClaimEntrySnapshot
}

type claimRecord struct {
	BlockHash    [32]byte
	NodeID       [32]byte
	PubKeyXOnly  [32]byte
	PowNonce     uint64
	Signature    [64]byte
	ClaimID      [32]byte
	ReceivedAtMs uint64
}

type engineState struct {
	LastSinkHash [32]byte
	HasLastSink  bool

	WindowHashes    [][32]byte
	WindowSet       map[[32]byte]struct{}
	RetentionHashes [][32]byte
	RetentionSet    map[[32]byte]struct{}

	RecentClaimsByBlock    map[[32]byte]map[[32]byte]claimRecord
	PendingUnknownClaims   map[[32]byte][]claimRecord
	WinningClaimByBlock    map[[32]byte]claimRecord
	ScoreByNodeID          map[[32]byte]uint32
	LastClaimTimeByNodeID  map[[32]byte]uint64
	LastClaimBlockByNodeID map[[32]byte][32]byte

	ConflictTotal uint64
	Dirty         bool
	LastFlushTime time.Time
}

type claimStateDisk struct {
	SchemaVersion   uint32            `json:"schema_version"`
	LastSink        string            `json:"last_sink,omitempty"`
	WindowHashes    []string          `json:"window_hashes,omitempty"`
	RetentionHashes []string          `json:"retention_hashes,omitempty"`
	Winners         []claimDiskRecord `json:"winners,omitempty"`
	ConflictTotal   uint64            `json:"conflict_total"`
}

type claimDiskRecord struct {
	BlockHash    string `json:"block_hash"`
	NodeID       string `json:"node_id"`
	PubKeyXOnly  string `json:"pubkey_xonly"`
	PowNonce     uint64 `json:"pow_nonce,omitempty"`
	Signature    string `json:"signature"`
	ClaimID      string `json:"claim_id"`
	ReceivedAtMs uint64 `json:"received_at_ms"`
}

type Engine struct {
	enabled     bool
	networkCode uint8
	claimsDir   string
	mu          sync.Mutex
	state       *engineState
}

func New(enabled bool, networkName string, appDir string) *Engine {
	networkCode, err := netadapter.UnifiedNodeNetworkCodeFromName(networkName)
	if err != nil {
		networkCode = 0
	}
	claimsDir := filepath.Join(appDir, claimsStateDirName)
	if enabled {
		_ = os.MkdirAll(claimsDir, 0o700)
	}

	state := newEngineState()
	if enabled {
		if err := loadState(claimsDir, state, networkCode); err != nil {
			log.Warnf("strong-node-claims: failed loading persisted state: %s", err)
		}
		recomputeScores(state)
	}

	return &Engine{
		enabled:     enabled,
		networkCode: networkCode,
		claimsDir:   claimsDir,
		state:       state,
	}
}

func (e *Engine) Enabled() bool {
	return e.enabled
}

func (e *Engine) ShouldAdvertiseServiceBit(hardforkActive bool) bool {
	return e.enabled && hardforkActive
}

func (e *Engine) LastSink() (*externalapi.DomainHash, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.state.HasLastSink {
		return nil, false
	}
	hash := e.state.LastSinkHash
	return externalapi.NewDomainHashFromByteArray(&hash), true
}

func (e *Engine) IngestClaim(
	message *appmessage.MsgBlockProducerClaimV1,
	hardforkActive bool,
	blockKnown bool,
	expectedNodeID *[32]byte,
) IngestOutcome {
	if !e.enabled || !hardforkActive {
		return IngestOutcome{Status: IngestIgnored}
	}
	if message == nil {
		return IngestOutcome{Status: IngestStrike, Reason: "nil block producer claim"}
	}

	nowMs := uint64(time.Now().UnixMilli())
	record, err := validateClaimMessage(message, e.networkCode, nowMs)
	if err != nil {
		return IngestOutcome{Status: IngestStrike, Reason: err.Error()}
	}
	if expectedNodeID != nil && record.NodeID != *expectedNodeID {
		return IngestOutcome{
			Status: IngestStrike,
			Reason: "claim node ID does not match peer handshake identity",
			NodeID: &record.NodeID,
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	cleanupPendingUnknownClaims(e.state, nowMs)

	_, knownFromRetention := e.state.RetentionSet[record.BlockHash]
	_, knownFromWindow := e.state.WindowSet[record.BlockHash]
	known := blockKnown || knownFromRetention || knownFromWindow
	if !known {
		if !enqueuePendingUnknownClaim(e.state, record, nowMs) {
			return IngestOutcome{Status: IngestDropped}
		}
		e.state.Dirty = true
		return IngestOutcome{Status: IngestAccepted, Pending: true}
	}

	if !insertKnownClaim(e.state, record) {
		return IngestOutcome{Status: IngestDropped}
	}
	e.state.Dirty = true
	return IngestOutcome{Status: IngestAccepted, Pending: false}
}

func (e *Engine) ApplyChainPathUpdate(path *externalapi.SelectedChainPath, newSink *externalapi.DomainHash, hardforkActive bool) {
	if !e.enabled || !hardforkActive || path == nil || newSink == nil {
		return
	}

	nowMs := uint64(time.Now().UnixMilli())
	e.mu.Lock()
	defer e.mu.Unlock()

	changed := false
	for _, removed := range path.Removed {
		if removed == nil {
			continue
		}
		key := *removed.ByteArray()
		if _, ok := e.state.WindowSet[key]; ok {
			delete(e.state.WindowSet, key)
			e.state.WindowHashes = removeHashFromList(e.state.WindowHashes, key)
			if winner, hasWinner := e.state.WinningClaimByBlock[key]; hasWinner {
				decrementScore(e.state.ScoreByNodeID, winner.NodeID)
			}
			changed = true
		}
		if _, ok := e.state.RetentionSet[key]; ok {
			delete(e.state.RetentionSet, key)
			e.state.RetentionHashes = removeHashFromList(e.state.RetentionHashes, key)
			changed = true
		}
		if purgeClaimStateForBlock(e.state, key) {
			changed = true
		}
	}

	for _, added := range path.Added {
		if added == nil {
			continue
		}
		key := *added.ByteArray()
		if _, ok := e.state.RetentionSet[key]; !ok {
			e.state.RetentionSet[key] = struct{}{}
			e.state.RetentionHashes = append(e.state.RetentionHashes, key)
			changed = true
		}
		if _, ok := e.state.WindowSet[key]; !ok {
			e.state.WindowSet[key] = struct{}{}
			e.state.WindowHashes = append(e.state.WindowHashes, key)
			if winner, hasWinner := e.state.WinningClaimByBlock[key]; hasWinner {
				incrementScore(e.state.ScoreByNodeID, winner.NodeID)
			}
			changed = true
		}
		if promotePendingUnknownClaimsForBlock(e.state, key) {
			changed = true
		}
	}

	for len(e.state.WindowHashes) > CLAIM_WINDOW_SIZE_BLOCKS {
		evicted := e.state.WindowHashes[0]
		e.state.WindowHashes = e.state.WindowHashes[1:]
		delete(e.state.WindowSet, evicted)
		if winner, hasWinner := e.state.WinningClaimByBlock[evicted]; hasWinner {
			decrementScore(e.state.ScoreByNodeID, winner.NodeID)
		}
		changed = true
	}

	retentionLimit := CLAIM_WINDOW_SIZE_BLOCKS + CLAIM_REORG_MARGIN_BLOCKS
	for len(e.state.RetentionHashes) > retentionLimit {
		evicted := e.state.RetentionHashes[0]
		e.state.RetentionHashes = e.state.RetentionHashes[1:]
		delete(e.state.RetentionSet, evicted)
		purgeClaimStateForBlock(e.state, evicted)
		changed = true
	}

	cleanupPendingUnknownClaims(e.state, nowMs)

	newSinkKey := *newSink.ByteArray()
	if !e.state.HasLastSink || e.state.LastSinkHash != newSinkKey {
		e.state.LastSinkHash = newSinkKey
		e.state.HasLastSink = true
		changed = true
	}

	if changed {
		recomputeScores(e.state)
		e.state.Dirty = true
	}
}

func (e *Engine) Snapshot(hardforkActive bool) RuntimeSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()

	entries := make([]ClaimEntrySnapshot, 0, len(e.state.ScoreByNodeID))
	for nodeID, score := range e.state.ScoreByNodeID {
		share := uint32(0)
		if CLAIM_WINDOW_SIZE_BLOCKS > 0 {
			share = uint32((uint64(score) * 10_000) / uint64(CLAIM_WINDOW_SIZE_BLOCKS))
		}
		pubKeyXOnly := ""
		for _, winner := range e.state.WinningClaimByBlock {
			if winner.NodeID == nodeID {
				pubKeyXOnly = hex.EncodeToString(winner.PubKeyXOnly[:])
				break
			}
		}
		lastBlock := ""
		if blockHash, ok := e.state.LastClaimBlockByNodeID[nodeID]; ok {
			lastBlock = hex.EncodeToString(blockHash[:])
		}
		lastTime := e.state.LastClaimTimeByNodeID[nodeID]
		entries = append(entries, ClaimEntrySnapshot{
			NodeID:             hex.EncodeToString(nodeID[:]),
			PublicKeyXOnly:     pubKeyXOnly,
			ClaimedBlocks:      score,
			ShareBPS:           share,
			LastClaimBlockHash: lastBlock,
			LastClaimTimeMs:    lastTime,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ClaimedBlocks == entries[j].ClaimedBlocks {
			return entries[i].NodeID < entries[j].NodeID
		}
		return entries[i].ClaimedBlocks > entries[j].ClaimedBlocks
	})

	return RuntimeSnapshot{
		Enabled:          e.enabled,
		HardforkActive:   hardforkActive,
		RuntimeAvailable: e.enabled && hardforkActive,
		WindowSize:       CLAIM_WINDOW_SIZE_BLOCKS,
		ConflictTotal:    e.state.ConflictTotal,
		Entries:          entries,
	}
}

func (e *Engine) ClaimNodeIDsForBlock(blockHash [32]byte) [][32]byte {
	e.mu.Lock()
	defer e.mu.Unlock()

	records := collectValidClaimRecordsForBlock(e.state, e.networkCode, blockHash)
	nodeIDs := make([][32]byte, 0, len(records))
	for _, record := range records {
		nodeIDs = append(nodeIDs, record.NodeID)
	}
	return nodeIDs
}

func (e *Engine) ClaimMessagesForBlock(blockHash [32]byte) []*appmessage.MsgBlockProducerClaimV1 {
	e.mu.Lock()
	defer e.mu.Unlock()

	records := collectValidClaimRecordsForBlock(e.state, e.networkCode, blockHash)
	messages := make([]*appmessage.MsgBlockProducerClaimV1, 0, len(records))
	for _, record := range records {
		messages = append(messages, claimRecordToMessage(e.networkCode, record))
	}
	return messages
}

func (e *Engine) MaybeFlush() {
	e.flush(false)
}

func (e *Engine) BestEffortFlush() {
	e.flush(true)
}

func (e *Engine) flush(force bool) {
	if !e.enabled {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.state.Dirty {
		return
	}
	if !force && !e.state.LastFlushTime.IsZero() && time.Since(e.state.LastFlushTime) < flushMinInterval {
		return
	}
	if err := persistState(e.claimsDir, e.state); err != nil {
		log.Warnf("strong-node-claims: failed persisting state: %s", err)
		return
	}
	e.state.LastFlushTime = time.Now()
	e.state.Dirty = false
}

func newEngineState() *engineState {
	return &engineState{
		WindowSet:              make(map[[32]byte]struct{}),
		RetentionSet:           make(map[[32]byte]struct{}),
		RecentClaimsByBlock:    make(map[[32]byte]map[[32]byte]claimRecord),
		PendingUnknownClaims:   make(map[[32]byte][]claimRecord),
		WinningClaimByBlock:    make(map[[32]byte]claimRecord),
		ScoreByNodeID:          make(map[[32]byte]uint32),
		LastClaimTimeByNodeID:  make(map[[32]byte]uint64),
		LastClaimBlockByNodeID: make(map[[32]byte][32]byte),
	}
}

func validateClaimMessage(message *appmessage.MsgBlockProducerClaimV1, expectedNetworkCode uint8, nowMs uint64) (claimRecord, error) {
	var empty claimRecord
	if message.SchemaVersion != claimSchemaVersion {
		return empty, errors.Errorf("invalid claim schema version %d", message.SchemaVersion)
	}
	if message.Network != uint32(expectedNetworkCode) {
		return empty, errors.New("claim network mismatch")
	}
	if len(message.BlockHash) != 32 {
		return empty, errors.New("block hash must be exactly 32 bytes")
	}
	if len(message.NodePubkeyXOnly) != 32 {
		return empty, errors.New("node pubkey x-only must be exactly 32 bytes")
	}
	if message.NodePowNonce == nil {
		return empty, errors.New("node pow nonce is required")
	}
	if len(message.Signature) != 64 {
		return empty, errors.New("claim signature must be exactly 64 bytes")
	}

	var blockHash [32]byte
	copy(blockHash[:], message.BlockHash)
	var pubKey [32]byte
	copy(pubKey[:], message.NodePubkeyXOnly)
	var signature [64]byte
	copy(signature[:], message.Signature)
	powNonce := *message.NodePowNonce

	nodeID := netadapter.ComputeUnifiedNodeID(pubKey)
	if !netadapter.IsValidUnifiedNodePoWNonce(expectedNetworkCode, pubKey, powNonce) {
		return empty, errors.New("claim node identity proof-of-work is invalid")
	}
	claimID := netadapter.ComputeBlockProducerClaimDigest(expectedNetworkCode, blockHash, nodeID)
	if !netadapter.VerifyBlockProducerClaimSignature(pubKey, claimID, signature) {
		return empty, errors.New("claim signature verification failed")
	}

	return claimRecord{
		BlockHash:    blockHash,
		NodeID:       nodeID,
		PubKeyXOnly:  pubKey,
		PowNonce:     powNonce,
		Signature:    signature,
		ClaimID:      claimID,
		ReceivedAtMs: nowMs,
	}, nil
}

func claimRecordIsValid(record claimRecord, expectedNetworkCode uint8) bool {
	nodeID := netadapter.ComputeUnifiedNodeID(record.PubKeyXOnly)
	if nodeID != record.NodeID {
		return false
	}
	if !netadapter.IsValidUnifiedNodePoWNonce(expectedNetworkCode, record.PubKeyXOnly, record.PowNonce) {
		return false
	}
	claimID := netadapter.ComputeBlockProducerClaimDigest(expectedNetworkCode, record.BlockHash, record.NodeID)
	if claimID != record.ClaimID {
		return false
	}
	return netadapter.VerifyBlockProducerClaimSignature(record.PubKeyXOnly, record.ClaimID, record.Signature)
}

func collectValidClaimRecordsForBlock(state *engineState, networkCode uint8, blockHash [32]byte) []claimRecord {
	byNode := make(map[[32]byte]claimRecord)
	if records, ok := state.RecentClaimsByBlock[blockHash]; ok {
		for _, record := range records {
			if claimRecordIsValid(record, networkCode) {
				if _, exists := byNode[record.NodeID]; !exists {
					byNode[record.NodeID] = record
				}
			}
		}
	}
	if records, ok := state.PendingUnknownClaims[blockHash]; ok {
		for _, record := range records {
			if claimRecordIsValid(record, networkCode) {
				if _, exists := byNode[record.NodeID]; !exists {
					byNode[record.NodeID] = record
				}
			}
		}
	}

	nodeIDs := make([][32]byte, 0, len(byNode))
	for nodeID := range byNode {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Slice(nodeIDs, func(i, j int) bool {
		return bytes.Compare(nodeIDs[i][:], nodeIDs[j][:]) < 0
	})

	records := make([]claimRecord, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		records = append(records, byNode[nodeID])
	}
	return records
}

func claimRecordToMessage(networkCode uint8, record claimRecord) *appmessage.MsgBlockProducerClaimV1 {
	powNonce := record.PowNonce
	return &appmessage.MsgBlockProducerClaimV1{
		SchemaVersion:   claimSchemaVersion,
		Network:         uint32(networkCode),
		BlockHash:       append([]byte(nil), record.BlockHash[:]...),
		NodePubkeyXOnly: append([]byte(nil), record.PubKeyXOnly[:]...),
		NodePowNonce:    &powNonce,
		Signature:       append([]byte(nil), record.Signature[:]...),
	}
}

func insertKnownClaim(state *engineState, record claimRecord) bool {
	claimsForBlock, ok := state.RecentClaimsByBlock[record.BlockHash]
	if !ok {
		claimsForBlock = make(map[[32]byte]claimRecord)
		state.RecentClaimsByBlock[record.BlockHash] = claimsForBlock
	}
	if _, exists := claimsForBlock[record.NodeID]; exists {
		return false
	}
	if len(claimsForBlock) >= KNOWN_CLAIMS_PER_BLOCK_CAP {
		evictNodeID, shouldInsert := knownClaimEvictionCandidate(claimsForBlock, record.NodeID)
		if !shouldInsert {
			return false
		}
		delete(claimsForBlock, evictNodeID)
	}
	claimsForBlock[record.NodeID] = record
	if len(claimsForBlock) > 1 {
		state.ConflictTotal++
	}

	newWinner := selectWinner(claimsForBlock)
	oldWinner, hadOldWinner := state.WinningClaimByBlock[record.BlockHash]
	state.WinningClaimByBlock[record.BlockHash] = newWinner

	if _, inWindow := state.WindowSet[record.BlockHash]; inWindow {
		if hadOldWinner && oldWinner.NodeID != newWinner.NodeID {
			decrementScore(state.ScoreByNodeID, oldWinner.NodeID)
		}
		if !hadOldWinner || oldWinner.NodeID != newWinner.NodeID {
			incrementScore(state.ScoreByNodeID, newWinner.NodeID)
		}
	}

	state.LastClaimTimeByNodeID[newWinner.NodeID] = newWinner.ReceivedAtMs
	state.LastClaimBlockByNodeID[newWinner.NodeID] = newWinner.BlockHash
	return true
}

func knownClaimEvictionCandidate(claims map[[32]byte]claimRecord, incomingNodeID [32]byte) ([32]byte, bool) {
	var largest [32]byte
	found := false
	for nodeID := range claims {
		if !found || bytes.Compare(nodeID[:], largest[:]) > 0 {
			largest = nodeID
			found = true
		}
	}
	if !found {
		return largest, true
	}
	if bytes.Compare(incomingNodeID[:], largest[:]) >= 0 {
		return largest, false
	}
	return largest, true
}

func selectWinner(claims map[[32]byte]claimRecord) claimRecord {
	var winner claimRecord
	hasWinner := false
	for nodeID, record := range claims {
		if !hasWinner || bytes.Compare(nodeID[:], winner.NodeID[:]) < 0 {
			winner = record
			hasWinner = true
		}
	}
	return winner
}

func enqueuePendingUnknownClaim(state *engineState, record claimRecord, nowMs uint64) bool {
	list := state.PendingUnknownClaims[record.BlockHash]
	for _, existing := range list {
		if existing.NodeID == record.NodeID {
			return false
		}
	}
	if len(list) >= KNOWN_CLAIMS_PER_BLOCK_CAP {
		evictIndex, shouldInsert := pendingClaimEvictionIndex(list, record.NodeID)
		if !shouldInsert {
			return false
		}
		list = append(list[:evictIndex], list[evictIndex+1:]...)
	}
	state.PendingUnknownClaims[record.BlockHash] = append(list, record)
	cleanupPendingUnknownClaims(state, nowMs)
	return true
}

func pendingClaimEvictionIndex(claims []claimRecord, incomingNodeID [32]byte) (int, bool) {
	largestIndex := -1
	for i, record := range claims {
		if largestIndex < 0 || bytes.Compare(record.NodeID[:], claims[largestIndex].NodeID[:]) > 0 {
			largestIndex = i
		}
	}
	if largestIndex < 0 {
		return -1, true
	}
	if bytes.Compare(incomingNodeID[:], claims[largestIndex].NodeID[:]) >= 0 {
		return largestIndex, false
	}
	return largestIndex, true
}

func promotePendingUnknownClaimsForBlock(state *engineState, blockHash [32]byte) bool {
	list, ok := state.PendingUnknownClaims[blockHash]
	if !ok || len(list) == 0 {
		return false
	}
	delete(state.PendingUnknownClaims, blockHash)
	sort.Slice(list, func(i, j int) bool {
		return bytes.Compare(list[i].NodeID[:], list[j].NodeID[:]) < 0
	})
	changed := false
	for _, record := range list {
		if insertKnownClaim(state, record) {
			changed = true
		}
	}
	return changed
}

func cleanupPendingUnknownClaims(state *engineState, nowMs uint64) {
	ttlMs := uint64(PENDING_UNKNOWN_CLAIMS_TTL_SECONDS) * 1000
	for blockHash, list := range state.PendingUnknownClaims {
		filtered := make([]claimRecord, 0, len(list))
		for _, record := range list {
			if nowMs-record.ReceivedAtMs <= ttlMs {
				filtered = append(filtered, record)
			}
		}
		if len(filtered) == 0 {
			delete(state.PendingUnknownClaims, blockHash)
			continue
		}
		state.PendingUnknownClaims[blockHash] = filtered
	}

	for pendingClaimsCount(state) > PENDING_UNKNOWN_CLAIMS_CAP {
		var oldestBlock [32]byte
		var oldestIdx int
		var oldestMs uint64
		found := false

		for blockHash, list := range state.PendingUnknownClaims {
			for i, record := range list {
				if !found || record.ReceivedAtMs < oldestMs {
					found = true
					oldestBlock = blockHash
					oldestIdx = i
					oldestMs = record.ReceivedAtMs
				}
			}
		}
		if !found {
			return
		}

		list := state.PendingUnknownClaims[oldestBlock]
		list = append(list[:oldestIdx], list[oldestIdx+1:]...)
		if len(list) == 0 {
			delete(state.PendingUnknownClaims, oldestBlock)
		} else {
			state.PendingUnknownClaims[oldestBlock] = list
		}
	}
}

func pendingClaimsCount(state *engineState) int {
	total := 0
	for _, list := range state.PendingUnknownClaims {
		total += len(list)
	}
	return total
}

func incrementScore(score map[[32]byte]uint32, nodeID [32]byte) {
	score[nodeID] = score[nodeID] + 1
}

func decrementScore(score map[[32]byte]uint32, nodeID [32]byte) {
	current, ok := score[nodeID]
	if !ok {
		return
	}
	if current <= 1 {
		delete(score, nodeID)
		return
	}
	score[nodeID] = current - 1
}

func recomputeScores(state *engineState) {
	state.ScoreByNodeID = make(map[[32]byte]uint32)
	state.LastClaimTimeByNodeID = make(map[[32]byte]uint64)
	state.LastClaimBlockByNodeID = make(map[[32]byte][32]byte)
	for _, blockHash := range state.WindowHashes {
		winner, hasWinner := state.WinningClaimByBlock[blockHash]
		if !hasWinner {
			continue
		}
		incrementScore(state.ScoreByNodeID, winner.NodeID)
		state.LastClaimTimeByNodeID[winner.NodeID] = winner.ReceivedAtMs
		state.LastClaimBlockByNodeID[winner.NodeID] = winner.BlockHash
	}
}

func removeHashFromList(list [][32]byte, target [32]byte) [][32]byte {
	for i := range list {
		if list[i] == target {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

func purgeClaimStateForBlock(state *engineState, blockHash [32]byte) bool {
	changed := false
	if _, ok := state.RecentClaimsByBlock[blockHash]; ok {
		delete(state.RecentClaimsByBlock, blockHash)
		changed = true
	}
	if _, ok := state.WinningClaimByBlock[blockHash]; ok {
		delete(state.WinningClaimByBlock, blockHash)
		changed = true
	}
	if _, ok := state.PendingUnknownClaims[blockHash]; ok {
		delete(state.PendingUnknownClaims, blockHash)
		changed = true
	}
	return changed
}

func loadState(claimsDir string, state *engineState, networkCode uint8) error {
	currentPath := filepath.Join(claimsDir, claimsCurrentFilename)
	previousPath := filepath.Join(claimsDir, claimsPreviousFile)

	disk, err := readStateDisk(currentPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("strong-node-claims: current snapshot is invalid, quarantining %s: %s", currentPath, err)
			_ = quarantineFile(currentPath)
		}
		disk, err = readStateDisk(previousPath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			log.Warnf("strong-node-claims: previous snapshot is invalid, quarantining %s: %s", previousPath, err)
			_ = quarantineFile(previousPath)
			return err
		}
	}

	loadedState, err := decodeStateDisk(disk, networkCode)
	if err != nil {
		return err
	}
	*state = *loadedState
	return nil
}

func readStateDisk(path string) ([]byte, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func decodeStateDisk(raw []byte, networkCode uint8) (*engineState, error) {
	disk := claimStateDisk{}
	if err := json.Unmarshal(raw, &disk); err != nil {
		return nil, errors.Wrap(err, "failed decoding claim state snapshot")
	}
	if disk.SchemaVersion != claimStateSchemaV1 {
		return nil, errors.Errorf("unsupported claim state schema version %d", disk.SchemaVersion)
	}

	state := newEngineState()
	if disk.LastSink != "" {
		lastSink, err := decodeHex32(disk.LastSink)
		if err != nil {
			return nil, errors.Wrap(err, "invalid persisted last sink hash")
		}
		state.LastSinkHash = lastSink
		state.HasLastSink = true
	}

	for _, rawHash := range disk.WindowHashes {
		hash, err := decodeHex32(rawHash)
		if err != nil {
			return nil, errors.Wrap(err, "invalid persisted window hash")
		}
		if _, exists := state.WindowSet[hash]; exists {
			continue
		}
		state.WindowSet[hash] = struct{}{}
		state.WindowHashes = append(state.WindowHashes, hash)
	}
	for _, rawHash := range disk.RetentionHashes {
		hash, err := decodeHex32(rawHash)
		if err != nil {
			return nil, errors.Wrap(err, "invalid persisted retention hash")
		}
		if _, exists := state.RetentionSet[hash]; exists {
			continue
		}
		state.RetentionSet[hash] = struct{}{}
		state.RetentionHashes = append(state.RetentionHashes, hash)
	}
	for _, winner := range disk.Winners {
		blockHash, err := decodeHex32(winner.BlockHash)
		if err != nil {
			return nil, errors.Wrap(err, "invalid winner block hash")
		}
		nodeID, err := decodeHex32(winner.NodeID)
		if err != nil {
			return nil, errors.Wrap(err, "invalid winner node_id")
		}
		pubKeyXOnly, err := decodeHex32(winner.PubKeyXOnly)
		if err != nil {
			return nil, errors.Wrap(err, "invalid winner pubkey_xonly")
		}
		signature, err := decodeHex64(winner.Signature)
		if err != nil {
			return nil, errors.Wrap(err, "invalid winner signature")
		}
		claimID, err := decodeHex32(winner.ClaimID)
		if err != nil {
			return nil, errors.Wrap(err, "invalid winner claim_id")
		}
		record := claimRecord{
			BlockHash:    blockHash,
			NodeID:       nodeID,
			PubKeyXOnly:  pubKeyXOnly,
			PowNonce:     winner.PowNonce,
			Signature:    signature,
			ClaimID:      claimID,
			ReceivedAtMs: winner.ReceivedAtMs,
		}
		if !claimRecordIsValid(record, networkCode) {
			continue
		}
		state.WinningClaimByBlock[blockHash] = record
		state.RecentClaimsByBlock[blockHash] = map[[32]byte]claimRecord{
			nodeID: record,
		}
	}

	state.ConflictTotal = disk.ConflictTotal
	recomputeScores(state)
	return state, nil
}

func persistState(claimsDir string, state *engineState) error {
	if err := os.MkdirAll(claimsDir, 0o700); err != nil {
		return errors.Wrap(err, "failed creating claim state dir")
	}

	disk := claimStateDisk{
		SchemaVersion:   claimStateSchemaV1,
		ConflictTotal:   state.ConflictTotal,
		WindowHashes:    make([]string, 0, len(state.WindowHashes)),
		RetentionHashes: make([]string, 0, len(state.RetentionHashes)),
		Winners:         make([]claimDiskRecord, 0, len(state.WinningClaimByBlock)),
	}
	if state.HasLastSink {
		disk.LastSink = hex.EncodeToString(state.LastSinkHash[:])
	}
	for _, hash := range state.WindowHashes {
		disk.WindowHashes = append(disk.WindowHashes, hex.EncodeToString(hash[:]))
	}
	for _, hash := range state.RetentionHashes {
		disk.RetentionHashes = append(disk.RetentionHashes, hex.EncodeToString(hash[:]))
	}

	blockHashes := make([][32]byte, 0, len(state.WinningClaimByBlock))
	for blockHash := range state.WinningClaimByBlock {
		blockHashes = append(blockHashes, blockHash)
	}
	sort.Slice(blockHashes, func(i, j int) bool {
		return bytes.Compare(blockHashes[i][:], blockHashes[j][:]) < 0
	})

	for _, blockHash := range blockHashes {
		winner := state.WinningClaimByBlock[blockHash]
		disk.Winners = append(disk.Winners, claimDiskRecord{
			BlockHash:    hex.EncodeToString(winner.BlockHash[:]),
			NodeID:       hex.EncodeToString(winner.NodeID[:]),
			PubKeyXOnly:  hex.EncodeToString(winner.PubKeyXOnly[:]),
			PowNonce:     winner.PowNonce,
			Signature:    hex.EncodeToString(winner.Signature[:]),
			ClaimID:      hex.EncodeToString(winner.ClaimID[:]),
			ReceivedAtMs: winner.ReceivedAtMs,
		})
	}

	serialized, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return errors.Wrap(err, "failed serializing claim state")
	}
	serialized = append(serialized, '\n')

	currentPath := filepath.Join(claimsDir, claimsCurrentFilename)
	previousPath := filepath.Join(claimsDir, claimsPreviousFile)
	tmpPath := currentPath + ".tmp"

	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.Wrap(err, "failed creating temp claim state")
	}
	if _, err := file.Write(serialized); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return errors.Wrap(err, "failed writing temp claim state")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return errors.Wrap(err, "failed syncing temp claim state")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return errors.Wrap(err, "failed closing temp claim state")
	}

	if _, err := os.Stat(currentPath); err == nil {
		if data, readErr := os.ReadFile(currentPath); readErr == nil {
			_ = os.WriteFile(previousPath, data, 0o600)
		}
	}
	if err := os.Rename(tmpPath, currentPath); err != nil {
		_ = os.Remove(tmpPath)
		return errors.Wrap(err, "failed replacing claim state")
	}
	_ = syncDir(claimsDir)
	return nil
}

func quarantineFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	quarantinePath := path + ".corrupt-" + time.Now().Format("20060102150405")
	return os.Rename(path, quarantinePath)
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func decodeHex32(value string) ([32]byte, error) {
	var out [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return out, err
	}
	if len(decoded) != 32 {
		return out, errors.Errorf("expected 32 bytes, got %d", len(decoded))
	}
	copy(out[:], decoded)
	return out, nil
}

func decodeHex64(value string) ([64]byte, error) {
	var out [64]byte
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return out, err
	}
	if len(decoded) != 64 {
		return out, errors.Errorf("expected 64 bytes, got %d", len(decoded))
	}
	copy(out[:], decoded)
	return out, nil
}
