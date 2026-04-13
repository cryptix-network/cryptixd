package connmanager

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestExternalBanlistCandidateURLs(t *testing.T) {
	tests := []struct {
		name     string
		rawURL   string
		expected []string
	}{
		{
			name:     "https with http fallback",
			rawURL:   "https://antifraud.cryptix-network.org/api/v1/antifraud/snapshot",
			expected: []string{"https://antifraud.cryptix-network.org/api/v1/antifraud/snapshot", "http://antifraud.cryptix-network.org/api/v1/antifraud/snapshot"},
		},
		{
			name:     "http only",
			rawURL:   "http://localhost:8080/iplist",
			expected: []string{"http://localhost:8080/iplist"},
		},
		{
			name:     "without scheme",
			rawURL:   "antifraud.cryptix-network.org/api/v1/antifraud/snapshot",
			expected: []string{"https://antifraud.cryptix-network.org/api/v1/antifraud/snapshot", "http://antifraud.cryptix-network.org/api/v1/antifraud/snapshot"},
		},
	}

	for _, test := range tests {
		actual := externalBanlistCandidateURLs(test.rawURL)
		if len(actual) != len(test.expected) {
			t.Fatalf("%s: unexpected URL count: got %d expected %d", test.name, len(actual), len(test.expected))
		}
		for i := range actual {
			if actual[i] != test.expected[i] {
				t.Fatalf("%s: unexpected URL at index %d: got %q expected %q", test.name, i, actual[i], test.expected[i])
			}
		}
	}
}

func buildSignedSnapshotPayload(t *testing.T, enabled bool) []byte {
	t.Helper()

	signature := "e78caa63a9121ecf7f845ca4bce4b62ca01bb9277af000a5ffd030dc3855c7707d870f6e85a589a1d2b630eddc643a25d93665c7c663d55741fe5e7293bc539f"
	rootHash := "d121e2a127f06866c23799b48883e00e8c844f62a96e2e207457f52e11c7ab2f"
	if !enabled {
		signature = "5f94c8ec397d696d8c9c95f3c18865cd48a9e4f2b1d31b3c83dec516ed0f0f029812cf87c7abc82c43c4c8ac34fd828bc98e84b8f37459c8458a787398d85076"
		rootHash = "35debec6b2f2ad6def2f701bb97ad5c1c055a4c35135c1f13e4818727ea9bdb0"
	}

	document := map[string]interface{}{
		"status":                "success",
		"antifraud_enabled":     enabled,
		"schema_version":        antiFraudSchemaVersion,
		"network":               0,
		"snapshot_seq":          uint64(2),
		"generated_at_ms":       uint64(1_700_000_000_100),
		"signing_key_id":        0,
		"banned_ips_count":      1,
		"banned_ips":            []string{"127.0.0.1"},
		"banned_node_ids_count": 1,
		"banned_node_ids":       []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		"signature":             signature,
		"root_hash":             rootHash,
	}
	rawJSON, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("json.Marshal failed: %s", err)
	}
	return rawJSON
}

func TestDecodeExternalBanlistPayload(t *testing.T) {
	rawJSON := buildSignedSnapshotPayload(t, true)

	snapshot, err := decodeExternalBanlistPayload(rawJSON, 0)
	if err != nil {
		t.Fatalf("decodeExternalBanlistPayload unexpectedly failed: %s", err)
	}

	if snapshot.SnapshotSeq != 2 {
		t.Fatalf("unexpected snapshot seq: got %d expected 2", snapshot.SnapshotSeq)
	}
	if !snapshot.AntiFraudEnabled {
		t.Fatalf("expected antifraud_enabled=true")
	}
	if len(snapshot.IPs) != 1 {
		t.Fatalf("unexpected IP count: got %d expected 1", len(snapshot.IPs))
	}
	if _, ok := snapshot.IPs["127.0.0.1"]; !ok {
		t.Fatalf("expected IPv4 loopback IP to be present")
	}
	if len(snapshot.NodeIDs) != 1 {
		t.Fatalf("unexpected node ID count: got %d expected 1", len(snapshot.NodeIDs))
	}
	if _, ok := snapshot.NodeIDs["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]; !ok {
		t.Fatalf("expected node ID to be present")
	}
}

func TestDecodeExternalBanlistPayloadRejectsBadSignature(t *testing.T) {
	rawJSON := buildSignedSnapshotPayload(t, true)
	var payload map[string]interface{}
	if err := json.Unmarshal(rawJSON, &payload); err != nil {
		t.Fatalf("json.Unmarshal failed: %s", err)
	}
	payload["signature"] = "00" + payload["signature"].(string)[2:]
	brokenJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal failed: %s", err)
	}

	_, err = decodeExternalBanlistPayload(brokenJSON, 0)
	if err == nil {
		t.Fatalf("expected invalid signature to fail")
	}
}

func TestDecodeExternalBanlistPayloadAcceptsSignedRuntimeDisable(t *testing.T) {
	rawJSON := buildSignedSnapshotPayload(t, false)

	snapshot, err := decodeExternalBanlistPayload(rawJSON, 0)
	if err != nil {
		t.Fatalf("decodeExternalBanlistPayload unexpectedly failed: %s", err)
	}
	if snapshot.AntiFraudEnabled {
		t.Fatalf("expected antifraud_enabled=false")
	}
}

func TestDecodeExternalBanlistPayloadStatusError(t *testing.T) {
	_, err := decodeExternalBanlistPayload([]byte(`{"status":"error","ips":["127.0.0.1"]}`), 0)
	if err == nil {
		t.Fatalf("expected non-success status to return an error")
	}
}

func TestReadSnapshotAntiFraudEnabledRequiresStrictBool(t *testing.T) {
	enabled, err := readSnapshotAntiFraudEnabled([]byte(`{"antifraud_enabled":true}`))
	if err != nil {
		t.Fatalf("expected boolean flag to parse, got error: %s", err)
	}
	if !enabled {
		t.Fatalf("expected antifraud_enabled=true")
	}

	enabled, err = readSnapshotAntiFraudEnabled([]byte(`{"data":{"antifraud_enabled":false}}`))
	if err != nil {
		t.Fatalf("expected nested boolean flag to parse, got error: %s", err)
	}
	if enabled {
		t.Fatalf("expected antifraud_enabled=false")
	}

	_, err = readSnapshotAntiFraudEnabled([]byte(`{"antifraud_enabled":"true"}`))
	if err == nil {
		t.Fatalf("expected string antifraud_enabled to be rejected")
	}
}

func TestPruneAntiFraudPeerVotesRemovesExpiredAndInvalidEntries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	votes := map[string]*peerAntiFraudVote{
		"fresh": {
			snapshot:   &externalBanlistSnapshot{SnapshotSeq: 10},
			receivedAt: now.Add(-time.Second),
		},
		"expired": {
			snapshot:   &externalBanlistSnapshot{SnapshotSeq: 9},
			receivedAt: now.Add(-externalBanlistPeerVoteMaxAge - time.Second),
		},
		"nil-vote": nil,
		"nil-snap": {
			snapshot:   nil,
			receivedAt: now,
		},
	}

	pruneAntiFraudPeerVotes(votes, now)

	if len(votes) != 1 {
		t.Fatalf("expected exactly one peer vote after pruning, got %d", len(votes))
	}
	if _, ok := votes["fresh"]; !ok {
		t.Fatalf("expected fresh vote to remain after pruning")
	}
}

func TestPruneAntiFraudPeerVotesCapsSizeToNewestEntries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	votes := make(map[string]*peerAntiFraudVote, externalBanlistPeerVoteMaxSize+10)
	for i := 0; i < externalBanlistPeerVoteMaxSize+10; i++ {
		peerID := fmt.Sprintf("peer-%04d", i)
		votes[peerID] = &peerAntiFraudVote{
			snapshot:   &externalBanlistSnapshot{SnapshotSeq: uint64(i)},
			receivedAt: now.Add(-time.Duration(i) * time.Millisecond),
		}
	}

	pruneAntiFraudPeerVotes(votes, now)

	if len(votes) != externalBanlistPeerVoteMaxSize {
		t.Fatalf("expected pruned size %d, got %d", externalBanlistPeerVoteMaxSize, len(votes))
	}
	if _, ok := votes["peer-0000"]; !ok {
		t.Fatalf("expected newest vote peer-0000 to remain after pruning")
	}
	oldestID := fmt.Sprintf("peer-%04d", externalBanlistPeerVoteMaxSize+9)
	if _, ok := votes[oldestID]; ok {
		t.Fatalf("expected oldest vote %s to be evicted", oldestID)
	}
}

func TestHandleExternalBanlistRefreshFailureEscalatesToPeerFallback(t *testing.T) {
	manager := &ConnectionManager{}
	now := time.Unix(1_700_000_000, 0)

	manager.handleExternalBanlistRefreshFailure(now, errors.New("seed endpoint unavailable"))

	manager.externalBanlistLock.RLock()
	firstRuntimeEnabled := manager.antiFraudRuntimeEnabled
	firstRetryPending := manager.externalBanlistRetryPending
	firstPeerFallback := manager.antiFraudPeerFallback
	firstNextFetch := manager.nextExternalBanlistFetch
	manager.externalBanlistLock.RUnlock()

	if !firstRuntimeEnabled {
		t.Fatalf("expected anti-fraud runtime to stay enabled during retry")
	}
	if !firstRetryPending {
		t.Fatalf("expected retry pending to be true after first failure")
	}
	if firstPeerFallback {
		t.Fatalf("expected peer fallback to remain false after first failure")
	}
	expectedRetryAt := now.Add(externalBanlistRetryInterval)
	if !firstNextFetch.Equal(expectedRetryAt) {
		t.Fatalf("unexpected first retry time: got %s expected %s", firstNextFetch, expectedRetryAt)
	}

	secondNow := now.Add(time.Second)
	manager.handleExternalBanlistRefreshFailure(secondNow, errors.New("seed endpoint unavailable"))

	manager.externalBanlistLock.RLock()
	secondRuntimeEnabled := manager.antiFraudRuntimeEnabled
	secondRetryPending := manager.externalBanlistRetryPending
	secondPeerFallback := manager.antiFraudPeerFallback
	secondNextFetch := manager.nextExternalBanlistFetch
	manager.externalBanlistLock.RUnlock()

	if !secondRuntimeEnabled {
		t.Fatalf("expected anti-fraud runtime to remain enabled during peer fallback")
	}
	if secondRetryPending {
		t.Fatalf("expected retry pending to be false after fallback activation")
	}
	if !secondPeerFallback {
		t.Fatalf("expected peer fallback to be enabled after consecutive failures")
	}
	expectedFallbackFetch := secondNow.Add(externalBanlistFetchInterval)
	if !secondNextFetch.Equal(expectedFallbackFetch) {
		t.Fatalf("unexpected fallback fetch time: got %s expected %s", secondNextFetch, expectedFallbackFetch)
	}
}

func TestHandleExternalBanlistRefreshFailureKeepsExistingPeerFallback(t *testing.T) {
	manager := &ConnectionManager{
		antiFraudRuntimeEnabled:     true,
		antiFraudPeerFallback:       true,
		externalBanlistRetryPending: true,
		nextExternalBanlistFetch:    time.Unix(0, 0),
		antiFraudCurrentSnapshot:    nil,
		antiFraudHashWindow:         [antiFraudHashWindowLen][32]byte{},
		antiFraudPeerVotes:          nil,
		externallyBannedIPs:         nil,
		externallyBannedNodeIDs:     nil,
		locallyBannedUnifiedNodeIDs: nil,
	}
	now := time.Unix(1_700_000_500, 0)

	manager.handleExternalBanlistRefreshFailure(now, errors.New("still unavailable"))

	manager.externalBanlistLock.RLock()
	defer manager.externalBanlistLock.RUnlock()
	if !manager.antiFraudPeerFallback {
		t.Fatalf("expected peer fallback to remain enabled")
	}
	if manager.externalBanlistRetryPending {
		t.Fatalf("expected retry pending to be cleared while already in fallback")
	}
	expectedNextFetch := now.Add(externalBanlistFetchInterval)
	if !manager.nextExternalBanlistFetch.Equal(expectedNextFetch) {
		t.Fatalf("unexpected next fetch while in fallback: got %s expected %s", manager.nextExternalBanlistFetch, expectedNextFetch)
	}
}
