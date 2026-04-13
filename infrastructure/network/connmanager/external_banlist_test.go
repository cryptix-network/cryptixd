package connmanager

import (
	"encoding/json"
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

func buildSignedSnapshotPayload(t *testing.T) []byte {
	t.Helper()

	document := map[string]interface{}{
		"status":                "success",
		"schema_version":        antiFraudSchemaVersion,
		"network":               0,
		"snapshot_seq":          uint64(2),
		"generated_at_ms":       uint64(1_700_000_000_100),
		"signing_key_id":        0,
		"banned_ips_count":      1,
		"banned_ips":            []string{"127.0.0.1"},
		"banned_node_ids_count": 1,
		"banned_node_ids":       []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		"signature":             "cbab47b2818ea9f780b6c99467c7659504cb7a6f7f896277896d4e2ce291296af547b27c9c03fda0825b81cb16039503da1b100dac6942f2a0d654422905cdab",
		"root_hash":             "52e4851244a37828f957d69b7de3f0ee07bc60f913dc0987f612f77411a070c0",
	}
	rawJSON, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("json.Marshal failed: %s", err)
	}
	return rawJSON
}

func TestDecodeExternalBanlistPayload(t *testing.T) {
	rawJSON := buildSignedSnapshotPayload(t)

	snapshot, err := decodeExternalBanlistPayload(rawJSON, 0)
	if err != nil {
		t.Fatalf("decodeExternalBanlistPayload unexpectedly failed: %s", err)
	}

	if snapshot.SnapshotSeq != 2 {
		t.Fatalf("unexpected snapshot seq: got %d expected 2", snapshot.SnapshotSeq)
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
	rawJSON := buildSignedSnapshotPayload(t)
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
