package connmanager

import (
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/domain/dagconfig"
	"github.com/cryptix-network/cryptixd/infrastructure/config"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/id"
	secp256k1 "github.com/cryptix-network/go-secp256k1"
	"github.com/zeebo/blake3"
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

func TestIsNodeIDBanned(t *testing.T) {
	serializedID, err := hex.DecodeString("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatalf("hex.DecodeString failed: %s", err)
	}
	peerID, err := id.FromBytes(serializedID)
	if err != nil {
		t.Fatalf("id.FromBytes failed: %s", err)
	}

	cm := &ConnectionManager{
		cfg: &config.Config{
			Flags: &config.Flags{
				EnableExternalBanlist: true,
			},
		},
		externallyBannedNodeIDs: map[string]struct{}{
			peerID.String(): {},
		},
	}

	if !cm.IsNodeIDBanned(peerID) {
		t.Fatalf("expected peer ID to be banned")
	}
}

func TestExtractStrongNodeIDFromUserAgent(t *testing.T) {
	const strongNodeID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	userAgent := "/cryptixd:1.0.0/cryptixd:1.0.0(strong-id=" + strongNodeID + ")/"

	extracted, ok := extractStrongNodeIDFromUserAgent(userAgent)
	if !ok {
		t.Fatalf("expected strong-node ID to be extracted from user-agent")
	}
	if extracted != strongNodeID {
		t.Fatalf("unexpected strong-node ID: got %s expected %s", extracted, strongNodeID)
	}
}

func TestApplyStrongNodeAnnouncement(t *testing.T) {
	keyPair, err := secp256k1.GenerateSchnorrKeyPair()
	if err != nil {
		t.Fatalf("GenerateSchnorrKeyPair failed: %s", err)
	}
	pubKey, err := keyPair.SchnorrPublicKey()
	if err != nil {
		t.Fatalf("SchnorrPublicKey failed: %s", err)
	}
	serializedPubKey, err := pubKey.Serialize()
	if err != nil {
		t.Fatalf("Serialize public key failed: %s", err)
	}

	pubKeyBytes := serializedPubKey[:]
	staticIDRaw := blake3.Sum256(pubKeyBytes)

	cm := &ConnectionManager{
		cfg: &config.Config{
			Flags: &config.Flags{},
		},
	}
	cm.cfg.Flags.NetworkFlags.ActiveNetParams = &dagconfig.TestnetParams

	netConnection := new(netadapter.NetConnection)
	announcement := &appmessage.MsgStrongNodeAnnouncement{
		SchemaVersion:  1,
		Network:        cm.cfg.NetParams().Name,
		StaticIDRaw:    staticIDRaw[:],
		PubKeyXOnly:    pubKeyBytes,
		SeqNo:          1,
		WindowStartMs:  1_000_000,
		WindowEndMs:    1_000_500,
		FoundBlocks10m: 12,
		TotalBlocks10m: 100,
		SentAtMs:       uint64(time.Now().UnixMilli()),
	}
	preimage := buildStrongNodeAnnouncementPreimage(announcement)
	digest := blake3.Sum256(preimage)
	var secpHash secp256k1.Hash
	copy(secpHash[:], digest[:])
	signature, err := keyPair.SchnorrSign(&secpHash)
	if err != nil {
		t.Fatalf("SchnorrSign failed: %s", err)
	}
	serializedSig := signature.Serialize()
	announcement.Signature = serializedSig[:]

	strongNodeID := cm.ApplyStrongNodeAnnouncement(netConnection, announcement)
	if strongNodeID == "" {
		t.Fatalf("expected strong-node ID to be applied")
	}
	if netConnection.StrongNodeID() != strongNodeID {
		t.Fatalf("connection strong-node ID was not updated")
	}
}

func TestIsStrongNodeIDBanned(t *testing.T) {
	const strongNodeID = "89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
	cm := &ConnectionManager{
		cfg: &config.Config{
			Flags: &config.Flags{
				EnableExternalBanlist: true,
			},
		},
		externallyBannedNodeIDs: map[string]struct{}{
			strongNodeID: {},
		},
	}

	if !cm.IsStrongNodeIDBanned(strongNodeID) {
		t.Fatalf("expected strong-node ID to be banned")
	}
}
