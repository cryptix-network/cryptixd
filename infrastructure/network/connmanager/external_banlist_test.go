package connmanager

import (
	"encoding/hex"
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
			rawURL:   "https://antifraud.cryptix-network.org/api/confirmed-cases/iplist",
			expected: []string{"https://antifraud.cryptix-network.org/api/confirmed-cases/iplist", "http://antifraud.cryptix-network.org/api/confirmed-cases/iplist"},
		},
		{
			name:     "http only",
			rawURL:   "http://localhost:8080/iplist",
			expected: []string{"http://localhost:8080/iplist"},
		},
		{
			name:     "without scheme",
			rawURL:   "antifraud.cryptix-network.org/api/confirmed-cases/iplist",
			expected: []string{"https://antifraud.cryptix-network.org/api/confirmed-cases/iplist", "http://antifraud.cryptix-network.org/api/confirmed-cases/iplist"},
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

func TestDecodeExternalBanlistPayload(t *testing.T) {
	rawJSON := []byte(`{
		"status": "success",
		"ips": ["127.0.0.1", "invalid-ip", "::ffff:127.0.0.1", "2001:db8::1", "127.0.0.1"],
		"node_ids": [
			"00112233445566778899aabbccddeeff",
			"00112233445566778899AABBCCDDEEFF",
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"this-is-not-a-node-id"
		]
	}`)

	ips, nodeIDs, err := decodeExternalBanlistPayload(rawJSON)
	if err != nil {
		t.Fatalf("decodeExternalBanlistPayload unexpectedly failed: %s", err)
	}

	if len(ips) != 2 {
		t.Fatalf("unexpected IP count: got %d expected 2", len(ips))
	}
	if _, ok := ips["127.0.0.1"]; !ok {
		t.Fatalf("expected IPv4 loopback IP to be present")
	}
	if _, ok := ips["2001:db8::1"]; !ok {
		t.Fatalf("expected IPv6 IP to be present")
	}

	if len(nodeIDs) != 2 {
		t.Fatalf("unexpected node ID count: got %d expected 2", len(nodeIDs))
	}
	if _, ok := nodeIDs["00112233445566778899aabbccddeeff"]; !ok {
		t.Fatalf("expected 32-char node ID to be present")
	}
	if _, ok := nodeIDs["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]; !ok {
		t.Fatalf("expected 64-char node ID to be present")
	}
}

func TestDecodeExternalBanlistPayloadStatusError(t *testing.T) {
	_, _, err := decodeExternalBanlistPayload([]byte(`{"status":"error","ips":["127.0.0.1"]}`))
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
