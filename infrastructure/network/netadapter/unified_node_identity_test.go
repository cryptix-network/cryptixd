package netadapter

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestComputeUnifiedNodeIDDeterministic(t *testing.T) {
	var pub [32]byte
	for i := 0; i < len(pub); i++ {
		pub[i] = byte(i + 1)
	}
	first := computeUnifiedNodeID(pub)
	second := computeUnifiedNodeID(pub)
	if first != second {
		t.Fatalf("expected deterministic node ID")
	}
}

func TestNodePoWNonceValidation(t *testing.T) {
	var pub [32]byte
	for i := 0; i < len(pub); i++ {
		pub[i] = byte(31 - i)
	}
	nonce := mineNodePoWNonce(1, pub)
	if !isValidNodePoWNonce(1, pub, nonce) {
		t.Fatalf("expected mined nonce to be valid")
	}
	if isValidNodePoWNonce(255, pub, nonce) {
		t.Fatalf("expected invalid network code to fail validation")
	}
}

func TestLoadOrCreateUnifiedNodeIdentityPersists(t *testing.T) {
	tempDir := t.TempDir()
	identityA, err := loadOrCreateUnifiedNodeIdentity(tempDir, "cryptix-mainnet")
	if err != nil {
		t.Fatalf("loadOrCreateUnifiedNodeIdentity failed: %s", err)
	}
	identityB, err := loadOrCreateUnifiedNodeIdentity(tempDir, "cryptix-mainnet")
	if err != nil {
		t.Fatalf("loadOrCreateUnifiedNodeIdentity second call failed: %s", err)
	}
	if identityA.NodeID != identityB.NodeID {
		t.Fatalf("expected persisted node ID to stay stable across reload")
	}
	if identityA.PowNonce != identityB.PowNonce {
		t.Fatalf("expected persisted PoW nonce to stay stable across reload")
	}

	identityFile := filepath.Join(tempDir, unifiedNodeIdentityDirName, unifiedNodeIdentityFilename)
	if _, statErr := os.Stat(identityFile); statErr != nil {
		t.Fatalf("expected identity file to exist: %s", statErr)
	}
}

func TestCrossLanguageVectorsMatch(t *testing.T) {
	vectors := []struct {
		network    uint8
		pubkeyHex  string
		nodeIDHex  string
		nonce      uint64
		powHashHex string
	}{
		{
			network:    0,
			pubkeyHex:  "6d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2",
			nodeIDHex:  "1b393963bd75edc656dbc0207e35416c509d27a2bf83119c4b4f916bedbab3a2",
			nonce:      1763949,
			powHashHex: "00000bc349b49f4e4ade68388d08c61b675702a222d254d8d4411e9c5e46e1be",
		},
		{
			network:    0,
			pubkeyHex:  "5f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486",
			nodeIDHex:  "53240c1f9d4506e30994f69fbbf8feb97f3d2e0d89330cf76207b41fef73d994",
			nonce:      1297078,
			powHashHex: "00000cc9a5a11330fa7921cab2ecde7cddf9898bc90067f833bfe67c4c8f9af0",
		},
		{
			network:    1,
			pubkeyHex:  "fc10777c57060195c83e9885c790c8a26496d305b366b8e5fbf475203c680f79",
			nodeIDHex:  "e28077604051f2d4cc5218b7d57e81164203ccfb2b503b2aa0dd8fd30c19e274",
			nonce:      345502,
			powHashHex: "00003e411f41cc52438ec9dafca71e57ca44008506d3fe7535abd46229e17594",
		},
		{
			network:    2,
			pubkeyHex:  "c93b4ed533a76866a3c3ea1cc0bc3e70c0dbe32a945057b5dff95b88ce9280dd",
			nodeIDHex:  "524988b85b8b6ba0d4e24b934cc5b129c628f70609932cd4509e82eb6a22556a",
			nonce:      124967,
			powHashHex: "000015e1c263f2bb0d143105ce860e510f83a35fb8add33543ca7336e0a98c9a",
		},
		{
			network:    3,
			pubkeyHex:  "01ea552a43712c4c96771ce1e9f83a877a735b31b3e200df94c661153c7dcb4b",
			nodeIDHex:  "570a7eadd0f105a27fd5530dd175a8d8d21c38b657206afdd37e6cd644b4b84f",
			nonce:      211636,
			powHashHex: "00003cba8df2eb272709f06a05f870d71ac9f3c866f9d4ab0e2b4e1026c52aea",
		},
	}

	for _, vector := range vectors {
		pubRaw, err := hex.DecodeString(vector.pubkeyHex)
		if err != nil {
			t.Fatalf("pubkey decode failed: %s", err)
		}
		nodeIDRaw, err := hex.DecodeString(vector.nodeIDHex)
		if err != nil {
			t.Fatalf("node ID decode failed: %s", err)
		}
		powHashRaw, err := hex.DecodeString(vector.powHashHex)
		if err != nil {
			t.Fatalf("pow hash decode failed: %s", err)
		}
		var pub [32]byte
		var expectedNodeID [32]byte
		var expectedPowHash [32]byte
		copy(pub[:], pubRaw)
		copy(expectedNodeID[:], nodeIDRaw)
		copy(expectedPowHash[:], powHashRaw)

		computedNodeID := computeUnifiedNodeID(pub)
		if computedNodeID != expectedNodeID {
			t.Fatalf("unexpected node ID for vector %+v", vector)
		}
		computedPowHash := computeNodePoWHash(vector.network, pub, vector.nonce)
		if computedPowHash != expectedPowHash {
			t.Fatalf("unexpected PoW hash for vector %+v", vector)
		}
		if !isValidNodePoWNonce(vector.network, pub, vector.nonce) {
			t.Fatalf("expected nonce to validate for vector %+v", vector)
		}
	}
}
