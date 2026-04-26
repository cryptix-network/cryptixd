package strongnodeclaims

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter"
)

type claimVector struct {
	Name           string `json:"name"`
	NetworkU8      uint8  `json:"network_u8"`
	BlockHashHex   string `json:"block_hash_hex"`
	PubKeyXOnlyHex string `json:"pubkey_xonly_hex"`
	NodeIDHex      string `json:"node_id_hex"`
	ClaimDigestHex string `json:"claim_digest_hex"`
	SignatureHex   string `json:"signature_hex"`
}

func TestLockedConstants(t *testing.T) {
	if CLAIM_WINDOW_SIZE_BLOCKS != 1000 {
		t.Fatalf("CLAIM_WINDOW_SIZE_BLOCKS mismatch: got %d", CLAIM_WINDOW_SIZE_BLOCKS)
	}
	if CLAIM_REORG_MARGIN_BLOCKS != 256 {
		t.Fatalf("CLAIM_REORG_MARGIN_BLOCKS mismatch: got %d", CLAIM_REORG_MARGIN_BLOCKS)
	}
	if KNOWN_CLAIMS_PER_BLOCK_CAP != 64 {
		t.Fatalf("KNOWN_CLAIMS_PER_BLOCK_CAP mismatch: got %d", KNOWN_CLAIMS_PER_BLOCK_CAP)
	}
	if PENDING_UNKNOWN_CLAIMS_CAP != 4096 {
		t.Fatalf("PENDING_UNKNOWN_CLAIMS_CAP mismatch: got %d", PENDING_UNKNOWN_CLAIMS_CAP)
	}
	if PENDING_UNKNOWN_CLAIMS_TTL_SECONDS != 180 {
		t.Fatalf("PENDING_UNKNOWN_CLAIMS_TTL_SECONDS mismatch: got %d", PENDING_UNKNOWN_CLAIMS_TTL_SECONDS)
	}
}

func TestCrossLanguageVectors(t *testing.T) {
	vectorsPath := filepath.Join("..", "..", "..", "docs", "strong_node_claimant_hf_v1_1_vectors.json")
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("failed reading vectors file %s: %s", vectorsPath, err)
	}

	var vectors []claimVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("failed decoding vectors JSON: %s", err)
	}
	if len(vectors) < 5 {
		t.Fatalf("expected at least 5 vectors, got %d", len(vectors))
	}

	for _, vector := range vectors {
		blockHash := mustDecodeHex32(t, vector.BlockHashHex)
		pubKey := mustDecodeHex32(t, vector.PubKeyXOnlyHex)
		expectedNodeID := mustDecodeHex32(t, vector.NodeIDHex)
		expectedDigest := mustDecodeHex32(t, vector.ClaimDigestHex)
		signature := mustDecodeHex64(t, vector.SignatureHex)

		nodeID := netadapter.ComputeUnifiedNodeID(pubKey)
		if nodeID != expectedNodeID {
			t.Fatalf("%s: node_id mismatch: got %x expected %x", vector.Name, nodeID, expectedNodeID)
		}

		claimDigest := netadapter.ComputeBlockProducerClaimDigest(vector.NetworkU8, blockHash, nodeID)
		if claimDigest != expectedDigest {
			t.Fatalf("%s: claim_digest mismatch: got %x expected %x", vector.Name, claimDigest, expectedDigest)
		}

		if !netadapter.VerifyBlockProducerClaimSignature(pubKey, claimDigest, signature) {
			t.Fatalf("%s: signature verification failed", vector.Name)
		}
	}
}

func mustDecodeHex32(t *testing.T, value string) [32]byte {
	t.Helper()
	var out [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("invalid hex value %q: %s", value, err)
	}
	if len(decoded) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(decoded))
	}
	copy(out[:], decoded)
	return out
}

func mustDecodeHex64(t *testing.T, value string) [64]byte {
	t.Helper()
	var out [64]byte
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("invalid hex value %q: %s", value, err)
	}
	if len(decoded) != 64 {
		t.Fatalf("expected 64 bytes, got %d", len(decoded))
	}
	copy(out[:], decoded)
	return out
}
