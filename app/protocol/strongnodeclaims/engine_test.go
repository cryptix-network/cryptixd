package strongnodeclaims

import (
	"encoding/hex"
	"testing"

	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter"
	secp256k1 "github.com/cryptix-network/go-secp256k1"
)

func TestPendingClaimPromotionAndRestartRebuild(t *testing.T) {
	tempDir := t.TempDir()
	engine := New(true, "cryptix-mainnet", tempDir)

	const (
		privKeyHex   = "9e335f14f1a549c374a273b014e4e6658c666b9be6bb7478085510abcba7fae2"
		blockHashHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	)
	claim := mustBuildSignedClaim(t, 0, privKeyHex, blockHashHex)

	outcome := engine.IngestClaim(claim, true, false)
	if outcome.Status != IngestAccepted || !outcome.Pending {
		t.Fatalf("expected pending accepted claim, got %+v", outcome)
	}
	if snapshot := engine.Snapshot(true); len(snapshot.Entries) != 0 {
		t.Fatalf("expected no scored entries before window promotion, got %d", len(snapshot.Entries))
	}

	blockHash, err := externalapi.NewDomainHashFromByteSlice(claim.BlockHash)
	if err != nil {
		t.Fatalf("invalid block hash in claim: %s", err)
	}
	engine.ApplyChainPathUpdate(
		&externalapi.SelectedChainPath{Added: []*externalapi.DomainHash{blockHash}},
		blockHash,
		true,
	)
	engine.BestEffortFlush()

	snapshot := engine.Snapshot(true)
	if len(snapshot.Entries) != 1 {
		t.Fatalf("expected one scored entry after promotion, got %d", len(snapshot.Entries))
	}
	if snapshot.Entries[0].ClaimedBlocks != 1 {
		t.Fatalf("expected claimed_blocks=1, got %d", snapshot.Entries[0].ClaimedBlocks)
	}

	reloaded := New(true, "cryptix-mainnet", tempDir)
	reloadedSnapshot := reloaded.Snapshot(true)
	if len(reloadedSnapshot.Entries) != 1 {
		t.Fatalf("expected one scored entry after reload, got %d", len(reloadedSnapshot.Entries))
	}
	if reloadedSnapshot.Entries[0].ClaimedBlocks != 1 {
		t.Fatalf("expected claimed_blocks=1 after reload, got %d", reloadedSnapshot.Entries[0].ClaimedBlocks)
	}
}

func TestApplyChainPathUpdateRemovesClaimStateForRemovedBlocks(t *testing.T) {
	tempDir := t.TempDir()
	engine := New(true, "cryptix-mainnet", tempDir)

	const (
		privKeyHex   = "9e335f14f1a549c374a273b014e4e6658c666b9be6bb7478085510abcba7fae2"
		blockHashHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	claim := mustBuildSignedClaim(t, 0, privKeyHex, blockHashHex)
	blockHash, err := externalapi.NewDomainHashFromByteSlice(claim.BlockHash)
	if err != nil {
		t.Fatalf("invalid block hash in claim: %s", err)
	}

	outcome := engine.IngestClaim(claim, true, true)
	if outcome.Status != IngestAccepted || outcome.Pending {
		t.Fatalf("expected accepted known claim, got %+v", outcome)
	}

	engine.ApplyChainPathUpdate(
		&externalapi.SelectedChainPath{Added: []*externalapi.DomainHash{blockHash}},
		blockHash,
		true,
	)
	engine.ApplyChainPathUpdate(
		&externalapi.SelectedChainPath{Removed: []*externalapi.DomainHash{blockHash}},
		blockHash,
		true,
	)

	key := *blockHash.ByteArray()
	engine.mu.Lock()
	defer engine.mu.Unlock()

	if _, ok := engine.state.WindowSet[key]; ok {
		t.Fatalf("expected removed block to be absent from window set")
	}
	if _, ok := engine.state.RetentionSet[key]; ok {
		t.Fatalf("expected removed block to be absent from retention set")
	}
	if _, ok := engine.state.RecentClaimsByBlock[key]; ok {
		t.Fatalf("expected removed block to be absent from recent claims map")
	}
	if _, ok := engine.state.WinningClaimByBlock[key]; ok {
		t.Fatalf("expected removed block to be absent from winning claims map")
	}
	if _, ok := engine.state.PendingUnknownClaims[key]; ok {
		t.Fatalf("expected removed block to be absent from pending claims map")
	}
	if len(engine.state.ScoreByNodeID) != 0 {
		t.Fatalf("expected no scores after removing the only claimed block, got %d", len(engine.state.ScoreByNodeID))
	}
}

func mustBuildSignedClaim(t *testing.T, network uint8, privKeyHex, blockHashHex string) *appmessage.MsgBlockProducerClaimV1 {
	t.Helper()
	var privKey [32]byte
	privRaw, err := hex.DecodeString(privKeyHex)
	if err != nil || len(privRaw) != 32 {
		t.Fatalf("invalid private key hex %q", privKeyHex)
	}
	copy(privKey[:], privRaw)

	var blockHash [32]byte
	blockRaw, err := hex.DecodeString(blockHashHex)
	if err != nil || len(blockRaw) != 32 {
		t.Fatalf("invalid block hash hex %q", blockHashHex)
	}
	copy(blockHash[:], blockRaw)

	keyPair, err := secp256k1.DeserializeSchnorrPrivateKeyFromSlice(privKey[:])
	if err != nil {
		t.Fatalf("failed decoding private key: %s", err)
	}
	pubKey, err := keyPair.SchnorrPublicKey()
	if err != nil {
		t.Fatalf("failed deriving pubkey: %s", err)
	}
	pubSerialized, err := pubKey.Serialize()
	if err != nil {
		t.Fatalf("failed serializing pubkey: %s", err)
	}

	var pubKeyXOnly [32]byte
	copy(pubKeyXOnly[:], pubSerialized[:])
	nodeID := netadapter.ComputeUnifiedNodeID(pubKeyXOnly)
	claimDigest := netadapter.ComputeBlockProducerClaimDigest(network, blockHash, nodeID)

	var secpHash secp256k1.Hash
	copy(secpHash[:], claimDigest[:])
	signature, err := keyPair.SchnorrSign(&secpHash)
	if err != nil {
		t.Fatalf("failed signing claim digest: %s", err)
	}
	signatureSerialized := signature.Serialize()

	return &appmessage.MsgBlockProducerClaimV1{
		SchemaVersion:   uint32(claimSchemaVersion),
		Network:         uint32(network),
		BlockHash:       append([]byte(nil), blockHash[:]...),
		NodePubkeyXOnly: append([]byte(nil), pubKeyXOnly[:]...),
		Signature:       append([]byte(nil), signatureSerialized[:]...),
	}
}
