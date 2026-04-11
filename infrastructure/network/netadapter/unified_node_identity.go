package netadapter

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	secp256k1 "github.com/cryptix-network/go-secp256k1"
	"github.com/pkg/errors"
	"github.com/zeebo/blake3"
)

const (
	unifiedNodeIdentitySchemaVersion = 1
	unifiedNodeIdentityDirName       = "strong-nodes"
	unifiedNodeIdentityFilename      = "node_identity.json"
	unifiedNodeIdentityFileMaxBytes  = 16 * 1024
	unifiedNodeIDHexLength           = 64
	nodePoWDomainTag                 = "cryptix-node-id-pow-v1"
	nodeAuthDomainTag                = "cryptix-node-id-auth-v1"
	mainnetNodePoWDifficulty         = 20
	nonMainnetNodePoWDifficulty      = 18
)

type UnifiedNodeIdentity struct {
	PrivateKey  [32]byte
	PubKeyXOnly [32]byte
	NodeID      [32]byte
	PowNonce    uint64
}

type unifiedNodeIdentityDisk struct {
	SchemaVersion  uint32  `json:"schema_version"`
	SecretKey      string  `json:"secret_key"`
	PublicKeyXOnly string  `json:"public_key_xonly"`
	StaticIDRaw    string  `json:"static_id_raw"`
	LastSeqNo      uint64  `json:"last_seq_no"`
	PowNonce       *uint64 `json:"pow_nonce,omitempty"`
}

func loadOrCreateUnifiedNodeIdentity(appDir string, networkName string) (*UnifiedNodeIdentity, error) {
	networkCode, err := networkCodeFromName(networkName)
	if err != nil {
		return nil, err
	}

	identityDir := filepath.Join(appDir, unifiedNodeIdentityDirName)
	if err := os.MkdirAll(identityDir, 0o700); err != nil {
		return nil, errors.Wrap(err, "failed creating unified node identity directory")
	}

	identityFile := filepath.Join(identityDir, unifiedNodeIdentityFilename)
	if identity, err := loadUnifiedNodeIdentity(identityFile, networkCode); err == nil {
		return identity, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		quarantinePath := identityFile + fmt.Sprintf(".corrupt-%d", time.Now().UnixMilli())
		_ = os.Rename(identityFile, quarantinePath)
	}

	return createAndPersistUnifiedNodeIdentity(identityFile, networkCode)
}

func createEphemeralUnifiedNodeIdentity(networkName string) (*UnifiedNodeIdentity, error) {
	networkCode, err := networkCodeFromName(networkName)
	if err != nil {
		return nil, err
	}
	keyPair, err := secp256k1.GenerateSchnorrKeyPair()
	if err != nil {
		return nil, err
	}
	pub, err := keyPair.SchnorrPublicKey()
	if err != nil {
		return nil, err
	}
	pubSerialized, err := pub.Serialize()
	if err != nil {
		return nil, err
	}
	privSerialized := keyPair.SerializePrivateKey()
	var privateKey [32]byte
	copy(privateKey[:], privSerialized[:])
	var pubKeyXOnly [32]byte
	copy(pubKeyXOnly[:], pubSerialized[:])
	nodeID := computeUnifiedNodeID(pubKeyXOnly)
	powNonce := mineNodePoWNonce(networkCode, pubKeyXOnly)
	return &UnifiedNodeIdentity{
		PrivateKey:  privateKey,
		PubKeyXOnly: pubKeyXOnly,
		NodeID:      nodeID,
		PowNonce:    powNonce,
	}, nil
}

func loadUnifiedNodeIdentity(identityFile string, networkCode uint8) (*UnifiedNodeIdentity, error) {
	raw, err := os.ReadFile(identityFile)
	if err != nil {
		return nil, err
	}
	if len(raw) > unifiedNodeIdentityFileMaxBytes {
		return nil, errors.Errorf("identity file exceeded max size of %d bytes", unifiedNodeIdentityFileMaxBytes)
	}

	var disk unifiedNodeIdentityDisk
	if err := json.Unmarshal(raw, &disk); err != nil {
		return nil, errors.Wrap(err, "invalid unified node identity JSON")
	}
	if disk.SchemaVersion != unifiedNodeIdentitySchemaVersion {
		return nil, errors.Errorf("unsupported unified node identity schema version %d", disk.SchemaVersion)
	}

	privateKeyBytes, err := decodeHex32(disk.SecretKey)
	if err != nil {
		return nil, errors.Wrap(err, "invalid secret_key")
	}
	keyPair, err := secp256k1.DeserializeSchnorrPrivateKeyFromSlice(privateKeyBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "invalid secret_key")
	}
	pub, err := keyPair.SchnorrPublicKey()
	if err != nil {
		return nil, err
	}
	pubSerialized, err := pub.Serialize()
	if err != nil {
		return nil, err
	}
	var expectedPub [32]byte
	copy(expectedPub[:], pubSerialized[:])
	storedPub, err := decodeHex32(disk.PublicKeyXOnly)
	if err != nil {
		return nil, errors.Wrap(err, "invalid public_key_xonly")
	}
	if storedPub != expectedPub {
		return nil, errors.New("public_key_xonly does not match secret key")
	}

	storedNodeID, err := decodeHex32(disk.StaticIDRaw)
	if err != nil {
		return nil, errors.Wrap(err, "invalid static_id_raw")
	}
	nodeID := computeUnifiedNodeID(storedPub)
	if storedNodeID != nodeID {
		return nil, errors.New("static_id_raw does not match blake3(public_key_xonly)")
	}

	powNonce := uint64(0)
	if disk.PowNonce != nil {
		powNonce = *disk.PowNonce
	}
	if !isValidNodePoWNonce(networkCode, storedPub, powNonce) {
		powNonce = mineNodePoWNonce(networkCode, storedPub)
		disk.PowNonce = &powNonce
		if err := persistUnifiedNodeIdentity(identityFile, &disk); err != nil {
			return nil, err
		}
	}

	return &UnifiedNodeIdentity{
		PrivateKey:  privateKeyBytes,
		PubKeyXOnly: storedPub,
		NodeID:      nodeID,
		PowNonce:    powNonce,
	}, nil
}

func createAndPersistUnifiedNodeIdentity(identityFile string, networkCode uint8) (*UnifiedNodeIdentity, error) {
	keyPair, err := secp256k1.GenerateSchnorrKeyPair()
	if err != nil {
		return nil, err
	}
	pub, err := keyPair.SchnorrPublicKey()
	if err != nil {
		return nil, err
	}
	pubSerialized, err := pub.Serialize()
	if err != nil {
		return nil, err
	}

	privSerialized := keyPair.SerializePrivateKey()
	var privateKey [32]byte
	copy(privateKey[:], privSerialized[:])
	var pubKeyXOnly [32]byte
	copy(pubKeyXOnly[:], pubSerialized[:])
	nodeID := computeUnifiedNodeID(pubKeyXOnly)
	powNonce := mineNodePoWNonce(networkCode, pubKeyXOnly)

	disk := &unifiedNodeIdentityDisk{
		SchemaVersion:  unifiedNodeIdentitySchemaVersion,
		SecretKey:      hex.EncodeToString(privateKey[:]),
		PublicKeyXOnly: hex.EncodeToString(pubKeyXOnly[:]),
		StaticIDRaw:    hex.EncodeToString(nodeID[:]),
		LastSeqNo:      0,
		PowNonce:       &powNonce,
	}
	if err := persistUnifiedNodeIdentity(identityFile, disk); err != nil {
		return nil, err
	}

	return &UnifiedNodeIdentity{
		PrivateKey:  privateKey,
		PubKeyXOnly: pubKeyXOnly,
		NodeID:      nodeID,
		PowNonce:    powNonce,
	}, nil
}

func persistUnifiedNodeIdentity(identityFile string, disk *unifiedNodeIdentityDisk) error {
	tmpFile := identityFile + ".tmp"
	serialized, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}
	serialized = append(serialized, '\n')
	if err := os.WriteFile(tmpFile, serialized, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpFile, identityFile); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}
	return nil
}

func networkCodeFromName(name string) (uint8, error) {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch {
	case lower == "mainnet" || lower == "cryptix-mainnet":
		return 0, nil
	case lower == "testnet" || lower == "cryptix-testnet" || strings.HasPrefix(lower, "testnet-") || strings.HasPrefix(lower, "cryptix-testnet-"):
		return 1, nil
	case lower == "devnet" || lower == "cryptix-devnet":
		return 2, nil
	case lower == "simnet" || lower == "cryptix-simnet":
		return 3, nil
	default:
		return 0, errors.Errorf("unsupported network name %q", name)
	}
}

// UnifiedNodeNetworkCodeFromName resolves the canonical unified-node network code.
func UnifiedNodeNetworkCodeFromName(name string) (uint8, error) {
	return networkCodeFromName(name)
}

func nodePoWDifficulty(networkCode uint8) (uint8, bool) {
	switch networkCode {
	case 0:
		return mainnetNodePoWDifficulty, true
	case 1, 2, 3:
		return nonMainnetNodePoWDifficulty, true
	default:
		return 0, false
	}
}

func computeUnifiedNodeID(pubKeyXOnly [32]byte) [32]byte {
	return blake3.Sum256(pubKeyXOnly[:])
}

// ComputeUnifiedNodeID computes the unified node identifier from x-only pubkey bytes.
func ComputeUnifiedNodeID(pubKeyXOnly [32]byte) [32]byte {
	return computeUnifiedNodeID(pubKeyXOnly)
}

func computeNodePoWHash(networkCode uint8, pubKeyXOnly [32]byte, powNonce uint64) [32]byte {
	hasher := sha256.New()
	hasher.Write([]byte(nodePoWDomainTag))
	hasher.Write([]byte{networkCode})
	hasher.Write(pubKeyXOnly[:])
	var nonceBytes [8]byte
	nonceBytes[0] = byte(powNonce >> 56)
	nonceBytes[1] = byte(powNonce >> 48)
	nonceBytes[2] = byte(powNonce >> 40)
	nonceBytes[3] = byte(powNonce >> 32)
	nonceBytes[4] = byte(powNonce >> 24)
	nonceBytes[5] = byte(powNonce >> 16)
	nonceBytes[6] = byte(powNonce >> 8)
	nonceBytes[7] = byte(powNonce)
	hasher.Write(nonceBytes[:])

	var out [32]byte
	copy(out[:], hasher.Sum(nil))
	return out
}

func computeNodeAuthHash(
	networkCode uint8,
	signerNodeID [32]byte,
	verifierNodeID [32]byte,
	signerChallengeNonce uint64,
	verifierChallengeNonce uint64,
) [32]byte {
	payload := make([]byte, 0, len(nodeAuthDomainTag)+1+32+32+8+8)
	payload = append(payload, []byte(nodeAuthDomainTag)...)
	payload = append(payload, networkCode)
	payload = append(payload, signerNodeID[:]...)
	payload = append(payload, verifierNodeID[:]...)
	var nonceBytes [8]byte
	binary.BigEndian.PutUint64(nonceBytes[:], signerChallengeNonce)
	payload = append(payload, nonceBytes[:]...)
	binary.BigEndian.PutUint64(nonceBytes[:], verifierChallengeNonce)
	payload = append(payload, nonceBytes[:]...)
	return blake3.Sum256(payload)
}

func signUnifiedNodeAuthProof(
	identity *UnifiedNodeIdentity,
	networkCode uint8,
	verifierNodeID [32]byte,
	signerChallengeNonce uint64,
	verifierChallengeNonce uint64,
) ([64]byte, error) {
	var empty [64]byte
	if identity == nil {
		return empty, errors.New("unified node identity is nil")
	}
	keyPair, err := secp256k1.DeserializeSchnorrPrivateKeyFromSlice(identity.PrivateKey[:])
	if err != nil {
		return empty, err
	}
	digest := computeNodeAuthHash(networkCode, identity.NodeID, verifierNodeID, signerChallengeNonce, verifierChallengeNonce)
	var secpHash secp256k1.Hash
	copy(secpHash[:], digest[:])
	signature, err := keyPair.SchnorrSign(&secpHash)
	if err != nil {
		return empty, err
	}
	serialized := signature.Serialize()
	var out [64]byte
	copy(out[:], serialized[:])
	return out, nil
}

func verifyUnifiedNodeAuthProof(
	networkCode uint8,
	signerPubKeyXOnly [32]byte,
	signerNodeID [32]byte,
	verifierNodeID [32]byte,
	signerChallengeNonce uint64,
	verifierChallengeNonce uint64,
	signature [64]byte,
) bool {
	pubKey, err := secp256k1.DeserializeSchnorrPubKey(signerPubKeyXOnly[:])
	if err != nil {
		return false
	}
	signatureObj, err := secp256k1.DeserializeSchnorrSignatureFromSlice(signature[:])
	if err != nil {
		return false
	}
	digest := computeNodeAuthHash(networkCode, signerNodeID, verifierNodeID, signerChallengeNonce, verifierChallengeNonce)
	var secpHash secp256k1.Hash
	copy(secpHash[:], digest[:])
	return pubKey.SchnorrVerify(&secpHash, signatureObj)
}

func leadingZeroBits(hash [32]byte) uint8 {
	var bits uint8
	for _, value := range hash {
		if value == 0 {
			bits += 8
			continue
		}
		for i := 7; i >= 0; i-- {
			if (value & (1 << uint(i))) != 0 {
				return bits
			}
			bits++
		}
		return bits
	}
	return bits
}

func isValidNodePoWNonce(networkCode uint8, pubKeyXOnly [32]byte, powNonce uint64) bool {
	required, ok := nodePoWDifficulty(networkCode)
	if !ok {
		return false
	}
	return leadingZeroBits(computeNodePoWHash(networkCode, pubKeyXOnly, powNonce)) >= required
}

// IsValidUnifiedNodePoWNonce validates the handshake PoW nonce for the given network.
func IsValidUnifiedNodePoWNonce(networkCode uint8, pubKeyXOnly [32]byte, powNonce uint64) bool {
	return isValidNodePoWNonce(networkCode, pubKeyXOnly, powNonce)
}

func mineNodePoWNonce(networkCode uint8, pubKeyXOnly [32]byte) uint64 {
	var nonce uint64
	for {
		if isValidNodePoWNonce(networkCode, pubKeyXOnly, nonce) {
			return nonce
		}
		nonce++
	}
}

func decodeHex32(raw string) ([32]byte, error) {
	var out [32]byte
	cleaned := strings.TrimSpace(raw)
	if len(cleaned) != unifiedNodeIDHexLength {
		return out, errors.Errorf("expected %d hex chars", unifiedNodeIDHexLength)
	}
	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return out, err
	}
	copy(out[:], decoded)
	return out, nil
}
