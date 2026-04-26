package netadapter

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	secp256k1 "github.com/cryptix-network/go-secp256k1"
	"github.com/pkg/errors"
	"github.com/zeebo/blake3"
)

const (
	// BlockProducerClaimSchemaVersion defines claimant payload schema.
	BlockProducerClaimSchemaVersion = uint32(1)
	claimDigestDomainTag            = "cryptix-block-claim-v1"
)

// ComputeBlockProducerClaimDigest computes:
// BLAKE3-256("cryptix-block-claim-v1" || network_u8 || block_hash || node_id)
func ComputeBlockProducerClaimDigest(networkCode uint8, blockHash [32]byte, nodeID [32]byte) [32]byte {
	payload := make([]byte, 0, len(claimDigestDomainTag)+1+32+32)
	payload = append(payload, []byte(claimDigestDomainTag)...)
	payload = append(payload, networkCode)
	payload = append(payload, blockHash[:]...)
	payload = append(payload, nodeID[:]...)
	return blake3.Sum256(payload)
}

// VerifyBlockProducerClaimSignature verifies a BIP340 Schnorr signature directly over the 32-byte claim digest.
func VerifyBlockProducerClaimSignature(pubkeyXOnly [32]byte, claimDigest [32]byte, signature [64]byte) bool {
	pubKey, err := secp256k1.DeserializeSchnorrPubKey(pubkeyXOnly[:])
	if err != nil {
		return false
	}
	signatureObj, err := secp256k1.DeserializeSchnorrSignatureFromSlice(signature[:])
	if err != nil {
		return false
	}
	var secpHash secp256k1.Hash
	copy(secpHash[:], claimDigest[:])
	return pubKey.SchnorrVerify(&secpHash, signatureObj)
}

func signBlockProducerClaimDigest(identity *UnifiedNodeIdentity, claimDigest [32]byte) ([64]byte, error) {
	var empty [64]byte
	if identity == nil {
		return empty, errors.New("unified node identity is not initialized")
	}
	keyPair, err := secp256k1.DeserializeSchnorrPrivateKeyFromSlice(identity.PrivateKey[:])
	if err != nil {
		return empty, err
	}
	var secpHash secp256k1.Hash
	copy(secpHash[:], claimDigest[:])
	signature, err := keyPair.SchnorrSign(&secpHash)
	if err != nil {
		return empty, err
	}
	serialized := signature.Serialize()
	var out [64]byte
	copy(out[:], serialized[:])
	return out, nil
}

// BuildBlockProducerClaim builds and signs a local claimant payload for the given block hash.
func (na *NetAdapter) BuildBlockProducerClaim(networkName string, blockHash *externalapi.DomainHash) (*appmessage.MsgBlockProducerClaimV1, error) {
	if na.unifiedNodeIdentity == nil {
		return nil, errors.New("unified node identity is not initialized")
	}
	if blockHash == nil {
		return nil, errors.New("block hash is nil")
	}
	networkCode, err := networkCodeFromName(networkName)
	if err != nil {
		return nil, err
	}

	blockHashArray := *blockHash.ByteArray()
	nodeID := computeUnifiedNodeID(na.unifiedNodeIdentity.PubKeyXOnly)
	powNonce := na.unifiedNodeIdentity.PowNonce
	claimDigest := ComputeBlockProducerClaimDigest(networkCode, blockHashArray, nodeID)
	signature, err := signBlockProducerClaimDigest(na.unifiedNodeIdentity, claimDigest)
	if err != nil {
		return nil, err
	}

	return &appmessage.MsgBlockProducerClaimV1{
		SchemaVersion:   BlockProducerClaimSchemaVersion,
		Network:         uint32(networkCode),
		BlockHash:       append([]byte(nil), blockHashArray[:]...),
		NodePubkeyXOnly: append([]byte(nil), na.unifiedNodeIdentity.PubKeyXOnly[:]...),
		NodePowNonce:    &powNonce,
		Signature:       append([]byte(nil), signature[:]...),
	}, nil
}
