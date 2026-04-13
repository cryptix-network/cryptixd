package netadapter

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/pkg/errors"
	"github.com/zeebo/blake3"
)

const (
	QuantumHandshakeMLKEM1024PublicKeySize    = mlkem1024.PublicKeySize
	QuantumHandshakeMLKEM1024PrivateKeySize   = mlkem1024.PrivateKeySize
	QuantumHandshakeMLKEM1024CiphertextSize   = mlkem1024.CiphertextSize
	QuantumHandshakeMLKEM1024SharedSecretSize = mlkem1024.SharedKeySize
	QuantumHandshakeProofSize                 = 32
)

const quantumHandshakeDomainTag = "cryptix-pq-mlkem1024-ready-v1"

// GenerateQuantumHandshakeKeyPair returns a fresh per-connection ML-KEM-1024 key pair.
func (na *NetAdapter) GenerateQuantumHandshakeKeyPair() ([]byte, []byte, error) {
	publicKey, privateKey, err := mlkem1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	packedPublicKey, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	packedPrivateKey, err := privateKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return packedPublicKey, packedPrivateKey, nil
}

// EncapsulateQuantumHandshake encapsulates a shared secret to the peer ML-KEM-1024 public key.
func (na *NetAdapter) EncapsulateQuantumHandshake(peerPublicKey []byte) ([]byte, [QuantumHandshakeMLKEM1024SharedSecretSize]byte, error) {
	var empty [QuantumHandshakeMLKEM1024SharedSecretSize]byte
	if len(peerPublicKey) != QuantumHandshakeMLKEM1024PublicKeySize {
		return nil, empty, errors.Errorf("peer ML-KEM-1024 public key must be exactly %d bytes", QuantumHandshakeMLKEM1024PublicKeySize)
	}

	var unpackedPublicKey mlkem1024.PublicKey
	if err := unpackedPublicKey.Unpack(peerPublicKey); err != nil {
		return nil, empty, errors.Wrap(err, "invalid peer ML-KEM-1024 public key")
	}

	ciphertext := make([]byte, QuantumHandshakeMLKEM1024CiphertextSize)
	var sharedSecret [QuantumHandshakeMLKEM1024SharedSecretSize]byte
	unpackedPublicKey.EncapsulateTo(ciphertext, sharedSecret[:], nil)
	return ciphertext, sharedSecret, nil
}

// DecapsulateQuantumHandshake decapsulates the peer ciphertext with the local ML-KEM-1024 private key.
func (na *NetAdapter) DecapsulateQuantumHandshake(
	localPrivateKey []byte,
	ciphertext []byte,
) ([QuantumHandshakeMLKEM1024SharedSecretSize]byte, error) {
	var empty [QuantumHandshakeMLKEM1024SharedSecretSize]byte
	if len(localPrivateKey) != QuantumHandshakeMLKEM1024PrivateKeySize {
		return empty, errors.Errorf("local ML-KEM-1024 private key must be exactly %d bytes", QuantumHandshakeMLKEM1024PrivateKeySize)
	}
	if len(ciphertext) != QuantumHandshakeMLKEM1024CiphertextSize {
		return empty, errors.Errorf("peer ML-KEM-1024 ciphertext must be exactly %d bytes", QuantumHandshakeMLKEM1024CiphertextSize)
	}

	var unpackedPrivateKey mlkem1024.PrivateKey
	if err := unpackedPrivateKey.Unpack(localPrivateKey); err != nil {
		return empty, errors.Wrap(err, "invalid local ML-KEM-1024 private key")
	}

	var sharedSecret [QuantumHandshakeMLKEM1024SharedSecretSize]byte
	unpackedPrivateKey.DecapsulateTo(sharedSecret[:], ciphertext)
	return sharedSecret, nil
}

// ComputeQuantumHandshakeProof binds the ML-KEM shared secret to node IDs and challenge nonces.
func (na *NetAdapter) ComputeQuantumHandshakeProof(
	networkName string,
	signerNodeID [32]byte,
	verifierNodeID [32]byte,
	signerChallengeNonce uint64,
	verifierChallengeNonce uint64,
	sharedSecret [QuantumHandshakeMLKEM1024SharedSecretSize]byte,
) ([QuantumHandshakeProofSize]byte, error) {
	var empty [QuantumHandshakeProofSize]byte
	networkCode, err := networkCodeFromName(networkName)
	if err != nil {
		return empty, err
	}

	payload := make([]byte, 0, len(quantumHandshakeDomainTag)+1+32+32+8+8+QuantumHandshakeMLKEM1024SharedSecretSize)
	payload = append(payload, []byte(quantumHandshakeDomainTag)...)
	payload = append(payload, networkCode)
	payload = append(payload, signerNodeID[:]...)
	payload = append(payload, verifierNodeID[:]...)
	var nonceBytes [8]byte
	binary.BigEndian.PutUint64(nonceBytes[:], signerChallengeNonce)
	payload = append(payload, nonceBytes[:]...)
	binary.BigEndian.PutUint64(nonceBytes[:], verifierChallengeNonce)
	payload = append(payload, nonceBytes[:]...)
	payload = append(payload, sharedSecret[:]...)

	sum := blake3.Sum256(payload)
	var proof [QuantumHandshakeProofSize]byte
	copy(proof[:], sum[:])
	return proof, nil
}
