package netadapter

import "testing"

func TestQuantumHandshakeMLKEM1024RoundTrip(t *testing.T) {
	na := &NetAdapter{}
	publicKey, privateKey, err := na.GenerateQuantumHandshakeKeyPair()
	if err != nil {
		t.Fatalf("GenerateQuantumHandshakeKeyPair: %s", err)
	}
	if len(publicKey) != QuantumHandshakeMLKEM1024PublicKeySize {
		t.Fatalf("unexpected public key size: got %d want %d", len(publicKey), QuantumHandshakeMLKEM1024PublicKeySize)
	}
	if len(privateKey) != QuantumHandshakeMLKEM1024PrivateKeySize {
		t.Fatalf("unexpected private key size: got %d want %d", len(privateKey), QuantumHandshakeMLKEM1024PrivateKeySize)
	}

	ciphertext, senderSharedSecret, err := na.EncapsulateQuantumHandshake(publicKey)
	if err != nil {
		t.Fatalf("EncapsulateQuantumHandshake: %s", err)
	}
	if len(ciphertext) != QuantumHandshakeMLKEM1024CiphertextSize {
		t.Fatalf("unexpected ciphertext size: got %d want %d", len(ciphertext), QuantumHandshakeMLKEM1024CiphertextSize)
	}

	receiverSharedSecret, err := na.DecapsulateQuantumHandshake(privateKey, ciphertext)
	if err != nil {
		t.Fatalf("DecapsulateQuantumHandshake: %s", err)
	}
	if senderSharedSecret != receiverSharedSecret {
		t.Fatalf("shared secret mismatch")
	}
}

func TestQuantumHandshakeProofIsNonceBound(t *testing.T) {
	na := &NetAdapter{}
	signerNodeID := [32]byte{0x11}
	verifierNodeID := [32]byte{0x22}
	sharedSecret := [QuantumHandshakeMLKEM1024SharedSecretSize]byte{0x55}

	proofA, err := na.ComputeQuantumHandshakeProof("cryptix-testnet", signerNodeID, verifierNodeID, 10, 20, sharedSecret)
	if err != nil {
		t.Fatalf("ComputeQuantumHandshakeProof A: %s", err)
	}
	proofB, err := na.ComputeQuantumHandshakeProof("cryptix-testnet", signerNodeID, verifierNodeID, 10, 20, sharedSecret)
	if err != nil {
		t.Fatalf("ComputeQuantumHandshakeProof B: %s", err)
	}
	proofC, err := na.ComputeQuantumHandshakeProof("cryptix-testnet", signerNodeID, verifierNodeID, 10, 21, sharedSecret)
	if err != nil {
		t.Fatalf("ComputeQuantumHandshakeProof C: %s", err)
	}
	if proofA != proofB {
		t.Fatalf("expected deterministic proof")
	}
	if proofA == proofC {
		t.Fatalf("expected proof change on nonce change")
	}
}

func TestQuantumHandshakeRejectsMalformedInputs(t *testing.T) {
	na := &NetAdapter{}
	if _, _, err := na.EncapsulateQuantumHandshake([]byte{1, 2, 3}); err == nil {
		t.Fatalf("expected encapsulation to fail on malformed public key")
	}
	if _, err := na.DecapsulateQuantumHandshake([]byte{1, 2, 3}, []byte{1, 2, 3}); err == nil {
		t.Fatalf("expected decapsulation to fail on malformed key/ciphertext")
	}
}
