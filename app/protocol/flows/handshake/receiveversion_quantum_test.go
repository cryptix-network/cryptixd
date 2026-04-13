package handshake

import (
	"testing"

	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter"
)

func TestValidatePeerQuantumHandshakePubKey(t *testing.T) {
	valid := make([]byte, netadapter.QuantumHandshakeMLKEM1024PublicKeySize)

	key, err := validatePeerQuantumHandshakePubKey(&appmessage.MsgVersion{PQMLKEM1024PubKey: valid}, true)
	if err != nil {
		t.Fatalf("expected success for valid required key, got error: %s", err)
	}
	if len(key) != len(valid) {
		t.Fatalf("unexpected key length: got %d want %d", len(key), len(valid))
	}

	key, err = validatePeerQuantumHandshakePubKey(&appmessage.MsgVersion{}, false)
	if err != nil {
		t.Fatalf("expected success for missing optional key, got error: %s", err)
	}
	if len(key) != 0 {
		t.Fatalf("expected empty key for optional missing field, got %d bytes", len(key))
	}

	if _, err = validatePeerQuantumHandshakePubKey(&appmessage.MsgVersion{}, true); err == nil {
		t.Fatalf("expected error for missing required key")
	}

	if _, err = validatePeerQuantumHandshakePubKey(&appmessage.MsgVersion{PQMLKEM1024PubKey: []byte{1, 2, 3}}, false); err == nil {
		t.Fatalf("expected error for malformed key size")
	}
}
