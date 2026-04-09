package protowire

import (
	"errors"
	"testing"
)

func TestToAppMessageUnknownPayload(t *testing.T) {
	message := &CryptixdMessage{}
	_, err := message.ToAppMessage()
	if !errors.Is(err, ErrUnknownMessagePayload) {
		t.Fatalf("expected ErrUnknownMessagePayload, got %v", err)
	}
}
