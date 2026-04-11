package appmessage

import "time"

type baseMessage struct {
	messageNumber uint64
	receivedAt    time.Time
	requestID     uint32
	responseID    uint32
}

func (b *baseMessage) MessageNumber() uint64 {
	return b.messageNumber
}

func (b *baseMessage) SetMessageNumber(messageNumber uint64) {
	b.messageNumber = messageNumber
}

func (b *baseMessage) ReceivedAt() time.Time {
	return b.receivedAt
}

func (b *baseMessage) SetReceivedAt(receivedAt time.Time) {
	b.receivedAt = receivedAt
}

func (b *baseMessage) RequestID() uint32 {
	return b.requestID
}

func (b *baseMessage) SetRequestID(requestID uint32) {
	b.requestID = requestID
}

func (b *baseMessage) ResponseID() uint32 {
	return b.responseID
}

func (b *baseMessage) SetResponseID(responseID uint32) {
	b.responseID = responseID
}
