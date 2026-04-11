package addressmanager

import (
	"encoding/binary"
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/util/mstime"
	"net"
	"reflect"
	"testing"
)

func TestAddressKeySerialization(t *testing.T) {
	addressManager, teardown := newAddressManagerForTest(t, "TestAddressKeySerialization")
	defer teardown()
	addressStore := addressManager.store

	testAddress := &appmessage.NetAddress{IP: net.ParseIP("2602:100:abcd::102"), Port: 12345}
	testAddressKey := netAddressKey(testAddress)

	serializedTestAddressKey := addressStore.serializeAddressKey(testAddressKey)
	deserializedTestAddressKey := addressStore.deserializeAddressKey(serializedTestAddressKey)
	if !reflect.DeepEqual(testAddressKey, deserializedTestAddressKey) {
		t.Fatalf("testAddressKey and deserializedTestAddressKey are not equal\n"+
			"testAddressKey:%+v\ndeserializedTestAddressKey:%+v", testAddressKey, deserializedTestAddressKey)
	}
}

func TestAddressSerialization(t *testing.T) {
	addressManager, teardown := newAddressManagerForTest(t, "TestAddressSerialization")
	defer teardown()
	addressStore := addressManager.store

	testAddress := &address{
		netAddress: &appmessage.NetAddress{
			IP:        net.ParseIP("2602:100:abcd::102"),
			Port:      12345,
			Timestamp: mstime.Now(),
		},
		connectionFailedCount: 98465,
	}

	serializedTestAddress := addressStore.serializeAddress(testAddress)
	deserializedTestAddress := addressStore.deserializeAddress(serializedTestAddress)
	if !reflect.DeepEqual(testAddress, deserializedTestAddress) {
		t.Fatalf("testAddress and deserializedTestAddress are not equal\n"+
			"testAddress:%+v\ndeserializedTestAddress:%+v", testAddress, deserializedTestAddress)
	}
}

func TestDeserializeAddressLegacySerialization(t *testing.T) {
	addressManager, teardown := newAddressManagerForTest(t, "TestDeserializeAddressLegacySerialization")
	defer teardown()
	addressStore := addressManager.store

	testIP := net.ParseIP("2602:100:abcd::102").To16()
	testPort := uint16(12345)
	testTimestamp := mstime.Now()
	testFailedCount := uint64(98465)
	serializedTestAddress := make([]byte, serializedAddressLegacySize)
	copy(serializedTestAddress[:], testIP)
	binary.LittleEndian.PutUint16(serializedTestAddress[16:], testPort)
	binary.LittleEndian.PutUint64(serializedTestAddress[18:], uint64(testTimestamp.UnixMilliseconds()))
	binary.LittleEndian.PutUint64(serializedTestAddress[26:], testFailedCount)

	deserializedTestAddress := addressStore.deserializeAddress(serializedTestAddress)
	if !deserializedTestAddress.netAddress.IP.Equal(testIP) {
		t.Fatalf("Unexpected IP. Want: %s, got: %s", testIP, deserializedTestAddress.netAddress.IP)
	}
	if deserializedTestAddress.netAddress.Port != testPort {
		t.Fatalf("Unexpected port. Want: %d, got: %d", testPort, deserializedTestAddress.netAddress.Port)
	}
	if deserializedTestAddress.netAddress.Timestamp.UnixMilliseconds() != testTimestamp.UnixMilliseconds() {
		t.Fatalf("Unexpected timestamp. Want: %d, got: %d",
			testTimestamp.UnixMilliseconds(), deserializedTestAddress.netAddress.Timestamp.UnixMilliseconds())
	}
	if deserializedTestAddress.connectionFailedCount != testFailedCount {
		t.Fatalf("Unexpected failed count. Want: %d, got: %d", testFailedCount, deserializedTestAddress.connectionFailedCount)
	}
	if deserializedTestAddress.verified {
		t.Fatalf("Legacy serialized address unexpectedly marked as verified")
	}
}

func TestDeserializeAddressShortInput(t *testing.T) {
	addressManager, teardown := newAddressManagerForTest(t, "TestDeserializeAddressShortInput")
	defer teardown()
	addressStore := addressManager.store

	testIP := net.ParseIP("2602:100:abcd::102").To16()
	serializedTestAddress := make([]byte, net.IPv6len+1)
	copy(serializedTestAddress[:], testIP)

	deserializedTestAddress := addressStore.deserializeAddress(serializedTestAddress)
	if !deserializedTestAddress.netAddress.IP.Equal(testIP) {
		t.Fatalf("Unexpected IP. Want: %s, got: %s", testIP, deserializedTestAddress.netAddress.IP)
	}
	if deserializedTestAddress.netAddress.Port != 0 {
		t.Fatalf("Unexpected port. Want: 0, got: %d", deserializedTestAddress.netAddress.Port)
	}
	if !deserializedTestAddress.netAddress.Timestamp.IsZero() {
		t.Fatalf("Unexpected timestamp. Want zero timestamp for short input")
	}
	if deserializedTestAddress.connectionFailedCount != 0 {
		t.Fatalf("Unexpected failed count. Want: 0, got: %d", deserializedTestAddress.connectionFailedCount)
	}
	if deserializedTestAddress.verified {
		t.Fatalf("Short input unexpectedly marked as verified")
	}
}

func TestRestoreSkipsCorruptEntries(t *testing.T) {
	addressManager, teardown := newAddressManagerForTest(t, "TestRestoreSkipsCorruptEntries")
	defer teardown()
	addressStore := addressManager.store

	validNotBannedAddress := &address{
		netAddress: &appmessage.NetAddress{
			IP:        net.ParseIP("2602:100:abcd::102"),
			Port:      12345,
			Timestamp: mstime.Now(),
		},
		connectionFailedCount: 2,
		verified:              true,
	}
	validNotBannedKey := netAddressKey(validNotBannedAddress.netAddress)
	if err := addressStore.database.Put(addressStore.notBannedDatabaseKey(validNotBannedKey), addressStore.serializeAddress(validNotBannedAddress)); err != nil {
		t.Fatalf("Couldn't add valid not-banned entry: %s", err)
	}

	if err := addressStore.database.Put(notBannedAddressBucket.Key([]byte{1, 2, 3}), make([]byte, serializedAddressSize)); err != nil {
		t.Fatalf("Couldn't add invalid not-banned key entry: %s", err)
	}
	if err := addressStore.database.Put(notBannedAddressBucket.Key(make([]byte, serializedAddressKeySize)), []byte{1, 2, 3}); err != nil {
		t.Fatalf("Couldn't add invalid not-banned value entry: %s", err)
	}

	validBannedAddress := &address{
		netAddress: &appmessage.NetAddress{
			IP:        net.ParseIP("2602:100:abcd::103"),
			Port:      12346,
			Timestamp: mstime.Now(),
		},
	}
	var validBannedKey ipv6
	copy(validBannedKey[:], validBannedAddress.netAddress.IP.To16())
	if err := addressStore.database.Put(bannedAddressBucket.Key(validBannedKey[:]), addressStore.serializeAddress(validBannedAddress)); err != nil {
		t.Fatalf("Couldn't add valid banned entry: %s", err)
	}

	if err := addressStore.database.Put(bannedAddressBucket.Key([]byte{1, 2, 3}), make([]byte, serializedAddressSize)); err != nil {
		t.Fatalf("Couldn't add invalid banned key entry: %s", err)
	}
	if err := addressStore.database.Put(bannedAddressBucket.Key(make([]byte, serializedBannedKeySize)), []byte{1, 2, 3}); err != nil {
		t.Fatalf("Couldn't add invalid banned value entry: %s", err)
	}

	addressStore.notBannedAddresses = map[addressKey]*address{}
	addressStore.bannedAddresses = map[ipv6]*address{}

	if err := addressStore.restoreNotBannedAddresses(); err != nil {
		t.Fatalf("restoreNotBannedAddresses failed: %s", err)
	}
	if err := addressStore.restoreBannedAddresses(); err != nil {
		t.Fatalf("restoreBannedAddresses failed: %s", err)
	}

	if len(addressStore.notBannedAddresses) != 1 {
		t.Fatalf("Unexpected not-banned entry count. Want: 1, got: %d", len(addressStore.notBannedAddresses))
	}
	if len(addressStore.bannedAddresses) != 1 {
		t.Fatalf("Unexpected banned entry count. Want: 1, got: %d", len(addressStore.bannedAddresses))
	}
}
