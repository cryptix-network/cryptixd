package addressmanager

import (
	"encoding/binary"
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/infrastructure/db/database"
	"github.com/cryptix-network/cryptixd/util/mstime"
	"github.com/pkg/errors"
	"net"
)

var notBannedAddressBucket = database.MakeBucket([]byte("not-banned-addresses"))
var bannedAddressBucket = database.MakeBucket([]byte("banned-addresses"))

const (
	serializedAddressKeySize    = net.IPv6len + 2
	serializedBannedKeySize     = net.IPv6len
	serializedAddressLegacySize = net.IPv6len + 2 + 8 + 8
	serializedAddressSize       = serializedAddressLegacySize + 1
)

type addressStore struct {
	database           database.Database
	notBannedAddresses map[addressKey]*address
	bannedAddresses    map[ipv6]*address
}

func newAddressStore(database database.Database) (*addressStore, error) {
	addressStore := &addressStore{
		database:           database,
		notBannedAddresses: map[addressKey]*address{},
		bannedAddresses:    map[ipv6]*address{},
	}
	err := addressStore.restoreNotBannedAddresses()
	if err != nil {
		return nil, err
	}
	err = addressStore.restoreBannedAddresses()
	if err != nil {
		return nil, err
	}

	log.Infof("Loaded %d addresses and %d banned addresses",
		len(addressStore.notBannedAddresses), len(addressStore.bannedAddresses))

	return addressStore, nil
}

func (as *addressStore) restoreNotBannedAddresses() error {
	cursor, err := as.database.Cursor(notBannedAddressBucket)
	if err != nil {
		return err
	}
	defer cursor.Close()
	for ok := cursor.First(); ok; ok = cursor.Next() {
		databaseKey, err := cursor.Key()
		if err != nil {
			return err
		}
		serializedKey := databaseKey.Suffix()
		if len(serializedKey) != serializedAddressKeySize {
			log.Warnf("Skipping not-banned address with invalid key length %d", len(serializedKey))
			continue
		}
		key := as.deserializeAddressKey(serializedKey)

		serializedNetAddress, err := cursor.Value()
		if err != nil {
			return err
		}
		if len(serializedNetAddress) < serializedAddressLegacySize {
			log.Warnf("Skipping not-banned address %x with invalid value length %d", serializedKey, len(serializedNetAddress))
			continue
		}
		netAddress := as.deserializeAddress(serializedNetAddress)
		as.notBannedAddresses[key] = netAddress
	}
	return nil
}

func (as *addressStore) restoreBannedAddresses() error {
	cursor, err := as.database.Cursor(bannedAddressBucket)
	if err != nil {
		return err
	}
	defer cursor.Close()
	for ok := cursor.First(); ok; ok = cursor.Next() {
		databaseKey, err := cursor.Key()
		if err != nil {
			return err
		}
		serializedKey := databaseKey.Suffix()
		if len(serializedKey) != serializedBannedKeySize {
			log.Warnf("Skipping banned address with invalid key length %d", len(serializedKey))
			continue
		}
		var ipv6 ipv6
		copy(ipv6[:], serializedKey)

		serializedNetAddress, err := cursor.Value()
		if err != nil {
			return err
		}
		if len(serializedNetAddress) < serializedAddressLegacySize {
			log.Warnf("Skipping banned address %x with invalid value length %d", serializedKey, len(serializedNetAddress))
			continue
		}
		netAddress := as.deserializeAddress(serializedNetAddress)
		as.bannedAddresses[ipv6] = netAddress
	}
	return nil
}

func (as *addressStore) notBannedCount() int {
	return len(as.notBannedAddresses)
}

func (as *addressStore) add(key addressKey, address *address) error {
	if _, ok := as.notBannedAddresses[key]; ok {
		return nil
	}

	as.notBannedAddresses[key] = address

	databaseKey := as.notBannedDatabaseKey(key)
	serializedAddress := as.serializeAddress(address)
	return as.database.Put(databaseKey, serializedAddress)
}

// updateNotBanned updates the not-banned address collection
func (as *addressStore) updateNotBanned(key addressKey, address *address) error {
	if _, ok := as.notBannedAddresses[key]; !ok {
		return errors.Errorf("address %s is not in the store", address.netAddress.TCPAddress())
	}

	as.notBannedAddresses[key] = address

	databaseKey := as.notBannedDatabaseKey(key)
	serializedAddress := as.serializeAddress(address)
	return as.database.Put(databaseKey, serializedAddress)
}

func (as *addressStore) getNotBanned(key addressKey) (*address, bool) {
	address, ok := as.notBannedAddresses[key]
	return address, ok
}

func (as *addressStore) remove(key addressKey) error {
	delete(as.notBannedAddresses, key)

	databaseKey := as.notBannedDatabaseKey(key)
	return as.database.Delete(databaseKey)
}

func (as *addressStore) getAllNotBanned() []*address {
	addresses := make([]*address, 0, len(as.notBannedAddresses))
	for _, address := range as.notBannedAddresses {
		addresses = append(addresses, address)
	}
	return addresses
}

func (as *addressStore) getAllNotBannedNetAddresses() []*appmessage.NetAddress {
	addresses := make([]*appmessage.NetAddress, 0, len(as.notBannedAddresses))
	for _, address := range as.notBannedAddresses {
		addresses = append(addresses, address.netAddress)
	}
	return addresses
}

func (as *addressStore) getAllVerifiedNotBannedNetAddresses() []*appmessage.NetAddress {
	addresses := make([]*appmessage.NetAddress, 0, len(as.notBannedAddresses))
	for _, address := range as.notBannedAddresses {
		if !address.verified {
			continue
		}
		addresses = append(addresses, address.netAddress)
	}
	return addresses
}

func (as *addressStore) getAllNotBannedNetAddressesWithout(ignoredAddresses []*appmessage.NetAddress) []*address {
	ignoredKeys := netAddressesKeys(ignoredAddresses)

	addresses := make([]*address, 0, len(as.notBannedAddresses))
	for key, address := range as.notBannedAddresses {
		if !ignoredKeys[key] {
			addresses = append(addresses, address)
		}
	}
	return addresses
}

func (as *addressStore) isNotBanned(key addressKey) bool {
	_, ok := as.notBannedAddresses[key]
	return ok
}

func (as *addressStore) addBanned(key addressKey, address *address) error {
	if _, ok := as.bannedAddresses[key.address]; ok {
		return nil
	}

	as.bannedAddresses[key.address] = address

	databaseKey := as.bannedDatabaseKey(key)
	serializedAddress := as.serializeAddress(address)
	return as.database.Put(databaseKey, serializedAddress)
}

func (as *addressStore) removeBanned(key addressKey) error {
	delete(as.bannedAddresses, key.address)

	databaseKey := as.bannedDatabaseKey(key)
	return as.database.Delete(databaseKey)
}

func (as *addressStore) getAllBannedNetAddresses() []*appmessage.NetAddress {
	bannedAddresses := make([]*appmessage.NetAddress, 0, len(as.bannedAddresses))
	for _, bannedAddress := range as.bannedAddresses {
		bannedAddresses = append(bannedAddresses, bannedAddress.netAddress)
	}
	return bannedAddresses
}

func (as *addressStore) isBanned(key addressKey) bool {
	_, ok := as.bannedAddresses[key.address]
	return ok
}

func (as *addressStore) getBanned(key addressKey) (*address, bool) {
	bannedAddress, ok := as.bannedAddresses[key.address]
	return bannedAddress, ok
}

// netAddressKeys returns a key of the ip address to use it in maps.
func netAddressesKeys(netAddresses []*appmessage.NetAddress) map[addressKey]bool {
	result := make(map[addressKey]bool, len(netAddresses))
	for _, netAddress := range netAddresses {
		key := netAddressKey(netAddress)
		result[key] = true
	}
	return result
}

func (as *addressStore) notBannedDatabaseKey(key addressKey) *database.Key {
	serializedKey := as.serializeAddressKey(key)
	return notBannedAddressBucket.Key(serializedKey)
}

func (as *addressStore) bannedDatabaseKey(key addressKey) *database.Key {
	return bannedAddressBucket.Key(key.address[:])
}

func (as *addressStore) serializeAddressKey(key addressKey) []byte {
	serializedSize := 16 + 2 // ipv6 + port
	serializedKey := make([]byte, serializedSize)

	copy(serializedKey[:], key.address[:])
	binary.LittleEndian.PutUint16(serializedKey[16:], key.port)

	return serializedKey
}

func (as *addressStore) deserializeAddressKey(serializedKey []byte) addressKey {
	if len(serializedKey) < serializedAddressKeySize {
		return addressKey{}
	}

	var ip ipv6
	copy(ip[:], serializedKey[:net.IPv6len])

	port := binary.LittleEndian.Uint16(serializedKey[net.IPv6len:serializedAddressKeySize])

	return addressKey{
		port:    port,
		address: ip,
	}
}

func (as *addressStore) serializeAddress(address *address) []byte {
	serializedSize := serializedAddressSize // ipv6 + port + timestamp + connectionFailedCount + verified
	serializedNetAddress := make([]byte, serializedSize)

	copy(serializedNetAddress[:], address.netAddress.IP.To16()[:])
	binary.LittleEndian.PutUint16(serializedNetAddress[16:], address.netAddress.Port)
	binary.LittleEndian.PutUint64(serializedNetAddress[18:], uint64(address.netAddress.Timestamp.UnixMilliseconds()))
	binary.LittleEndian.PutUint64(serializedNetAddress[26:], uint64(address.connectionFailedCount))
	if address.verified {
		serializedNetAddress[34] = 1
	}

	return serializedNetAddress
}

func (as *addressStore) deserializeAddress(serializedAddress []byte) *address {
	ip := make(net.IP, net.IPv6len)
	if len(serializedAddress) >= net.IPv6len {
		copy(ip[:], serializedAddress[:net.IPv6len])
	}

	var port uint16
	if len(serializedAddress) >= net.IPv6len+2 {
		port = binary.LittleEndian.Uint16(serializedAddress[net.IPv6len : net.IPv6len+2])
	}

	timestamp := mstime.Time{}
	if len(serializedAddress) >= net.IPv6len+2+8 {
		timestamp = mstime.UnixMilliseconds(int64(binary.LittleEndian.Uint64(serializedAddress[18:26])))
	}

	var connectionFailedCount uint64
	if len(serializedAddress) >= serializedAddressLegacySize {
		connectionFailedCount = binary.LittleEndian.Uint64(serializedAddress[26:34])
	}

	verified := len(serializedAddress) >= serializedAddressSize && serializedAddress[34] == 1

	return &address{
		netAddress: &appmessage.NetAddress{
			IP:        ip,
			Port:      port,
			Timestamp: timestamp,
		},
		connectionFailedCount: connectionFailedCount,
		verified:              verified,
	}
}
