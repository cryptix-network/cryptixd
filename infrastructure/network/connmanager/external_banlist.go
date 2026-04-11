package connmanager

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	urlpkg "net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter"
	secp256k1 "github.com/cryptix-network/go-secp256k1"
	"github.com/pkg/errors"
	"github.com/zeebo/blake3"
)

const (
	externalBanlistFetchInterval   = 10 * time.Minute
	externalBanlistRequestTimeout  = 10 * time.Second
	externalBanlistMaxResponseSize = 2 * 1024 * 1024
	externalBanlistMaxIPs          = 4096
	externalBanlistMaxNodeIDs      = 4096
	externalBanlistMaxEntryLength  = 256
	externalBanlistPeerVoteMaxAge  = 2 * time.Minute
	externalBanlistPeerVoteMaxSize = 512
	antiFraudSchemaVersion         = 1
	antiFraudDomainSep             = "cryptix-antifraud-snapshot-v1"
	antiFraudSignatureHexLength    = 128
	antiFraudNodeIDHexLength       = 64
	antiFraudPubKeyCurrentHex      = "c93b4ed533a76866a3c3ea1cc0bc3e70c0dbe32a945057b5dff95b88ce9280dd"
	antiFraudPubKeyNextHex         = "fc10777c57060195c83e9885c790c8a26496d305b366b8e5fbf475203c680f79"
	antiFraudHashWindowLen         = 3
	antiFraudZeroHashHex           = "0000000000000000000000000000000000000000000000000000000000000000"
	antiFraudPersistDir            = "antifraud"
	antiFraudCurrentFile           = "current.snapshot"
	antiFraudPreviousFile          = "previous.snapshot"
)

type externalBanlistSnapshot struct {
	SchemaVersion uint8
	Network       uint8
	SnapshotSeq   uint64
	GeneratedAtMs uint64
	SigningKeyID  uint8
	Signature     [64]byte
	RootHash      [32]byte
	IPEntries     [][]byte
	NodeIDEntries [][32]byte
	IPs           map[string]struct{}
	NodeIDs       map[string]struct{}
}

type normalizedAntiFraudSnapshot struct {
	schemaVersion uint8
	network       uint8
	snapshotSeq   uint64
	generatedAtMs uint64
	signingKeyID  uint8
	ipEntries     [][]byte
	nodeIDEntries [][32]byte
	signature     [64]byte
	rootHash      [32]byte
}

type peerAntiFraudVote struct {
	snapshot   *externalBanlistSnapshot
	receivedAt time.Time
}

func (c *ConnectionManager) externalBanlistEnabled() bool {
	return c != nil && c.cfg != nil && c.cfg.EnableExternalBanlist
}

func (c *ConnectionManager) refreshExternalBanlistIfNeeded(now time.Time) {
	if !c.externalBanlistEnabled() {
		c.externalBanlistLock.Lock()
		c.antiFraudPeerFallback = true
		c.externalBanlistLock.Unlock()
		return
	}

	c.externalBanlistLock.RLock()
	nextFetch := c.nextExternalBanlistFetch
	c.externalBanlistLock.RUnlock()
	if !nextFetch.IsZero() && now.Before(nextFetch) {
		return
	}

	snapshot, err := c.fetchExternalBanlist()

	c.externalBanlistLock.Lock()
	c.nextExternalBanlistFetch = now.Add(externalBanlistFetchInterval)
	c.externalBanlistLock.Unlock()

	if err != nil {
		log.Warnf("External antifraud banlist refresh failed: %s", err)
		c.externalBanlistLock.Lock()
		c.antiFraudPeerFallback = true
		c.externalBanlistLock.Unlock()
		return
	}

	applied, applyErr := c.tryApplyAntiFraudSnapshot(snapshot, "banserver")
	if applyErr != nil {
		log.Warnf("External antifraud snapshot rejected: %s", applyErr)
		c.externalBanlistLock.Lock()
		c.antiFraudPeerFallback = true
		c.externalBanlistLock.Unlock()
		return
	}
	c.externalBanlistLock.Lock()
	c.antiFraudPeerFallback = false
	c.externalBanlistLock.Unlock()
	if applied {
		log.Infof(
			"External antifraud snapshot refreshed: seq=%d hash=%s ips=%d node_ids=%d",
			snapshot.SnapshotSeq,
			hex.EncodeToString(snapshot.RootHash[:]),
			len(snapshot.IPs),
			len(snapshot.NodeIDs),
		)
	}
}

func (c *ConnectionManager) fetchExternalBanlist() (*externalBanlistSnapshot, error) {
	if c.cfg == nil {
		return nil, errors.New("connection manager config is nil")
	}

	expectedNetwork, err := antiFraudNetworkFromName(c.cfg.NetParams().Name)
	if err != nil {
		return nil, err
	}

	candidates := externalBanlistCandidateURLs(c.cfg.ExternalBanlistURL)
	if len(candidates) == 0 {
		return nil, errors.Errorf("invalid external banlist URL %q", c.cfg.ExternalBanlistURL)
	}

	var lastErr error
	for index, candidate := range candidates {
		snapshot, err := c.fetchExternalBanlistFromURL(candidate, expectedNetwork)
		if err != nil {
			lastErr = err
			continue
		}

		if index > 0 {
			log.Warnf("External antifraud banlist fetched via fallback URL %s", candidate)
		}
		return snapshot, nil
	}

	return nil, errors.Wrap(lastErr, "failed to fetch external banlist from all configured endpoints")
}

func externalBanlistCandidateURLs(rawURL string) []string {
	cleanURL := strings.TrimSpace(rawURL)
	if cleanURL == "" {
		return nil
	}

	parsed, err := urlpkg.Parse(cleanURL)
	if err != nil || parsed.Scheme == "" {
		cleanURL = strings.TrimPrefix(cleanURL, "//")
		return []string{
			"https://" + cleanURL,
			"http://" + cleanURL,
		}
	}

	parsedString := parsed.String()
	if strings.EqualFold(parsed.Scheme, "https") {
		fallback := *parsed
		fallback.Scheme = "http"
		return []string{parsedString, fallback.String()}
	}

	return []string{parsedString}
}

func (c *ConnectionManager) fetchExternalBanlistFromURL(endpoint string, expectedNetwork uint8) (*externalBanlistSnapshot, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // required for compatibility with legacy antifraud endpoints

	client := &http.Client{
		Transport: transport,
		Timeout:   externalBanlistRequestTimeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), externalBanlistRequestTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, errors.Errorf("unexpected status code %d", response.StatusCode)
	}

	limitedBodyReader := io.LimitReader(response.Body, externalBanlistMaxResponseSize+1)
	responseBody, err := io.ReadAll(limitedBodyReader)
	if err != nil {
		return nil, err
	}
	if len(responseBody) > externalBanlistMaxResponseSize {
		return nil, errors.Errorf("response body exceeded max size of %d bytes", externalBanlistMaxResponseSize)
	}

	return decodeExternalBanlistPayload(responseBody, expectedNetwork)
}

func decodeExternalBanlistPayload(payload []byte, expectedNetwork uint8) (*externalBanlistSnapshot, error) {
	var top map[string]interface{}
	if err := json.Unmarshal(payload, &top); err != nil {
		return nil, err
	}

	root := top
	if data, ok := top["data"]; ok {
		dataMap, ok := data.(map[string]interface{})
		if !ok {
			return nil, errors.New("field `data` must be an object")
		}
		root = dataMap
	}

	if status, ok := readJSONString(root, "status"); ok {
		if status != "" && !strings.EqualFold(status, "success") {
			return nil, errors.Errorf("banlist endpoint returned non-success status %q", status)
		}
	} else if status, ok := readJSONString(top, "status"); ok {
		if status != "" && !strings.EqualFold(status, "success") {
			return nil, errors.Errorf("banlist endpoint returned non-success status %q", status)
		}
	}

	schemaVersion, ok, err := readJSONUint(root, "schema_version", "schemaVersion")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("missing schema_version")
	}
	if schemaVersion != antiFraudSchemaVersion {
		return nil, errors.Errorf("unsupported schema_version %d (expected %d)", schemaVersion, antiFraudSchemaVersion)
	}

	network, ok, err := readJSONNetwork(root)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("missing network")
	}
	if network != expectedNetwork {
		return nil, errors.Errorf("snapshot network mismatch: expected %d got %d", expectedNetwork, network)
	}

	snapshotSeq, ok, err := readJSONUint(root, "snapshot_seq", "snapshotSeq")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("missing snapshot_seq")
	}
	generatedAtMs, ok, err := readJSONUint(root, "generated_at_ms", "generatedAtMs")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("missing generated_at_ms")
	}
	signingKeyIDRaw, ok, err := readJSONUint(root, "signing_key_id", "signingKeyId")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("missing signing_key_id")
	}
	if signingKeyIDRaw > 255 {
		return nil, errors.Errorf("invalid signing_key_id %d", signingKeyIDRaw)
	}
	signingKeyID := uint8(signingKeyIDRaw)

	signatureHex, ok := readJSONString(root, "signature")
	if !ok || signatureHex == "" {
		return nil, errors.New("missing signature")
	}
	signatureHex = strings.TrimSpace(signatureHex)
	if len(signatureHex) != antiFraudSignatureHexLength {
		return nil, errors.New("signature must be 64-byte hex")
	}
	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return nil, errors.Wrap(err, "invalid signature hex")
	}
	var signature [64]byte
	copy(signature[:], signatureBytes)

	rawIPs, ok, err := readJSONStringSlice(root, "banned_ips")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("missing banned_ips array")
	}
	rawNodeIDs, ok, err := readJSONStringSlice(root, "banned_node_ids")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("missing banned_node_ids array")
	}

	ipCount, hasIPCount, err := readJSONUint(root, "banned_ips_count")
	if err != nil {
		return nil, err
	}
	if !hasIPCount {
		return nil, errors.New("missing banned_ips_count")
	}
	if hasIPCount && ipCount > externalBanlistMaxIPs {
		return nil, errors.Errorf("banned_ips_count exceeds max %d", externalBanlistMaxIPs)
	}
	if len(rawIPs) > externalBanlistMaxIPs {
		return nil, errors.Errorf("banned_ips_count exceeds max %d", externalBanlistMaxIPs)
	}
	if hasIPCount && ipCount != uint64(len(rawIPs)) {
		return nil, errors.New("banned_ips_count mismatch")
	}

	nodeCount, hasNodeCount, err := readJSONUint(root, "banned_node_ids_count")
	if err != nil {
		return nil, err
	}
	if !hasNodeCount {
		return nil, errors.New("missing banned_node_ids_count")
	}
	if hasNodeCount && nodeCount > externalBanlistMaxNodeIDs {
		return nil, errors.Errorf("banned_node_ids_count exceeds max %d", externalBanlistMaxNodeIDs)
	}
	if len(rawNodeIDs) > externalBanlistMaxNodeIDs {
		return nil, errors.Errorf("banned_node_ids_count exceeds max %d", externalBanlistMaxNodeIDs)
	}
	if hasNodeCount && nodeCount != uint64(len(rawNodeIDs)) {
		return nil, errors.New("banned_node_ids_count mismatch")
	}

	ipEntries, normalizedIPs := normalizeExternalBanlistIPEntries(rawIPs)
	nodeEntries, normalizedNodeIDs := normalizeExternalBanlistNodeIDEntries(rawNodeIDs)

	if len(ipEntries) > externalBanlistMaxIPs {
		return nil, errors.Errorf("sanitized banned_ips_count exceeds max %d", externalBanlistMaxIPs)
	}
	if len(nodeEntries) > externalBanlistMaxNodeIDs {
		return nil, errors.Errorf("sanitized banned_node_ids_count exceeds max %d", externalBanlistMaxNodeIDs)
	}

	normalized := normalizedAntiFraudSnapshot{
		schemaVersion: uint8(schemaVersion),
		network:       network,
		snapshotSeq:   snapshotSeq,
		generatedAtMs: generatedAtMs,
		signingKeyID:  signingKeyID,
		ipEntries:     ipEntries,
		nodeIDEntries: nodeEntries,
		signature:     signature,
	}
	rootHash, err := normalized.computeRootHash()
	if err != nil {
		return nil, err
	}
	normalized.rootHash = rootHash
	if !verifyAntiFraudSnapshotSignature(network, signingKeyID, normalized.rootHash, signature) {
		return nil, errors.New("invalid snapshot signature")
	}

	if advertisedRootHex, ok := readJSONString(root, "root_hash", "rootHash"); ok && strings.TrimSpace(advertisedRootHex) != "" {
		advertisedRoot, err := hex.DecodeString(strings.TrimSpace(advertisedRootHex))
		if err != nil || len(advertisedRoot) != 32 {
			return nil, errors.New("invalid root_hash")
		}
		if !bytes.Equal(advertisedRoot, normalized.rootHash[:]) {
			return nil, errors.New("root_hash does not match canonical payload")
		}
	}

	return &externalBanlistSnapshot{
		SchemaVersion: uint8(schemaVersion),
		Network:       network,
		SnapshotSeq:   snapshotSeq,
		GeneratedAtMs: generatedAtMs,
		SigningKeyID:  signingKeyID,
		Signature:     signature,
		RootHash:      normalized.rootHash,
		IPEntries:     cloneIPEntries(ipEntries),
		NodeIDEntries: append([][32]byte(nil), nodeEntries...),
		IPs:           normalizedIPs,
		NodeIDs:       normalizedNodeIDs,
	}, nil
}

func (snapshot *normalizedAntiFraudSnapshot) computeRootHash() ([32]byte, error) {
	canonicalPayload, err := buildAntiFraudCanonicalPayload(
		snapshot.schemaVersion,
		snapshot.network,
		snapshot.snapshotSeq,
		snapshot.generatedAtMs,
		snapshot.signingKeyID,
		snapshot.ipEntries,
		snapshot.nodeIDEntries,
	)
	if err != nil {
		return [32]byte{}, err
	}
	return blake3.Sum256(canonicalPayload), nil
}

func buildAntiFraudCanonicalPayload(
	schemaVersion uint8,
	network uint8,
	snapshotSeq uint64,
	generatedAtMs uint64,
	signingKeyID uint8,
	ipEntries [][]byte,
	nodeIDEntries [][32]byte,
) ([]byte, error) {
	if len(ipEntries) > externalBanlistMaxIPs || len(nodeIDEntries) > externalBanlistMaxNodeIDs {
		return nil, errors.New("entry count exceeds maxima")
	}

	payload := make([]byte, 0, len(antiFraudDomainSep)+64)
	payload = append(payload, []byte(antiFraudDomainSep)...)
	payload = append(payload, schemaVersion)
	payload = append(payload, network)

	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], snapshotSeq)
	payload = append(payload, u64[:]...)
	binary.BigEndian.PutUint64(u64[:], generatedAtMs)
	payload = append(payload, u64[:]...)
	payload = append(payload, signingKeyID)

	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], uint32(len(ipEntries)))
	payload = append(payload, u32[:]...)
	for _, entry := range ipEntries {
		payload = append(payload, entry...)
	}

	binary.BigEndian.PutUint32(u32[:], uint32(len(nodeIDEntries)))
	payload = append(payload, u32[:]...)
	for _, entry := range nodeIDEntries {
		payload = append(payload, entry[:]...)
	}
	return payload, nil
}

func verifyAntiFraudSnapshotSignature(network uint8, signingKeyID uint8, rootHash [32]byte, signature [64]byte) bool {
	pubkey, ok := antiFraudPinnedPubKey(network, signingKeyID)
	if !ok {
		return false
	}

	pubKey, err := secp256k1.DeserializeSchnorrPubKey(pubkey[:])
	if err != nil {
		return false
	}
	signatureObj, err := secp256k1.DeserializeSchnorrSignatureFromSlice(signature[:])
	if err != nil {
		return false
	}

	var secpHash secp256k1.Hash
	copy(secpHash[:], rootHash[:])
	return pubKey.SchnorrVerify(&secpHash, signatureObj)
}

func antiFraudPinnedPubKey(_network uint8, signingKeyID uint8) ([32]byte, bool) {
	switch signingKeyID {
	case 0:
		return decodeHex32(antiFraudPubKeyCurrentHex)
	case 1:
		return decodeHex32(antiFraudPubKeyNextHex)
	default:
		return [32]byte{}, false
	}
}

func decodeHex32(raw string) ([32]byte, bool) {
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, false
	}
	var out [32]byte
	copy(out[:], decoded)
	return out, true
}

func antiFraudNetworkFromName(networkName string) (uint8, error) {
	normalized := strings.ToLower(strings.TrimSpace(networkName))
	switch {
	case normalized == "mainnet" || normalized == "cryptix-mainnet":
		return 0, nil
	case normalized == "testnet" || normalized == "cryptix-testnet" || strings.HasPrefix(normalized, "testnet-") || strings.HasPrefix(normalized, "cryptix-testnet-"):
		return 1, nil
	case normalized == "devnet" || normalized == "cryptix-devnet":
		return 2, nil
	case normalized == "simnet" || normalized == "cryptix-simnet":
		return 3, nil
	default:
		return 0, errors.Errorf("unsupported network %q for antifraud snapshot", networkName)
	}
}

func readJSONNetwork(root map[string]interface{}) (uint8, bool, error) {
	raw, ok := root["network"]
	if !ok {
		return 0, false, nil
	}
	switch value := raw.(type) {
	case float64:
		if value < 0 || value > 255 || value != float64(uint64(value)) {
			return 0, false, errors.New("invalid network")
		}
		return uint8(value), true, nil
	case string:
		normalized := strings.ToLower(strings.TrimSpace(value))
		switch {
		case normalized == "mainnet" || normalized == "cryptix-mainnet":
			return 0, true, nil
		case normalized == "testnet" || normalized == "cryptix-testnet" || strings.HasPrefix(normalized, "testnet-") || strings.HasPrefix(normalized, "cryptix-testnet-"):
			return 1, true, nil
		case normalized == "devnet" || normalized == "cryptix-devnet":
			return 2, true, nil
		case normalized == "simnet" || normalized == "cryptix-simnet":
			return 3, true, nil
		default:
			return 0, false, errors.New("invalid network")
		}
	default:
		return 0, false, errors.New("invalid network")
	}
}

func readJSONUint(root map[string]interface{}, keys ...string) (uint64, bool, error) {
	for _, key := range keys {
		raw, ok := root[key]
		if !ok {
			continue
		}
		switch value := raw.(type) {
		case float64:
			if value < 0 || value != float64(uint64(value)) {
				return 0, false, errors.Errorf("invalid integer value for %s", key)
			}
			return uint64(value), true, nil
		case string:
			candidate := strings.TrimSpace(value)
			if candidate == "" {
				return 0, false, errors.Errorf("empty numeric value for %s", key)
			}
			parsed, err := parseUintString(candidate)
			if err != nil {
				return 0, false, errors.Wrapf(err, "invalid integer value for %s", key)
			}
			return parsed, true, nil
		default:
			return 0, false, errors.Errorf("invalid integer type for %s", key)
		}
	}
	return 0, false, nil
}

func parseUintString(raw string) (uint64, error) {
	var value uint64
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, errors.New("contains non-digit characters")
		}
		digit := uint64(r - '0')
		if value > (^uint64(0)-digit)/10 {
			return 0, errors.New("integer overflow")
		}
		value = value*10 + digit
	}
	return value, nil
}

func readJSONString(root map[string]interface{}, keys ...string) (string, bool) {
	for _, key := range keys {
		raw, ok := root[key]
		if !ok {
			continue
		}
		value, ok := raw.(string)
		if !ok {
			return "", false
		}
		return strings.TrimSpace(value), true
	}
	return "", false
}

func readJSONStringSlice(root map[string]interface{}, keys ...string) ([]string, bool, error) {
	for _, key := range keys {
		raw, ok := root[key]
		if !ok {
			continue
		}
		array, ok := raw.([]interface{})
		if !ok {
			return nil, false, errors.Errorf("field %s must be an array", key)
		}
		values := make([]string, 0, len(array))
		for _, item := range array {
			str, ok := item.(string)
			if !ok {
				continue
			}
			values = append(values, str)
		}
		return values, true, nil
	}
	return nil, false, nil
}

func normalizeExternalBanlistIPEntries(rawIPs []string) ([][]byte, map[string]struct{}) {
	uniqueEntries := make(map[string][]byte)
	for _, rawIP := range rawIPs {
		candidate := strings.TrimSpace(rawIP)
		if candidate == "" || len(candidate) > externalBanlistMaxEntryLength {
			continue
		}
		parsedIP := net.ParseIP(candidate)
		if parsedIP == nil {
			continue
		}

		var entry []byte
		if ip4 := parsedIP.To4(); ip4 != nil {
			entry = append([]byte{4}, ip4...)
		} else {
			ip16 := parsedIP.To16()
			if ip16 == nil {
				continue
			}
			entry = append([]byte{6}, ip16...)
		}
		uniqueEntries[string(entry)] = entry
	}

	entries := make([][]byte, 0, len(uniqueEntries))
	for _, entry := range uniqueEntries {
		copied := make([]byte, len(entry))
		copy(copied, entry)
		entries = append(entries, copied)
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i], entries[j]) < 0
	})

	normalizedIPs := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if canonical, ok := canonicalIPFromEntry(entry); ok {
			normalizedIPs[canonical] = struct{}{}
		}
	}
	return entries, normalizedIPs
}

func canonicalIPFromEntry(entry []byte) (string, bool) {
	if len(entry) == 5 && entry[0] == 4 {
		return net.IP(entry[1:]).String(), true
	}
	if len(entry) == 17 && entry[0] == 6 {
		return net.IP(entry[1:]).String(), true
	}
	return "", false
}

func normalizeExternalBanlistNodeIDEntries(rawNodeIDs []string) ([][32]byte, map[string]struct{}) {
	uniqueEntries := make(map[[32]byte]struct{})
	for _, rawNodeID := range rawNodeIDs {
		candidate := strings.ToLower(strings.TrimSpace(rawNodeID))
		if candidate == "" || len(candidate) > externalBanlistMaxEntryLength {
			continue
		}
		if len(candidate) != antiFraudNodeIDHexLength {
			continue
		}
		decoded, err := hex.DecodeString(candidate)
		if err != nil || len(decoded) != 32 {
			continue
		}
		var entry [32]byte
		copy(entry[:], decoded)
		uniqueEntries[entry] = struct{}{}
	}

	entries := make([][32]byte, 0, len(uniqueEntries))
	for entry := range uniqueEntries {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i][:], entries[j][:]) < 0
	})

	normalizedNodeIDs := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		normalizedNodeIDs[hex.EncodeToString(entry[:])] = struct{}{}
	}
	return entries, normalizedNodeIDs
}

type AntiFraudMode uint8

const (
	AntiFraudModeFull AntiFraudMode = iota
	AntiFraudModeRestricted
)

type IngestPeerAntiFraudSnapshotResult struct {
	Applied  bool
	RootHash [32]byte
}

func (c *ConnectionManager) AntiFraudHashWindow() [][32]byte {
	c.externalBanlistLock.RLock()
	defer c.externalBanlistLock.RUnlock()
	out := make([][32]byte, antiFraudHashWindowLen)
	copy(out, c.antiFraudHashWindow[:])
	return out
}

func (c *ConnectionManager) IsAntiFraudPeerFallbackRequired() bool {
	c.externalBanlistLock.RLock()
	defer c.externalBanlistLock.RUnlock()
	return c.antiFraudPeerFallback
}

func (c *ConnectionManager) AntiFraudSnapshotForPeer() *appmessage.MsgAntiFraudSnapshotV1 {
	c.externalBanlistLock.RLock()
	defer c.externalBanlistLock.RUnlock()
	if c.antiFraudCurrentSnapshot == nil {
		return nil
	}
	return cloneAntiFraudSnapshotMessage(c.antiFraudCurrentSnapshot)
}

func (c *ConnectionManager) AntiFraudModeForPeerHashes(peerHashes [][32]byte) AntiFraudMode {
	local := c.AntiFraudHashWindow()
	if !validateAntiFraudHashWindow(peerHashes) {
		return AntiFraudModeRestricted
	}
	if !hasNonZeroAntiFraudHashOverlap(local, peerHashes) {
		return AntiFraudModeRestricted
	}
	return AntiFraudModeFull
}

func validateAntiFraudHashWindow(hashes [][32]byte) bool {
	if len(hashes) != antiFraudHashWindowLen {
		return false
	}
	seenNonZero := map[[32]byte]struct{}{}
	seenZero := false
	for _, hash := range hashes {
		if hash == ([32]byte{}) {
			seenZero = true
			continue
		}
		if seenZero {
			return false
		}
		if _, exists := seenNonZero[hash]; exists {
			return false
		}
		seenNonZero[hash] = struct{}{}
	}
	return true
}

func hasNonZeroAntiFraudHashOverlap(local, remote [][32]byte) bool {
	remoteSet := map[[32]byte]struct{}{}
	for _, hash := range remote {
		if hash == ([32]byte{}) {
			continue
		}
		remoteSet[hash] = struct{}{}
	}
	for _, hash := range local {
		if hash == ([32]byte{}) {
			continue
		}
		if _, ok := remoteSet[hash]; ok {
			return true
		}
	}
	return false
}

func (c *ConnectionManager) IngestPeerAntiFraudSnapshot(peerID string, message *appmessage.MsgAntiFraudSnapshotV1) (*IngestPeerAntiFraudSnapshotResult, error) {
	if peerID == "" {
		return nil, errors.New("peer ID is empty")
	}
	if message == nil {
		return nil, errors.New("snapshot message is nil")
	}
	expectedNetwork, err := antiFraudNetworkFromName(c.cfg.NetParams().Name)
	if err != nil {
		return nil, err
	}
	snapshot, err := decodeExternalBanlistSnapshotFromMessage(message, expectedNetwork)
	if err != nil {
		return nil, err
	}
	result := &IngestPeerAntiFraudSnapshotResult{Applied: false, RootHash: snapshot.RootHash}

	now := time.Now()
	c.externalBanlistLock.Lock()
	c.antiFraudPeerVotes[peerID] = &peerAntiFraudVote{
		snapshot:   snapshot,
		receivedAt: now,
	}
	pruneAntiFraudPeerVotes(c.antiFraudPeerVotes, now)
	var highestSeq uint64
	hasHighest := false
	for _, vote := range c.antiFraudPeerVotes {
		if vote == nil || vote.snapshot == nil {
			continue
		}
		if !hasHighest || vote.snapshot.SnapshotSeq > highestSeq {
			highestSeq = vote.snapshot.SnapshotSeq
			hasHighest = true
		}
	}
	if !hasHighest {
		c.externalBanlistLock.Unlock()
		return result, nil
	}

	candidates := make([]*externalBanlistSnapshot, 0, len(c.antiFraudPeerVotes))
	for _, vote := range c.antiFraudPeerVotes {
		if vote == nil || vote.snapshot == nil {
			continue
		}
		if vote.snapshot.SnapshotSeq == highestSeq {
			candidates = append(candidates, vote.snapshot)
		}
	}
	if len(candidates) == 0 {
		c.externalBanlistLock.Unlock()
		return result, nil
	}
	votesByHash := map[[32]byte]int{}
	snapshotByHash := map[[32]byte]*externalBanlistSnapshot{}
	for _, candidate := range candidates {
		votesByHash[candidate.RootHash]++
		snapshotByHash[candidate.RootHash] = candidate
	}
	var (
		winnerHash  [32]byte
		winnerVotes int
	)
	for hash, votes := range votesByHash {
		if votes > winnerVotes {
			winnerVotes = votes
			winnerHash = hash
		}
	}
	required := len(candidates)/2 + 1
	if winnerVotes < required {
		c.externalBanlistLock.Unlock()
		return result, nil
	}
	winner := snapshotByHash[winnerHash]
	applied, err := c.tryApplyAntiFraudSnapshotLocked(winner, "peer")
	c.externalBanlistLock.Unlock()
	result.Applied = applied
	return result, err
}

func pruneAntiFraudPeerVotes(votes map[string]*peerAntiFraudVote, now time.Time) {
	if len(votes) == 0 {
		return
	}

	for peerID, vote := range votes {
		if vote == nil || vote.snapshot == nil || now.Sub(vote.receivedAt) > externalBanlistPeerVoteMaxAge {
			delete(votes, peerID)
		}
	}
	if len(votes) <= externalBanlistPeerVoteMaxSize {
		return
	}

	type voteEntry struct {
		peerID     string
		receivedAt time.Time
	}
	ordered := make([]voteEntry, 0, len(votes))
	for peerID, vote := range votes {
		ordered = append(ordered, voteEntry{
			peerID:     peerID,
			receivedAt: vote.receivedAt,
		})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].receivedAt.Equal(ordered[j].receivedAt) {
			return ordered[i].peerID < ordered[j].peerID
		}
		return ordered[i].receivedAt.Before(ordered[j].receivedAt)
	})

	overflow := len(votes) - externalBanlistPeerVoteMaxSize
	for i := 0; i < overflow; i++ {
		delete(votes, ordered[i].peerID)
	}
}

func (c *ConnectionManager) AdvancePeerAntiFraudHashWindow(current [][32]byte, newHash [32]byte) [][32]byte {
	var normalized [antiFraudHashWindowLen][32]byte
	if validateAntiFraudHashWindow(current) {
		copy(normalized[:], current)
	}
	advanced := advanceAntiFraudHashWindow(normalized, newHash)
	out := make([][32]byte, antiFraudHashWindowLen)
	copy(out, advanced[:])
	return out
}

func decodeExternalBanlistSnapshotFromMessage(message *appmessage.MsgAntiFraudSnapshotV1, expectedNetwork uint8) (*externalBanlistSnapshot, error) {
	if message.SchemaVersion != antiFraudSchemaVersion {
		return nil, errors.Errorf("unsupported schema_version %d (expected %d)", message.SchemaVersion, antiFraudSchemaVersion)
	}
	if message.Network > 255 {
		return nil, errors.Errorf("invalid network %d", message.Network)
	}
	network := uint8(message.Network)
	if network != expectedNetwork {
		return nil, errors.Errorf("snapshot network mismatch: expected %d got %d", expectedNetwork, network)
	}
	if message.SigningKeyID > 255 {
		return nil, errors.Errorf("invalid signing_key_id %d", message.SigningKeyID)
	}
	if len(message.BannedIPs) > externalBanlistMaxIPs {
		return nil, errors.Errorf("banned_ips_count exceeds max %d", externalBanlistMaxIPs)
	}
	if len(message.BannedNodeIDs) > externalBanlistMaxNodeIDs {
		return nil, errors.Errorf("banned_node_ids_count exceeds max %d", externalBanlistMaxNodeIDs)
	}
	if len(message.Signature) != 64 {
		return nil, errors.New("signature must be exactly 64 bytes")
	}
	var signature [64]byte
	copy(signature[:], message.Signature)

	normalizedIPEntries, normalizedIPs := normalizeIPEntriesFromRaw(message.BannedIPs)
	normalizedNodeEntries, normalizedNodeIDs := normalizeNodeIDEntriesFromRaw(message.BannedNodeIDs)

	normalized := normalizedAntiFraudSnapshot{
		schemaVersion: uint8(message.SchemaVersion),
		network:       network,
		snapshotSeq:   message.SnapshotSeq,
		generatedAtMs: message.GeneratedAtMs,
		signingKeyID:  uint8(message.SigningKeyID),
		ipEntries:     normalizedIPEntries,
		nodeIDEntries: normalizedNodeEntries,
		signature:     signature,
	}
	rootHash, err := normalized.computeRootHash()
	if err != nil {
		return nil, err
	}
	normalized.rootHash = rootHash
	if !verifyAntiFraudSnapshotSignature(normalized.network, normalized.signingKeyID, normalized.rootHash, normalized.signature) {
		return nil, errors.New("invalid snapshot signature")
	}

	return &externalBanlistSnapshot{
		SchemaVersion: normalized.schemaVersion,
		Network:       normalized.network,
		SnapshotSeq:   normalized.snapshotSeq,
		GeneratedAtMs: normalized.generatedAtMs,
		SigningKeyID:  normalized.signingKeyID,
		Signature:     normalized.signature,
		RootHash:      normalized.rootHash,
		IPEntries:     cloneIPEntries(normalized.ipEntries),
		NodeIDEntries: append([][32]byte(nil), normalized.nodeIDEntries...),
		IPs:           normalizedIPs,
		NodeIDs:       normalizedNodeIDs,
	}, nil
}

func normalizeIPEntriesFromRaw(rawEntries [][]byte) ([][]byte, map[string]struct{}) {
	unique := map[string][]byte{}
	for _, entry := range rawEntries {
		if normalized, ok := normalizeIPBinaryEntry(entry); ok {
			unique[string(normalized)] = normalized
		}
	}
	entries := make([][]byte, 0, len(unique))
	for _, entry := range unique {
		copied := make([]byte, len(entry))
		copy(copied, entry)
		entries = append(entries, copied)
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i], entries[j]) < 0
	})
	ips := map[string]struct{}{}
	for _, entry := range entries {
		if canonical, ok := canonicalIPFromEntry(entry); ok {
			ips[canonical] = struct{}{}
		}
	}
	return entries, ips
}

func normalizeNodeIDEntriesFromRaw(rawEntries [][]byte) ([][32]byte, map[string]struct{}) {
	unique := map[[32]byte]struct{}{}
	for _, entry := range rawEntries {
		if len(entry) != 32 {
			continue
		}
		var node [32]byte
		copy(node[:], entry)
		unique[node] = struct{}{}
	}
	nodes := make([][32]byte, 0, len(unique))
	for node := range unique {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return bytes.Compare(nodes[i][:], nodes[j][:]) < 0
	})
	nodeIDs := map[string]struct{}{}
	for _, node := range nodes {
		nodeIDs[hex.EncodeToString(node[:])] = struct{}{}
	}
	return nodes, nodeIDs
}

func normalizeIPBinaryEntry(entry []byte) ([]byte, bool) {
	if len(entry) == 5 && entry[0] == 4 {
		ip := net.IP(entry[1:5]).To4()
		if ip == nil {
			return nil, false
		}
		return append([]byte{4}, ip...), true
	}
	if len(entry) == 17 && entry[0] == 6 {
		ip := net.IP(entry[1:17]).To16()
		if ip == nil {
			return nil, false
		}
		return append([]byte{6}, ip...), true
	}
	return nil, false
}

func cloneIPEntries(entries [][]byte) [][]byte {
	out := make([][]byte, 0, len(entries))
	for _, entry := range entries {
		copied := make([]byte, len(entry))
		copy(copied, entry)
		out = append(out, copied)
	}
	return out
}

func cloneAntiFraudSnapshotMessage(message *appmessage.MsgAntiFraudSnapshotV1) *appmessage.MsgAntiFraudSnapshotV1 {
	if message == nil {
		return nil
	}
	cloned := &appmessage.MsgAntiFraudSnapshotV1{
		SchemaVersion: message.SchemaVersion,
		Network:       message.Network,
		SnapshotSeq:   message.SnapshotSeq,
		GeneratedAtMs: message.GeneratedAtMs,
		SigningKeyID:  message.SigningKeyID,
		BannedIPs:     cloneIPEntries(message.BannedIPs),
		Signature:     append([]byte(nil), message.Signature...),
	}
	cloned.BannedNodeIDs = make([][]byte, 0, len(message.BannedNodeIDs))
	for _, entry := range message.BannedNodeIDs {
		copied := make([]byte, len(entry))
		copy(copied, entry)
		cloned.BannedNodeIDs = append(cloned.BannedNodeIDs, copied)
	}
	return cloned
}

func (c *ConnectionManager) tryApplyAntiFraudSnapshot(snapshot *externalBanlistSnapshot, source string) (bool, error) {
	c.externalBanlistLock.Lock()
	defer c.externalBanlistLock.Unlock()
	return c.tryApplyAntiFraudSnapshotLocked(snapshot, source)
}

func (c *ConnectionManager) tryApplyAntiFraudSnapshotLocked(snapshot *externalBanlistSnapshot, source string) (bool, error) {
	if snapshot == nil {
		return false, errors.New("snapshot is nil")
	}
	if c.hasExternalSnapshot {
		if snapshot.SnapshotSeq < c.externalSnapshotSeq {
			return false, errors.Errorf("received older snapshot_seq (%d < %d)", snapshot.SnapshotSeq, c.externalSnapshotSeq)
		}
		if snapshot.SnapshotSeq == c.externalSnapshotSeq {
			if snapshot.RootHash != c.externalSnapshotRootHash {
				return false, errors.New("same snapshot_seq with different root_hash")
			}
			return false, nil
		}
	}

	previousMessage := c.antiFraudCurrentSnapshot
	c.externallyBannedIPs = snapshot.IPs
	c.externallyBannedNodeIDs = snapshot.NodeIDs
	c.externalSnapshotSeq = snapshot.SnapshotSeq
	c.externalSnapshotRootHash = snapshot.RootHash
	c.hasExternalSnapshot = true
	c.antiFraudCurrentSnapshot = snapshot.toAppMessage()
	c.antiFraudHashWindow = advanceAntiFraudHashWindow(c.antiFraudHashWindow, snapshot.RootHash)
	_ = c.persistAntiFraudSnapshotsLocked(previousMessage, c.antiFraudCurrentSnapshot)

	log.Infof("Applied anti-fraud snapshot from %s: seq=%d hash=%s", source, snapshot.SnapshotSeq, hex.EncodeToString(snapshot.RootHash[:]))
	return true, nil
}

func (snapshot *externalBanlistSnapshot) toAppMessage() *appmessage.MsgAntiFraudSnapshotV1 {
	if snapshot == nil {
		return nil
	}
	bannedIPs := cloneIPEntries(snapshot.IPEntries)
	bannedNodeIDs := make([][]byte, 0, len(snapshot.NodeIDEntries))
	for _, entry := range snapshot.NodeIDEntries {
		copied := make([]byte, 32)
		copy(copied, entry[:])
		bannedNodeIDs = append(bannedNodeIDs, copied)
	}
	signature := make([]byte, 64)
	copy(signature, snapshot.Signature[:])
	return &appmessage.MsgAntiFraudSnapshotV1{
		SchemaVersion: uint32(snapshot.SchemaVersion),
		Network:       uint32(snapshot.Network),
		SnapshotSeq:   snapshot.SnapshotSeq,
		GeneratedAtMs: snapshot.GeneratedAtMs,
		SigningKeyID:  uint32(snapshot.SigningKeyID),
		BannedIPs:     bannedIPs,
		BannedNodeIDs: bannedNodeIDs,
		Signature:     signature,
	}
}

func advanceAntiFraudHashWindow(current [antiFraudHashWindowLen][32]byte, newHash [32]byte) [antiFraudHashWindowLen][32]byte {
	if newHash == ([32]byte{}) || current[0] == newHash {
		return current
	}
	ordered := make([][32]byte, 0, antiFraudHashWindowLen)
	ordered = append(ordered, newHash)
	for _, hash := range current {
		if hash == ([32]byte{}) {
			continue
		}
		exists := false
		for _, existing := range ordered {
			if existing == hash {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		ordered = append(ordered, hash)
		if len(ordered) == antiFraudHashWindowLen {
			break
		}
	}
	var result [antiFraudHashWindowLen][32]byte
	for i := 0; i < len(ordered) && i < antiFraudHashWindowLen; i++ {
		result[i] = ordered[i]
	}
	return result
}

func antiFraudPersistPath(baseDir string, name string) string {
	if baseDir == "" {
		return ""
	}
	return filepath.Join(baseDir, antiFraudPersistDir, name)
}

func (c *ConnectionManager) tryLoadPersistedAntiFraudSnapshot() {
	if c.cfg == nil || c.cfg.AppDir == "" {
		return
	}
	currentPath := antiFraudPersistPath(c.cfg.AppDir, antiFraudCurrentFile)
	previousPath := antiFraudPersistPath(c.cfg.AppDir, antiFraudPreviousFile)
	loaded := c.loadPersistedSnapshotFile(currentPath)
	if loaded == nil {
		loaded = c.loadPersistedSnapshotFile(previousPath)
	}
	if loaded == nil {
		return
	}
	if _, err := c.tryApplyAntiFraudSnapshot(loaded, "disk"); err != nil {
		log.Warnf("Ignoring persisted anti-fraud snapshot: %s", err)
	}
}

func (c *ConnectionManager) loadPersistedSnapshotFile(path string) *externalBanlistSnapshot {
	if path == "" {
		return nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var message appmessage.MsgAntiFraudSnapshotV1
	if err := json.Unmarshal(content, &message); err != nil {
		corruptPath := path + ".corrupt"
		_ = os.Rename(path, corruptPath)
		log.Warnf("Quarantined corrupt anti-fraud snapshot file %s -> %s", path, corruptPath)
		return nil
	}
	expectedNetwork, err := antiFraudNetworkFromName(c.cfg.NetParams().Name)
	if err != nil {
		return nil
	}
	snapshot, err := decodeExternalBanlistSnapshotFromMessage(&message, expectedNetwork)
	if err != nil {
		log.Warnf("Invalid persisted anti-fraud snapshot in %s: %s", path, err)
		return nil
	}
	return snapshot
}

func (c *ConnectionManager) persistAntiFraudSnapshotsLocked(previous *appmessage.MsgAntiFraudSnapshotV1, current *appmessage.MsgAntiFraudSnapshotV1) error {
	if c.cfg == nil || c.cfg.AppDir == "" || current == nil {
		return nil
	}
	currentPath := antiFraudPersistPath(c.cfg.AppDir, antiFraudCurrentFile)
	previousPath := antiFraudPersistPath(c.cfg.AppDir, antiFraudPreviousFile)
	if currentPath == "" || previousPath == "" {
		return nil
	}
	if previous != nil {
		if err := writeAntiFraudSnapshotAtomic(previousPath, previous); err != nil {
			return err
		}
	}
	return writeAntiFraudSnapshotAtomic(currentPath, current)
}

func writeAntiFraudSnapshotAtomic(path string, snapshot *appmessage.MsgAntiFraudSnapshotV1) error {
	if snapshot == nil {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	content, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	tempPath := path + ".tmp"
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func canonicalIPString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

func (c *ConnectionManager) isAddressExternallyBanned(address string) (bool, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false, errors.Wrapf(err, "could not split host and port from %s", address)
	}

	if parsedIP := net.ParseIP(host); parsedIP != nil {
		return c.isIPExternallyBanned(parsedIP), nil
	}

	if c.cfg.Lookup == nil {
		return false, errors.New("address lookup function is not configured")
	}

	resolvedIPs, err := c.cfg.Lookup(host)
	if err != nil {
		return false, errors.Wrapf(err, "could not resolve %s", host)
	}

	for _, resolvedIP := range resolvedIPs {
		if c.isIPExternallyBanned(resolvedIP) {
			return true, nil
		}
	}

	return false, nil
}

func (c *ConnectionManager) isIPExternallyBanned(ip net.IP) bool {
	canonicalIP := canonicalIPString(ip)
	if canonicalIP == "" {
		return false
	}

	c.externalBanlistLock.RLock()
	defer c.externalBanlistLock.RUnlock()

	_, ok := c.externallyBannedIPs[canonicalIP]
	return ok
}

// IsUnifiedNodeIDBanned returns true if the given unified node ID is blocked either locally or by external antifraud banlist.
func (c *ConnectionManager) IsUnifiedNodeIDBanned(nodeID [32]byte) bool {
	if c.IsUnifiedNodeIDLocallyBanned(nodeID) {
		return true
	}

	c.externalBanlistLock.RLock()
	defer c.externalBanlistLock.RUnlock()

	_, ok := c.externallyBannedNodeIDs[hex.EncodeToString(nodeID[:])]
	return ok
}
func (c *ConnectionManager) isNetConnectionExternallyBanned(netConnection *netadapter.NetConnection) bool {
	if netConnection == nil {
		return false
	}
	unifiedNodeID, hasUnifiedNodeID := netConnection.UnifiedNodeID()
	unifiedNodeIDBanned := hasUnifiedNodeID && c.IsUnifiedNodeIDBanned(unifiedNodeID)

	return c.isIPExternallyBanned(netConnection.NetAddress().IP) ||
		unifiedNodeIDBanned
}

func (c *ConnectionManager) disconnectExternallyBannedConnections(connections []*netadapter.NetConnection) {
	for _, connection := range connections {
		if connection == nil {
			continue
		}

		ipAddress := connection.NetAddress().IP
		ipBanned := c.isIPExternallyBanned(ipAddress)
		unifiedNodeID, hasUnifiedNodeID := connection.UnifiedNodeID()
		unifiedNodeIDBanned := hasUnifiedNodeID && c.IsUnifiedNodeIDBanned(unifiedNodeID)
		if !ipBanned && !unifiedNodeIDBanned {
			continue
		}

		if ipBanned {
			log.Infof("Disconnecting %s due to external antifraud IP ban %s", connection, canonicalIPString(ipAddress))
		}
		if unifiedNodeIDBanned {
			log.Infof("Disconnecting %s due to external antifraud unified node ID ban %s", connection, hex.EncodeToString(unifiedNodeID[:]))
		}
		connection.Disconnect()
	}
}
