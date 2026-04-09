package connmanager

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	urlpkg "net/url"
	"regexp"
	"strings"
	"time"

	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/id"
	secp256k1 "github.com/cryptix-network/go-secp256k1"
	"github.com/pkg/errors"
	"github.com/zeebo/blake3"
)

const (
	externalBanlistFetchInterval   = 5 * time.Minute
	externalBanlistRequestTimeout  = 10 * time.Second
	externalBanlistMaxResponseSize = 2 * 1024 * 1024
	externalBanlistMaxIPs          = 4096
	externalBanlistMaxNodeIDs      = 4096
	externalBanlistMaxEntryLength  = 256
	strongNodeIDHexLength          = 64
	strongNodeIDRawLength          = 32
	strongNodeSchemaVersion        = 1
	strongNodeAnnouncementMaxBytes = 2048
	strongNodeAcceptAgeMs          = 20 * 60 * 1000
	strongNodeFutureSkewMs         = 2 * 60 * 1000
	strongNodeWindowMs             = 10 * 60 * 1000
	strongNodeWindowToleranceMs    = 30 * 1000
	strongNodeNetworkMaxLen        = 64
)

var userAgentStrongNodeIDRegex = regexp.MustCompile(`(?i)strong-?id=([0-9a-f]{64})`)

var strongNodeDomainTag = []byte("StrongNodeAnnouncement/v1")

type externalBanlistResponse struct {
	Status  string   `json:"status"`
	IPs     []string `json:"ips"`
	NodeIDs []string `json:"node_ids"`
}

func (c *ConnectionManager) externalBanlistEnabled() bool {
	return c != nil && c.cfg != nil && c.cfg.EnableExternalBanlist
}

func (c *ConnectionManager) refreshExternalBanlistIfNeeded(now time.Time) {
	if !c.externalBanlistEnabled() {
		return
	}

	c.externalBanlistLock.RLock()
	nextFetch := c.nextExternalBanlistFetch
	c.externalBanlistLock.RUnlock()
	if !nextFetch.IsZero() && now.Before(nextFetch) {
		return
	}

	ips, nodeIDs, err := c.fetchExternalBanlist()

	c.externalBanlistLock.Lock()
	c.nextExternalBanlistFetch = now.Add(externalBanlistFetchInterval)
	c.externalBanlistLock.Unlock()

	if err != nil {
		log.Warnf("External antifraud banlist refresh failed: %s", err)
		return
	}

	c.externalBanlistLock.Lock()
	c.externallyBannedIPs = ips
	c.externallyBannedNodeIDs = nodeIDs
	c.externalBanlistLock.Unlock()

	log.Infof("External antifraud banlist refreshed: %d IPs, %d node IDs",
		len(ips), len(nodeIDs))
}

func (c *ConnectionManager) fetchExternalBanlist() (map[string]struct{}, map[string]struct{}, error) {
	if c.cfg == nil {
		return nil, nil, errors.New("connection manager config is nil")
	}

	candidates := externalBanlistCandidateURLs(c.cfg.ExternalBanlistURL)
	if len(candidates) == 0 {
		return nil, nil, errors.Errorf("invalid external banlist URL %q", c.cfg.ExternalBanlistURL)
	}

	var lastErr error
	for index, candidate := range candidates {
		ips, nodeIDs, err := c.fetchExternalBanlistFromURL(candidate)
		if err != nil {
			lastErr = err
			continue
		}

		if index > 0 {
			log.Warnf("External antifraud banlist fetched via fallback URL %s", candidate)
		}
		return ips, nodeIDs, nil
	}

	return nil, nil, errors.Wrap(lastErr, "failed to fetch external banlist from all configured endpoints")
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

func (c *ConnectionManager) fetchExternalBanlistFromURL(endpoint string) (map[string]struct{}, map[string]struct{}, error) {
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
		return nil, nil, err
	}
	request.Header.Set("Accept", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, nil, errors.Errorf("unexpected status code %d", response.StatusCode)
	}

	limitedBodyReader := io.LimitReader(response.Body, externalBanlistMaxResponseSize+1)
	responseBody, err := io.ReadAll(limitedBodyReader)
	if err != nil {
		return nil, nil, err
	}
	if len(responseBody) > externalBanlistMaxResponseSize {
		return nil, nil, errors.Errorf("response body exceeded max size of %d bytes", externalBanlistMaxResponseSize)
	}

	return decodeExternalBanlistPayload(responseBody)
}

func decodeExternalBanlistPayload(payload []byte) (map[string]struct{}, map[string]struct{}, error) {
	var parsed externalBanlistResponse
	err := json.Unmarshal(payload, &parsed)
	if err != nil {
		return nil, nil, err
	}

	if parsed.Status != "" && !strings.EqualFold(parsed.Status, "success") {
		return nil, nil, errors.Errorf("banlist endpoint returned non-success status %q", parsed.Status)
	}

	normalizedIPs := normalizeExternalBanlistIPs(parsed.IPs, externalBanlistMaxIPs)
	normalizedNodeIDs := normalizeExternalBanlistNodeIDs(parsed.NodeIDs, externalBanlistMaxNodeIDs)

	return normalizedIPs, normalizedNodeIDs, nil
}

func normalizeExternalBanlistIPs(rawIPs []string, maxEntries int) map[string]struct{} {
	normalized := make(map[string]struct{})

	for _, rawIP := range rawIPs {
		if len(normalized) >= maxEntries {
			break
		}

		candidate := strings.TrimSpace(rawIP)
		if candidate == "" || len(candidate) > externalBanlistMaxEntryLength {
			continue
		}

		parsedIP := net.ParseIP(candidate)
		if parsedIP == nil {
			continue
		}

		normalized[canonicalIPString(parsedIP)] = struct{}{}
	}

	return normalized
}

func normalizeExternalBanlistNodeIDs(rawNodeIDs []string, maxEntries int) map[string]struct{} {
	normalized := make(map[string]struct{})

	for _, rawNodeID := range rawNodeIDs {
		if len(normalized) >= maxEntries {
			break
		}

		candidate := strings.ToLower(strings.TrimSpace(rawNodeID))
		if candidate == "" || len(candidate) > externalBanlistMaxEntryLength {
			continue
		}

		if len(candidate) != id.IDLength*2 && len(candidate) != 64 {
			continue
		}

		_, err := hex.DecodeString(candidate)
		if err != nil {
			continue
		}

		normalized[candidate] = struct{}{}
	}

	return normalized
}

func normalizeStrongNodeIDHex(candidate string) (string, bool) {
	cleaned := strings.ToLower(strings.TrimSpace(candidate))
	if len(cleaned) != strongNodeIDHexLength {
		return "", false
	}
	if _, err := hex.DecodeString(cleaned); err != nil {
		return "", false
	}
	return cleaned, true
}

func extractStrongNodeIDFromUserAgent(userAgent string) (string, bool) {
	matches := userAgentStrongNodeIDRegex.FindStringSubmatch(userAgent)
	if len(matches) != 2 {
		return "", false
	}
	return normalizeStrongNodeIDHex(matches[1])
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
	if !c.externalBanlistEnabled() {
		return false, nil
	}

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
	if !c.externalBanlistEnabled() {
		return false
	}

	canonicalIP := canonicalIPString(ip)
	if canonicalIP == "" {
		return false
	}

	c.externalBanlistLock.RLock()
	defer c.externalBanlistLock.RUnlock()

	_, ok := c.externallyBannedIPs[canonicalIP]
	return ok
}

// IsNodeIDBanned returns true if the given peer ID is present in the external antifraud banlist.
func (c *ConnectionManager) IsNodeIDBanned(peerID *id.ID) bool {
	if !c.externalBanlistEnabled() || peerID == nil {
		return false
	}

	c.externalBanlistLock.RLock()
	defer c.externalBanlistLock.RUnlock()

	_, ok := c.externallyBannedNodeIDs[strings.ToLower(peerID.String())]
	return ok
}

// IsStrongNodeIDBanned returns true if the given strong-node ID is present in the external antifraud banlist.
func (c *ConnectionManager) IsStrongNodeIDBanned(strongNodeID string) bool {
	normalizedStrongID, ok := normalizeStrongNodeIDHex(strongNodeID)
	if !ok || !c.externalBanlistEnabled() {
		return false
	}

	c.externalBanlistLock.RLock()
	defer c.externalBanlistLock.RUnlock()

	_, banned := c.externallyBannedNodeIDs[normalizedStrongID]
	return banned
}

// UpdateConnectionStrongNodeIDFromUserAgent parses and stores a strong-node ID from the given user agent.
// It returns the normalized strong-node ID when present and valid.
func (c *ConnectionManager) UpdateConnectionStrongNodeIDFromUserAgent(netConnection *netadapter.NetConnection, userAgent string) string {
	if netConnection == nil {
		return ""
	}

	strongNodeID, ok := extractStrongNodeIDFromUserAgent(userAgent)
	if !ok {
		return ""
	}

	netConnection.SetStrongNodeID(strongNodeID)
	return strongNodeID
}

// ApplyStrongNodeAnnouncement validates and stores strong-node ID metadata from a strong-node announcement.
// It returns the normalized strong-node ID when the announcement is valid.
func (c *ConnectionManager) ApplyStrongNodeAnnouncement(netConnection *netadapter.NetConnection, message *appmessage.MsgStrongNodeAnnouncement) string {
	if netConnection == nil || message == nil {
		return ""
	}

	if message.SchemaVersion != strongNodeSchemaVersion {
		return ""
	}
	if c.cfg == nil || !isCompatibleStrongNodeNetwork(c.cfg.NetParams().Name, message.Network) {
		return ""
	}
	if len(message.Network) == 0 || len(message.Network) > strongNodeNetworkMaxLen {
		return ""
	}
	if len(message.StaticIDRaw) != strongNodeIDRawLength {
		return ""
	}
	if len(message.PubKeyXOnly) != strongNodeIDRawLength {
		return ""
	}
	if len(message.Signature) != 64 {
		return ""
	}
	if claimedIPLen := len(message.ClaimedIP); claimedIPLen != 0 && claimedIPLen != 4 && claimedIPLen != 16 {
		return ""
	}
	if !isStrongNodeAnnouncementWindowValid(message) {
		return ""
	}
	if estimateStrongNodeAnnouncementSize(message) > strongNodeAnnouncementMaxBytes {
		return ""
	}

	digest := blake3.Sum256(message.PubKeyXOnly)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), hex.EncodeToString(message.StaticIDRaw)) {
		return ""
	}
	if !verifyStrongNodeAnnouncementSignature(message) {
		return ""
	}

	strongNodeID := hex.EncodeToString(message.StaticIDRaw)
	netConnection.SetStrongNodeID(strongNodeID)
	return strongNodeID
}

func isStrongNodeAnnouncementWindowValid(message *appmessage.MsgStrongNodeAnnouncement) bool {
	if message.WindowEndMs < message.WindowStartMs {
		return false
	}
	windowLen := message.WindowEndMs - message.WindowStartMs
	if windowLen > strongNodeWindowMs+strongNodeWindowToleranceMs {
		return false
	}

	nowMs := uint64(time.Now().UnixMilli())
	if nowMs+strongNodeFutureSkewMs < message.SentAtMs {
		return false
	}
	if nowMs > message.SentAtMs && nowMs-message.SentAtMs > strongNodeAcceptAgeMs {
		return false
	}
	if message.SentAtMs+strongNodeWindowToleranceMs < message.WindowEndMs {
		return false
	}
	return true
}

func estimateStrongNodeAnnouncementSize(message *appmessage.MsgStrongNodeAnnouncement) int {
	// Conservative upper bound for protobuf framing for this fixed schema.
	size := 0
	size += 1 + maxVarintLen(uint64(message.SchemaVersion))
	size += 1 + maxVarintLen(uint64(len(message.Network))) + len(message.Network)
	size += 1 + maxVarintLen(uint64(len(message.StaticIDRaw))) + len(message.StaticIDRaw)
	size += 1 + maxVarintLen(uint64(len(message.PubKeyXOnly))) + len(message.PubKeyXOnly)
	size += 1 + maxVarintLen(message.SeqNo)
	size += 1 + maxVarintLen(message.WindowStartMs)
	size += 1 + maxVarintLen(message.WindowEndMs)
	size += 1 + maxVarintLen(uint64(message.FoundBlocks10m))
	size += 1 + maxVarintLen(uint64(message.TotalBlocks10m))
	size += 1 + maxVarintLen(message.SentAtMs)
	size += 1 + maxVarintLen(uint64(len(message.ClaimedIP))) + len(message.ClaimedIP)
	size += 1 + maxVarintLen(uint64(len(message.Signature))) + len(message.Signature)
	return size
}

func maxVarintLen(value uint64) int {
	length := 1
	for value >= 0x80 {
		value >>= 7
		length++
	}
	return length
}

func verifyStrongNodeAnnouncementSignature(message *appmessage.MsgStrongNodeAnnouncement) bool {
	preimage := buildStrongNodeAnnouncementPreimage(message)
	digest := blake3.Sum256(preimage)

	var secpHash secp256k1.Hash
	copy(secpHash[:], digest[:])

	pubKey, err := secp256k1.DeserializeSchnorrPubKey(message.PubKeyXOnly)
	if err != nil {
		return false
	}
	signature, err := secp256k1.DeserializeSchnorrSignatureFromSlice(message.Signature)
	if err != nil {
		return false
	}

	return pubKey.SchnorrVerify(&secpHash, signature)
}

func buildStrongNodeAnnouncementPreimage(message *appmessage.MsgStrongNodeAnnouncement) []byte {
	buffer := make([]byte, 0, 256)
	buffer = appendBorshByteSlice(buffer, strongNodeDomainTag)
	buffer = appendU32LE(buffer, message.SchemaVersion)
	buffer = appendBorshString(buffer, message.Network)
	buffer = append(buffer, message.StaticIDRaw...)
	buffer = append(buffer, message.PubKeyXOnly...)
	buffer = appendU64LE(buffer, message.SeqNo)
	buffer = appendU64LE(buffer, message.WindowStartMs)
	buffer = appendU64LE(buffer, message.WindowEndMs)
	buffer = appendU32LE(buffer, message.FoundBlocks10m)
	buffer = appendU32LE(buffer, message.TotalBlocks10m)
	buffer = appendU64LE(buffer, message.SentAtMs)
	buffer = appendBorshByteSlice(buffer, message.ClaimedIP)
	return buffer
}

func appendBorshString(buffer []byte, value string) []byte {
	return appendBorshByteSlice(buffer, []byte(value))
}

func appendBorshByteSlice(buffer []byte, value []byte) []byte {
	buffer = appendU32LE(buffer, uint32(len(value)))
	buffer = append(buffer, value...)
	return buffer
}

func appendU32LE(buffer []byte, value uint32) []byte {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], value)
	return append(buffer, bytes[:]...)
}

func appendU64LE(buffer []byte, value uint64) []byte {
	var bytes [8]byte
	binary.LittleEndian.PutUint64(bytes[:], value)
	return append(buffer, bytes[:]...)
}

func isCompatibleStrongNodeNetwork(localNetwork, remoteNetwork string) bool {
	if localNetwork == remoteNetwork {
		return true
	}
	return isTestnetNetworkAlias(localNetwork) && isTestnetNetworkAlias(remoteNetwork)
}

func isTestnetNetworkAlias(name string) bool {
	return name == "cryptix-testnet" || strings.HasPrefix(name, "cryptix-testnet-")
}

func (c *ConnectionManager) isNetConnectionExternallyBanned(netConnection *netadapter.NetConnection) bool {
	if netConnection == nil {
		return false
	}

	return c.isIPExternallyBanned(netConnection.NetAddress().IP) ||
		c.IsNodeIDBanned(netConnection.ID()) ||
		c.IsStrongNodeIDBanned(netConnection.StrongNodeID())
}

func (c *ConnectionManager) disconnectExternallyBannedConnections(connections []*netadapter.NetConnection) {
	if !c.externalBanlistEnabled() {
		return
	}

	for _, connection := range connections {
		if connection == nil {
			continue
		}

		ipAddress := connection.NetAddress().IP
		ipBanned := c.isIPExternallyBanned(ipAddress)
		nodeIDBanned := c.IsNodeIDBanned(connection.ID())
		strongNodeID := connection.StrongNodeID()
		strongNodeIDBanned := c.IsStrongNodeIDBanned(strongNodeID)
		if !ipBanned && !nodeIDBanned && !strongNodeIDBanned {
			continue
		}

		if ipBanned {
			log.Infof("Disconnecting %s due to external antifraud IP ban %s", connection, canonicalIPString(ipAddress))
		}
		if nodeIDBanned {
			log.Infof("Disconnecting %s due to external antifraud node ID ban %s", connection, connection.ID())
		}
		if strongNodeIDBanned {
			log.Infof("Disconnecting %s due to external antifraud strong-node ID ban %s", connection, strongNodeID)
		}
		connection.Disconnect()
	}
}
