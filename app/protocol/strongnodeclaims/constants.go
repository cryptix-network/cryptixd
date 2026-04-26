package strongnodeclaims

const (
	// Locked Rev3 protocol constants
	CLAIM_WINDOW_SIZE_BLOCKS           = 1000
	CLAIM_REORG_MARGIN_BLOCKS          = 256
	KNOWN_CLAIMS_PER_BLOCK_CAP         = 64
	PENDING_UNKNOWN_CLAIMS_CAP         = 4096
	PENDING_UNKNOWN_CLAIMS_TTL_SECONDS = 180
)

const (
	claimSchemaVersion    = uint32(1)
	claimStateSchemaV1    = uint32(1)
	claimsStateDirName    = "strong-node-claims"
	claimsCurrentFilename = "current.snapshot"
	claimsPreviousFile    = "previous.snapshot"
)
