# AntiFraud HF v1 State Machine

This state machine is normative for the signed AntiFraud connection banlist after payload hardfork activation.

Before the payload hardfork activates, nodes may fetch and relay snapshots, but connection enforcement is optional. After activation, a node rejects or disconnects peers whose IP address or verified unified node ID is present in the active signed banlist.

## Local State
- `last_valid_snapshot` (optional)
- `last_valid_seq` (`u64`, implicit in snapshot)
- `hash_window[3]` newest-first (`[h0, h1, h2]`) for version-message metadata only
- `seed_enabled` (operator configuration)
- `peer_fallback_active`

## Snapshot Acceptance
A candidate snapshot is accepted only if all checks pass:
1. Signature valid over canonical `root_hash`
2. `network` matches local network
3. Sanitization succeeds
4. Count limits are within maxima
5. `antifraud_enabled == true`
6. Rollback rules:
   - `snapshot_seq < last_valid_seq` => reject
   - `snapshot_seq == last_valid_seq` AND `root_hash != current_root_hash` => reject + conflict log

Signed snapshots with `antifraud_enabled == false` are validly parsed, but they are not applied and do not disable local runtime state.

## Source Strategy
- With the seed enabled, use the primary signed AntiFraud seed endpoint.
- If the seed fetch or validation fails twice in a row, keep the current state and enter peer fallback.
- With `--no-external-banlist`, `--no-banserver`, or `--antifraud-no-seed`, do not query the seed and use peer fallback directly.
- If no source can provide a valid newer snapshot, keep the last valid snapshot and continue retrying.

Selection among peer candidates:
1. Keep only candidates with highest `snapshot_seq`
2. Strict majority on `root_hash` within that highest sequence (`votes > n/2`)
3. If no strict majority exists, do not update

## Enforcement
The AntiFraud list has one role: connection filtering.

Enforced checks:
- Do not initiate or accept connections to banned IPs
- Disconnect active peers whose IP becomes banned
- After hardfork activation, disconnect peers whose verified unified node ID is banned

Not enforced by AntiFraud:
- Block acceptance
- Block producer claim validity
- Transaction relay
- Block relay or IBD flow registration
- Protocol mode restriction based on hash-window overlap

## Boot/Persistence
- Persist `current.snapshot` and `previous.snapshot` atomically (`temp -> fsync -> rename`)
- Corrupt snapshot files are ignored/quarantined; node continues
- Persisted snapshots with `antifraud_enabled == false` are ignored
- If no valid snapshot is available, keep runtime enabled for peer fallback/no-seed mode and wait for signed peer-majority data
