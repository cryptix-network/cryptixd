# Unified Node Identity HF v1

## Summary
- One node identity system is used for policy/authentication:
  - `node_id = BLAKE3-256(pubkey_xonly_32)`
- Identity is persisted in `strong-nodes/node_identity.json` with:
  - `secret_key`, `public_key_xonly`, `static_id_raw`, `pow_nonce`
- PoW is validated only during handshake.

## Handshake Fields (`VersionMessage`)
- `nodePubkeyXonly: bytes` (exactly 32 bytes when present)
- `nodePowNonce: optional uint64`

## PoW Canonical Input
`SHA-256` over exact byte sequence:
1. `domain_sep` bytes: UTF-8 `cryptix-node-id-pow-v1`
2. `network_u8` (1 byte): `0=mainnet, 1=testnet, 2=devnet, 3=simnet`
3. `pubkey_xonly` (32 bytes)
4. `pow_nonce_be64` (8 bytes, big-endian)

Acceptance:
- `k=20` for mainnet
- `k=18` for testnet/devnet/simnet
- valid iff hash has at least `k` leading zero bits

## HF Enforcement
- Pre-HF:
  - missing node identity fields are allowed (legacy compatibility)
- Post-HF:
  - missing or invalid node identity fields are rejected
  - minimum accepted protocol version is `7`
  - existing peers below v7 are disconnected on re-evaluation
