# STE API

The `ste` crate now exposes a stage-oriented public surface intended for the `tacita` crate and other protocol orchestration code.

## Public modules

- `ste::setup`
  - CRS and key-generation material.
  - Main entry points: `CRS`, `LagPolys`, `SecretKey`, `PublicKey`, `LagPublicKey`.
- `ste::encryption`
  - Ciphertext creation against an aggregate encryption key.
  - Main entry points: `Ciphertext`, `EncryptionKey`, `encrypt`.
- `ste::aggregation`
  - Aggregation-time key material and ciphertext combination.
  - Main entry points: `AggregateKey`, `EncryptionKey`, `SystemPublicKeys`, `aggregate_key_material`, `aggregate_ciphertexts`, `build_system_public_keys`.
- `ste::partial_decryption`
  - Individual committee-share production.
  - Main entry points: `PartialDecryption`, `compute_partial_decryption`, `zero_partial_decryption`.
- `ste::final_decryption`
  - Final threshold combine step from aggregate ciphertext plus partial decryptions.
  - Main entry point: `finalize_decryption`.

## Intended Tacita mapping

- Committee registration and key setup:
  - construct `CRS`
  - generate `SecretKey`
  - derive `LagPublicKey` or `PublicKey`
- Committee aggregate key material:
  - call `ste::aggregation::aggregate_key_material`
- Client submission encryption:
  - call `ste::encryption::encrypt`
- Server aggregation:
  - call `ste::aggregation::aggregate_ciphertexts`
- Committee online decryption shares:
  - call `ste::partial_decryption::compute_partial_decryption`
- Server final result recovery:
  - call `ste::final_decryption::finalize_decryption`

## Compatibility notes

- The underlying cryptographic implementation is unchanged in this refactor. This is an API-surface cleanup, not a redesign of the STE primitive.
- Legacy benchmark-style execution is still available as the example `legacy_ste_bench`.
- Internal support modules such as `decryption`, `utils`, and `utils2` are no longer intended as integration entry points.
