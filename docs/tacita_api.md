# Tacita API

This document describes the new top-level `tacita` crate, which is intended to become the clean end-to-end orchestration layer for the Tacita protocol described in [docs/ccs2026a-paper3291.pdf](/Users/varun/Documents/tacita-impl/docs/ccs2026a-paper3291.pdf).

## Goal

The `tacita` crate does not redesign the cryptographic protocol. Instead, it provides:

- explicit protocol message types
- role-oriented APIs for client, server, and committee logic
- abstract primitive boundaries for STE and MKLHTS
- a single-process simulator skeleton that wires the roles together at the API level

This keeps the end-to-end protocol structure explicit while allowing the existing `ste` and `hints` crates to continue evolving as primitive implementations.

## Crate Layout

- `tacita/src/types.rs`
  - explicit message and transport structs
- `tacita/src/config.rs`
  - protocol and round configuration types
- `tacita/src/errors.rs`
  - shared `TacitaError`
- `tacita/src/primitives.rs`
  - abstract STE and MKLHTS trait boundaries
- `tacita/src/client.rs`
  - client role API
- `tacita/src/server.rs`
  - server role API
- `tacita/src/committee.rs`
  - committee role API
- `tacita/src/simulator.rs`
  - single-process simulator skeleton
- `tacita/src/lib.rs`
  - crate root and legacy re-exports of `ste` and `hints`

## Explicit Message Types

The crate defines the following protocol-level message types:

- `ClientSigningKeyRegistration`
- `CommitteeEncryptionKeyRegistration`
- `CommitteeAggregateKeyMaterial`
- `ClientSubmission`
- `ServerAggregateBundle`
- `CommitteePartialDecryption`
- `ServerAggregateResult`

These types are generic over their cryptographic payloads, with opaque placeholder defaults. This keeps the API explicit without forcing the top-level protocol crate to commit to the current internal function layouts of `ste` or `hints`.

## Primitive Boundaries

The key abstraction layer is in [`tacita/src/primitives.rs`](/Users/varun/Documents/tacita-impl/tacita/src/primitives.rs):

- `StePrimitive`
  - committee key registration
  - aggregate key derivation
  - encryption
  - ciphertext aggregation
  - partial decryption
  - final decryption

- `MklhtsPrimitive`
  - client signing-key registration
  - aggregate verification-key derivation
  - submission signing
  - signature aggregation
  - aggregate-signature verification

The `tacita` role APIs depend on these traits, not on the current `ste` or `hints` function layouts.

## Intended Flow

### Registration / offline setup

1. Clients produce `ClientSigningKeyRegistration`.
2. Committee members produce `CommitteeEncryptionKeyRegistration`.
3. The simulator or orchestration layer derives `CommitteeAggregateKeyMaterial`.

### Online round

1. A `Client` encrypts its input with STE and signs the ciphertext with MKLHTS, producing `ClientSubmission`.
2. The `Server` aggregates all client submissions into `ServerAggregateBundle`.
3. Each `CommitteeMember` verifies the aggregate signature and, if valid, emits `CommitteePartialDecryption`.
4. The `Server` combines the partial decryptions to produce `ServerAggregateResult`.

## Current Integration Blocker

The `tacita` crate depends on the existing `ste` and `hints` crates, but direct concrete adapter implementations are intentionally not added yet.

The current blocker is the primitive split:

- `ste` uses arkworks `0.5.x`
- `hints` uses arkworks `0.4.x`

That makes direct shared cryptographic value plumbing unsafe to normalize casually. To avoid silently changing transcript formats, serialization assumptions, or proof semantics, the blocker is isolated behind traits and surfaced explicitly in the simulator skeleton through `TacitaError::VersionSplitBlocked`.

In other words:

- the top-level protocol API exists now
- the role wiring exists now
- the concrete `ste` and `hints` adapter layer should be added only once the primitive boundary is stabilized, or once the arkworks split is resolved deliberately

## Legacy Flows

The legacy demo and benchmark flows remain available in the primitive crates as examples. The `tacita` crate is not yet a CLI layer and does not add final client/server/committee commands in this step.
