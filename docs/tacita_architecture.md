# Tacita Architecture

This document maps the protocol described in [`docs/ccs2026a-paper3291.pdf`](/Users/varun/Documents/tacita-impl/docs/ccs2026a-paper3291.pdf) onto the current Rust workspace. The repository does not currently contain a single integrated "Tacita" protocol crate; instead it contains separate experimental implementations of STE and MKLHTS-like logic. The goal here is to describe the intended architecture first, then explain how the current code fits or does not fit.

## Protocol Stages

The paper describes four online protocol stages:

1. **Client encryption and signing**
   - Role: client
   - Action: encrypt the private input under the committee public key using STE, then sign the ciphertext under MKLHTS.
   - Output: one encrypted-and-signed contribution sent to the server.

2. **Server aggregation**
   - Role: server
   - Action: aggregate all received ciphertexts into one homomorphic ciphertext and aggregate all client signatures into one succinct aggregate signature.
   - Output: one aggregate bundle sent to the committee.

3. **Committee verification and partial decryption**
   - Role: committee
   - Action: verify that the aggregate MKLHTS signature attests to a threshold number of valid client contributions; only if verification succeeds, each committee member produces one STE partial decryption share bound to the aggregate ciphertext.
   - Output: one partial decryption share per participating committee member sent back to the server.

4. **Final decryption**
   - Role: server
   - Action: combine the STE partial decryption shares and recover the plaintext aggregate sum.
   - Output: the final aggregate plaintext.

## Offline vs Online Work

### Offline

The paper's main architectural trick is to move heavy work out of the online path.

- Clients publish or register their signing public keys.
- Committee members publish or register the public material needed for threshold decryption.
- Committee members precompute or retrieve aggregate public-key material.
- Polynomial/KZG-style preprocessing needed by MKLHTS and STE is prepared before any round begins.
- If a PKI exists, parties can retrieve already-published key material rather than interact per round.

### Online

- Each client sends exactly one message to the server.
- The server sends one aggregate bundle to the committee.
- Each active committee member sends one partial decryption share back to the server.
- The server locally finishes decryption.

The intended online path is therefore one-shot and constant-round.

## Exact Use of MKLHTS and STE by Stage

### Stage 1: Client encryption and signing

- **STE use**: encrypt the client input under the committee encryption key.
- **MKLHTS use**: sign the ciphertext (more precisely, the client contribution bound to the round/tag) so the server cannot substitute, drop, or selectively repackage ciphertexts without detection.

### Stage 2: Server aggregation

- **STE use**: exploit additive homomorphism to add ciphertexts into one ciphertext of the sum.
- **MKLHTS use**: exploit linear homomorphism to aggregate many client signatures into one succinct aggregate signature.

### Stage 3: Committee verification and partial decryption

- **MKLHTS use**: verify that the aggregate signature is valid for a threshold number of client contributions.
- **STE use**: if and only if MKLHTS verification succeeds, each committee member emits a partial decryption share for the aggregate ciphertext.

### Stage 4: Final decryption

- **STE use**: combine the partial decryptions to recover the aggregate plaintext.
- **MKLHTS use**: none at this stage; its job is already complete once verification gates decryption.

## Message Types That Should Exist

The current code mostly passes Rust values directly between functions. A complete Tacita architecture should expose explicit message types.

### Offline / registration material

- `ClientSigningKeyRegistration`
  - `client_id`
  - MKLHTS verification key
  - proof/certificate from PKI if applicable

- `CommitteeEncryptionKeyRegistration`
  - `committee_member_id`
  - STE public material needed for aggregation/decryption
  - proof/certificate from PKI if applicable

- `CommitteeAggregateKeyMaterial`
  - round-independent aggregate verification/decryption material derived offline

### Online protocol messages

- `ClientSubmission`
  - `round_id`
  - `client_id`
  - STE ciphertext
  - MKLHTS signature over the ciphertext and round binding data

- `ServerAggregateBundle`
  - `round_id`
  - aggregated STE ciphertext
  - aggregated MKLHTS signature
  - metadata needed to verify what was aggregated
  - any bitmap/weight/threshold proof material required by the MKLHTS verifier

- `CommitteePartialDecryption`
  - `round_id`
  - `committee_member_id`
  - STE partial decryption share
  - optional proof that the share is well formed

- `ServerAggregateResult`
  - `round_id`
  - recovered aggregate plaintext
  - optional audit metadata

The most important architectural point is that there should be no per-client server-to-committee fanout. The server should send one aggregate bundle, and the committee should answer with one share per member.

## Invariants After Each Stage

### After Stage 1

- Each accepted client contribution contains exactly one STE ciphertext and one MKLHTS signature.
- The ciphertext is bound to the round and intended committee key.
- The signature binds the client to that ciphertext so the server cannot safely rewrite it.

### After Stage 2

- The aggregate ciphertext decrypts to the sum of exactly the included client inputs.
- The aggregate signature corresponds to the same included set of client contributions.
- The server has only one aggregate bundle, not per-client artifacts for committee verification.

### After Stage 3

- Committee members only release decryption shares if aggregate signature verification succeeds.
- Each partial decryption share is bound to the specific aggregate ciphertext for that round.
- A threshold number of valid shares is sufficient for final decryption, and fewer than threshold shares reveal nothing useful.

### After Stage 4

- The recovered plaintext equals the sum of the included client inputs.
- No individual client plaintext is revealed.
- The server can justify that the recovered sum came from a threshold-authenticated aggregate bundle.

## Current Crate Layout

The workspace currently has two protocol-fragment crates:

- `ste`
  - Implements the modified silent threshold encryption machinery: CRS generation, public-key material, aggregation keys, encryption, partial decryption, and final decryption.
  - This is the closest thing to a reusable library in the current tree.

- `hints`
  - Implements KZG helpers plus a prototype for the MKLHTS-style setup/prove/verify flow.
  - Today it is structured as a benchmark/demo binary, not a reusable library.

### Keep

- Keep `ste` as the home of the STE primitive.
- Keep the KZG and polynomial logic in `hints` as the seed of the MKLHTS primitive.
- Keep the low-level arkworks serialization helpers in `ste/src/utils2.rs` or move them into a shared support crate later.

### Move

- Move `hints` from a binary-oriented prototype into a proper library crate, ideally renamed to `mklhts`.
- Move `hints/src/main.rs` logic into library modules such as `setup`, `sign`, `aggregate`, `prove`, and `verify`.
- Move the end-to-end driver code in `ste/src/main.rs` into `examples/` or a dedicated benchmark binary.
- Add a new top-level crate, e.g. `tacita`, that composes `mklhts` and `ste` into the actual client/server/committee protocol and owns the network message structs above.
- Consolidate duplicated polynomial/KZG utilities if both primitives keep needing them.

### Delete

- Delete `ste/src/mod.rs`; it duplicates `ste/src/lib.rs` and is already inconsistent with it.
- Delete or replace the README run command `cargo run --release -p silent-threshold`; that package does not exist in this workspace.
- Delete binary-only assumptions from `hints` once it is turned into a reusable protocol crate.

## Mapping of Current Code to Intended Stages

### Stage 1 in current code

- `ste/src/encryption.rs`
  - provides the STE ciphertext type and `encrypt`
- `hints/src/signer.rs`
  - attempts to produce per-client signatures and hint material

There is currently no shared round message type joining these into a single `ClientSubmission`.

### Stage 2 in current code

- `ste/src/encryption.rs`
  - `Ciphertext::add` supports homomorphic ciphertext aggregation
- `hints/src/main.rs`
  - `prove` and supporting helpers are the closest approximation to aggregate-signature proof generation

There is currently no server crate or explicit server aggregation API.

### Stage 3 in current code

- `hints/src/main.rs`
  - `verify` is the closest approximation to committee-side aggregate-signature verification
- `ste/src/setup.rs`
  - `SecretKey::partial_decryption`
- `ste/src/decryption.rs`
  - reconstructs the aggregate key components needed for final decryption

There is currently no explicit committee-side share message type, no share verification type, and no integrated "verify-then-decrypt" orchestration layer.

### Stage 4 in current code

- `ste/src/decryption.rs`
  - `agg_dec` performs the final STE reconstruction and returns the recovered message vector

This is the most complete online stage in the current repository.

## Open Issues

- The repository does not yet implement Tacita as an integrated protocol. `ste` and `hints` are separate experiments, with no crate that defines client/server/committee roles, message structs, or the verify-then-decrypt control flow.

- `hints/src/signer.rs` appears inconsistent with the intended MKLHTS logic. In `sign`, `party_i_setup_material` is called with `message` where the setup routine expects a secret key, so the produced hint material is derived from the wrong value.

- `hints/src/signer.rs` also appears to drop accumulated values. The loops building `q1` and `q2` call `.add(...)` but never assign the result back, so the stored `skshint_i` entries remain zero.

- `hints/src/signer.rs` and `hints/src/main.rs` disagree on the shape of `skshint_i`. The signer pushes only two elements, while `prove` reads indices `2` and `3`; as written, those reads always fall back to zero commitments.

- `hints/src/main.rs` computes several aggregated signature-related commitments (`s_q1_com`, `s_q2_com`, `sk_s_q1_com`, `sk_s_q2_com`) and then never uses them in verification. That strongly suggests the current proof system is incomplete relative to the paper.

- The current workspace splits cryptographic dependencies across incompatible arkworks major versions: `hints` uses `0.4.x` while `ste` uses `0.5.x`. That makes direct composition into one protocol crate harder than it should be.

- `ste/src/main.rs` duplicates module declarations instead of consuming the published `ste` library API, and `ste/src/mod.rs` duplicates the module list again. This is a structural smell, not a correctness bug, but it will make integration harder.

- `README.md` is out of sync with the workspace. It tells users to run `cargo run --release -p silent-threshold`, but the actual package name is `ste`.

- The file named by the task, `docs/paper.pdf`, does not exist. The actual paper in the repo is [`docs/ccs2026a-paper3291.pdf`](/Users/varun/Documents/tacita-impl/docs/ccs2026a-paper3291.pdf). That documentation mismatch should be fixed before more automation depends on it.

- Workspace metadata already shows configuration drift: the root workspace still uses the old resolver default, and the `hints` profile settings are ignored because profiles must live at the workspace root.
