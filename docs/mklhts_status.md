# MKLHTS Status

This note summarizes the current status of the refactored `hints` crate as a reusable MKLHTS-oriented library prototype.

## What Is Now Believed Correct

- The crate is no longer organized around one monolithic protocol file. The core flow is now split into:
  - [`hints/src/setup.rs`](/Users/varun/Documents/tacita-impl/hints/src/setup.rs)
  - [`hints/src/signer.rs`](/Users/varun/Documents/tacita-impl/hints/src/signer.rs)
  - [`hints/src/aggregate.rs`](/Users/varun/Documents/tacita-impl/hints/src/aggregate.rs)
  - [`hints/src/prove.rs`](/Users/varun/Documents/tacita-impl/hints/src/prove.rs)
  - [`hints/src/verify.rs`](/Users/varun/Documents/tacita-impl/hints/src/verify.rs)
  - [`hints/src/types.rs`](/Users/varun/Documents/tacita-impl/hints/src/types.rs)

- The old index-based signature/hint vectors have been replaced by explicit typed objects:
  - `SHint`
  - `SkSHint`
  - `ClientSignature`
  - `AggregateProofMaterial`

- The previously identified argument-flow bug in signing has been corrected:
  - `party_i_setup_material` is now fed the signer's secret key, not the message scalar.

- The previously dropped group-addition accumulations in signing have been corrected:
  - message-scaled aggregated commitments are now actually accumulated and stored.

- The previous producer/consumer mismatch for `skshint_i` shape has been removed:
  - `SkSHint` is now explicit and both producer and consumer use the same two-field structure.

- The proof path now carries previously computed aggregate commitments in `AggregateProofMaterial` instead of silently computing and discarding them.

- Focused tests now cover:
  - signer output shape
  - hint-vector lengths
  - aggregate proof input consistency
  - a tiny verify path

## What Remains Paper-Incomplete

- The verifier still only consumes the subset of aggregate proof material that the prior prototype already enforced through pairing checks (`sk_q1_com` and `sk_q2_com`).

- The additional aggregate proof commitments
  - `s_q1_com`
  - `s_q2_com`
  - `sk_s_q1_com`
  - `sk_s_q2_com`
  are now explicit and preserved, but they are not yet tied to a complete verifier-side relation that is clearly justified by the paper text and current prototype.

- The crate still behaves like a research prototype, not a finalized standalone MKLHTS package. The current design improves type safety and module boundaries, but it should not yet be treated as a reviewed production cryptographic implementation.

## Assumptions Still Needing Manual Review

- The message-scaling semantics for the hint commitments need paper-level confirmation.
  - The refactor now consistently multiplies the setup-derived commitments by the message where the old code strongly suggested that intent.
  - This is more internally consistent than the prior code, but it should still be checked against the paper and any original derivation notes.

- The exact role of the extra aggregate proof commitments in the full MKLHTS proof system remains ambiguous from the current code alone.
  - They are preserved and surfaced explicitly rather than guessed away.
  - Their final verifier usage should be added only after reconciling the code with the paper.

- The current `hints` crate still uses arkworks `0.4.x`, while `ste` uses arkworks `0.5.x`.
  - That version split does not block the internal refactor here, but it still blocks direct value-level integration with the top-level `tacita` crate without adapter work.

- The tiny-instance tests establish structural consistency, not a full security proof.
  - Any future tightening of the proof system should be reviewed against the paper before changing transcript or commitment behavior.
