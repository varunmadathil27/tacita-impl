# AGENTS.md

## Project Context

This repository is a research prototype for the Tacita secure aggregation protocol.

- The protocol specification is the paper at [docs/ccs2026a-paper3291.pdf](/Users/varun/Documents/tacita-impl/docs/ccs2026a-paper3291.pdf).
- Treat the paper as the primary source of truth for protocol behavior.
- Prefer paper-faithful behavior over premature optimization.
- Do not redesign the cryptographic protocol.

## Protocol Discipline

- Keep offline and online costs separate in both code structure and measurement.
- Do not hide offline precomputation inside online timing.
- Do not silently change transcript or serialization formats.
- Prefer small, explicit message types over implicit cross-module Rust values.
- Flag cryptographic ambiguities instead of guessing.

## Architecture Direction

- The end goal is a clean end-to-end implementation with separate client, server, and committee commands.
- Keep the protocol roles explicit in APIs, modules, and message types.
- Preserve a clear boundary between reusable cryptographic primitives and end-to-end protocol orchestration.
- Until the primitives are stabilized, keep legacy demo flows available as examples.

## Implementation Guidance

- When behavior in code and paper differ, pause and reconcile them explicitly rather than normalizing the code by assumption.
- Prefer refactors that clarify protocol stages, role ownership, and message flow.
- Avoid introducing hidden coupling between `ste`, `hints`/MKLHTS logic, and future end-to-end orchestration code.
- If a change affects transcripts, serialization, timing boundaries, or proof semantics, call that out explicitly in docs and review notes.

## Working Style

- Make one architectural change at a time.
- Keep compileability as a goal.
- When blocked, write the blocker clearly in `docs/`.
