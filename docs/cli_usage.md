# CLI Usage

The `tacita` crate now provides four role-oriented local binaries:

- `tacita-client`
- `tacita-server`
- `tacita-committee`
- `tacita-sim`

This first version is file-based and local only. It does not add networking or distributed persistence. Each command reads a shared TOML config file, reconstructs the deterministic toy backends locally, and reads or writes explicit protocol message files in JSON.

## Shared Config

Example `config/tacita-local.toml`:

```toml
[protocol]
registration_epoch = 1
threshold = 2
expected_clients = 3
committee_size = 4

[round]
round_id = 5
threshold = 2
expected_clients = 3
expected_committee_members = 4

[toy_ste]
committee_size = 4
slot_count = 2
threshold = 2
seed = 2026
max_discrete_log = 32

[toy_mklhts]
expected_clients = 3
seed = 3291

client_ids = [0, 1, 2]
committee_member_ids = [0, 1, 2, 3]
```

## Offline Stage

Client signing-key registration:

```bash
cargo run -p tacita --bin tacita-client -- register \
  --config config/tacita-local.toml \
  --client-id 0 \
  --out work/client-0-registration.json
```

Committee encryption-key registration:

```bash
cargo run -p tacita --bin tacita-committee -- register \
  --config config/tacita-local.toml \
  --committee-member-id 0 \
  --out work/committee-0-registration.json
```

Server aggregate-material derivation:

```bash
cargo run -p tacita --bin tacita-server -- derive-aggregate-material \
  --config config/tacita-local.toml \
  --client-registration work/client-0-registration.json \
  --client-registration work/client-1-registration.json \
  --client-registration work/client-2-registration.json \
  --committee-registration work/committee-0-registration.json \
  --committee-registration work/committee-1-registration.json \
  --committee-registration work/committee-2-registration.json \
  --committee-registration work/committee-3-registration.json \
  --out work/aggregate-material.json
```

## Online Round

Client encrypt-and-sign submission:

```bash
cargo run -p tacita --bin tacita-client -- submit \
  --config config/tacita-local.toml \
  --aggregate-material work/aggregate-material.json \
  --client-id 0 \
  --plaintext 1,2 \
  --out work/client-0-submission.json
```

Server aggregate:

```bash
cargo run -p tacita --bin tacita-server -- aggregate \
  --config config/tacita-local.toml \
  --aggregate-material work/aggregate-material.json \
  --submission work/client-0-submission.json \
  --submission work/client-1-submission.json \
  --submission work/client-2-submission.json \
  --out work/aggregate-bundle.json
```

Committee verify-and-partial-decrypt:

```bash
cargo run -p tacita --bin tacita-committee -- partial-decrypt \
  --config config/tacita-local.toml \
  --aggregate-material work/aggregate-material.json \
  --aggregate-bundle work/aggregate-bundle.json \
  --committee-member-id 0 \
  --out work/partial-0.json
```

Server finalize:

```bash
cargo run -p tacita --bin tacita-server -- finalize \
  --config config/tacita-local.toml \
  --aggregate-material work/aggregate-material.json \
  --aggregate-bundle work/aggregate-bundle.json \
  --partial-decryption work/partial-0.json \
  --partial-decryption work/partial-1.json \
  --out work/result.json
```

## Single-Process Simulation

The simulator binary preserves the single-process testing path:

```bash
cargo run -p tacita --bin tacita-sim -- round \
  --config config/tacita-local.toml \
  --inputs '1,2;3,4;5,6' \
  --out work/sim-round.json
```

The simulator output includes:

- the offline transcript
- the online transcript
- the final aggregate result

## Notes

- The message files are JSON wrappers around the explicit Tacita protocol message types.
- The current local CLI reconstructs deterministic toy primitive state from the shared config file rather than loading a production key store.
- This is intentional for the first file-based version: correctness and explicit stage boundaries come first, before any networking or persistence work.
