# Implementation of Tacita

This repository contains a Rust implementation of **silent threshold encryption** and **multikey linearly homomorphic threshold signatures** .  
Both are provided as standalone binaries with `main` functions that can be modified to experiment with different parameters.  
Each program outputs the runtimes of the protocol functions it executes.

---

## Project Structure

- `ste/`  
  Implements the **silent threshold encryption protocol**.  
  The `main.rs` file runs the full encryption pipeline with configurable parameters and reports runtimes for each phase.

- `hints/`  
  Implements the **multikey linearly homomorphic threshold signatures protocol** .  
  The `main.rs` file allows experimenting with parameters and outputs runtimes of each function.

---

## How to Build

Make sure you have [Rust](https://www.rust-lang.org/) installed.

```
# Build all binaries
cargo build --release
```

## How to Run

Run either binary with cargo run. You can modify the main functions in each crate to change parameters (e.g., number of participants and threshold).

```
# Run silent threshold signatures
cargo run --release -p silent-threshold

# Run hints
cargo run --release -p hints
```



