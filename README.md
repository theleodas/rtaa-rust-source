# RTAA/RTAA+ Aggregate Authentication on BLS12-381

A Rust implementation of the RTAA and RTAA+ round-based tag-based aggregate authentication protocols over the BLS12-381 elliptic curve. This repository investigates a security weakness in the original RTAA+ judge mechanism, implements a tag-binding correction, and evaluates both security correctness and computational costs through a suite of reproducible experiments.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Key Features](#2-key-features)
3. [Repository Structure](#3-repository-structure)
4. [Requirements](#4-requirements)
5. [Build Instructions](#5-build-instructions)
6. [Running Experiments](#6-running-experiments)
7. [Experimental Outputs](#7-experimental-outputs)
8. [Experimental Methodology](#8-experimental-methodology)
9. [Security Evaluation](#9-security-evaluation)
10. [Reproducibility](#10-reproducibility)
11. [Limitations](#11-limitations)
12. [License](#12-license)

---

## 1. Project Overview

### Aggregate Authentication

In RTAA, a set of μ devices each hold a secret key and, during a round, produce an authentication tag over their individual measurement data. A verifier can efficiently check the aggregate of all tags via a single multi-pairing equation, checking the cryptographic consistency of the aggregate authentication tags against the reported measurements and public keys. When aggregate verification fails, a **judge** algorithm identifies the misbehaving party through a binary-search procedure over subsets of tags.

### RTAA+ and the Audit Mechanism

RTAA+ extends the base protocol with per-party **audit proofs** (denoted ρ). Each device produces an audit proof alongside its tag, allowing the judge to first filter out entries with invalid proofs before running the binary-search dispute resolution. This is intended to handle cases where a party's tag is structurally malformed (e.g., corrupted in transit) without incorrectly blaming an honest party.

### The Security Weakness

In the original RTAA+ design, the audit proof ρ is computed over a hash `H3(ID, w)` that does not include the authentication tag τ. Because the tag is not bound into the audit hash, an adversary can substitute or swap tags while retaining valid audit proofs. This allows certain manipulations to evade detection by the audit step, causing the judge to either miss the attack or misidentify the responsible party.

### The Tag-Binding Fix

This implementation introduces a corrected audit proof in which the tag τ is included in the hash input: `H3(ID, w, τ)`. With this binding, modifying a tag without recomputing its corresponding audit proof invalidates the proof. This allows the judge to detect inconsistencies between tags and audit proofs. However, a malicious party possessing its secret key may still generate a structurally valid proof for a fraudulent tag; the aggregate authentication check and judge mechanism must handle this case.

### Purpose

This repository provides:

- A complete implementation of RTAA and RTAA+ (original and corrected) on BLS12-381.
- Concrete attack simulations demonstrating the vulnerability and its resolution.
- Computational cost measurements and parameter-sensitivity experiments.

---

## 2. Key Features

- **BLS12-381 pairing operations** using the `bls12_381` crate (zkcrypto) with RFC 9380 hash-to-curve (`ExpandMsgXmd<SHA-256>`) and hash-to-scalar via SHA-512.
- **Aggregate authentication verification** via `multi_miller_loop` with a single final exponentiation, checking the equation `e(Στ_i, g₂) = Π e(H₀(id_i) + g₁·w_i, PK_i)`.
- **Per-party auditing** (`audit_one`): verifies individual audit proofs using a 2-pair pairing check.
- **Batch auditing** (`audit_batch`): random-linear-combination batch verification of all audit proofs in a single multi-pairing.
- **Recursive bisection** (`invalid_set` with `batched=true`): identifies all invalid entries via binary subdivision of batch tests.
- **Hybrid auditing** (`invalid_set_hybrid`): a single batch test as a fast path; falls back to per-party checks only when the batch fails.
- **Judge mechanisms**:
  - `judge_base`: binary search over aggregate authentication checks.
  - `judge_plus_orig`: original RTAA+ judge with unbound audit proofs.
  - `judge_plus_fixed`: corrected RTAA+ judge with tag-bound audit proofs (per-party or batched).
  - `judge_plus_hybrid`: corrected judge using the hybrid auditing strategy.
- **Pedersen-VSS threshold key generation** with configurable number of dealers (ℓ) and threshold (t).
- **Pairing operation instrumentation**: atomic counters track exact numbers of Miller loop invocations and final exponentiations.
- **Six reproducible experiments** covering security correctness, wall-clock timing, pairing counts, and parameter sensitivity.

---

## 3. Repository Structure

```
.
├── README.md               # This file
├── Cargo.toml              # Package manifest and dependency declarations
├── Cargo.lock              # Locked dependency versions for reproducible builds
├── src/
│   └── main.rs             # Complete implementation (290 lines)
├── security_rust.csv       # Security experiment output: attack scenario results
├── timing_rust.csv         # Timing experiment output: wall-clock measurements by μ
├── counts_rust.csv         # Counts experiment output: pairing operation counts by μ
├── ksweep_rust.csv         # k-sweep experiment output: cost vs. message dimension
├── tkgsweep_rust.csv       # TKG sweep experiment output: key generation cost vs. (ℓ, t)
└── invalid_rust.csv        # Invalid-ρ experiment output: judge cost vs. corrupted proofs
```

> **Note:** In the source distribution, the project files reside within an `rtaa_rust/` subdirectory. When preparing the repository, the contents of `rtaa_rust/` should be placed at the repository root so that `Cargo.toml` and `README.md` are at the top level.

### Source Files

| File | Description |
|------|-------------|
| `Cargo.toml` | Defines the `rtaa` crate (v0.1.0, edition 2024) and its six dependencies. |
| `src/main.rs` | Single source file containing all protocol logic, experiment functions, and the `main()` entry point. |

### CSV Output Files

Each CSV file contains results from a previous execution of the corresponding experiment function. These files are provided for reference and can be regenerated by running the experiments (see [Running Experiments](#6-running-experiments)).

---

## 4. Requirements

### Rust Toolchain

- **Rust ≥ 1.85.0** is required. The `Cargo.toml` specifies `edition = "2024"`, which is supported starting from Rust 1.85.0.
- Install via [rustup](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Dependencies

All dependencies are sourced from [crates.io](https://crates.io/) and pinned in `Cargo.lock`:

| Crate | Version | Purpose |
|-------|---------|---------|
| `bls12_381` | 0.8 | BLS12-381 curve operations (with `experimental` feature for hash-to-curve) |
| `group` | 0.13 | Elliptic curve group trait abstractions |
| `ff` | 0.13 | Finite field arithmetic traits |
| `sha2` | 0.9 | SHA-256 (hash-to-curve) and SHA-512 (hash-to-scalar) |
| `rand` | 0.8 | Random number generation |
| `rand_core` | 0.6 | Core randomness traits |

No system-level or platform-specific dependencies are required beyond the Rust toolchain.

---

## 5. Build Instructions

Clone or download the repository, then build in release mode from the repository root:

```bash
cargo build --release
```

The `--release` flag enables compiler optimisations, which is important for obtaining representative timing measurements.

---

## 6. Running Experiments

The implementation provides six experiments, selected by a command-line argument. When no argument is provided, the `security` and `timing` experiments run in sequence.

### Security Experiment

```bash
cargo run --release -- security
```

Generates an honest round with μ = 4 parties, then applies six attack scenarios and records the output of each judge variant. Demonstrates which attacks the original and corrected judge mechanisms detect or misidentify.

### Timing Experiment

```bash
cargo run --release -- timing
```

Measures wall-clock execution time for aggregate verification, base judge, and corrected RTAA+ judge (per-party and batched audit modes) across μ ∈ {5, 10, 20, 40, 80, 160, 320}. Uses k = 20, ℓ = 5, t = 3. Timing values are medians over 7 repetitions (μ ≤ 80) or 3 repetitions (μ > 80).

### Pairing Counts Experiment

```bash
cargo run --release -- counts
```

Counts the exact number of Miller loop invocations and final exponentiations performed by aggregate verification, base judge, and corrected RTAA+ judge (per-party and batched) across μ ∈ {5, 10, 20, 40, 80, 160, 320}. Uses k = 20, ℓ = 5, t = 3.

### k-Sweep Experiment

```bash
cargo run --release -- ksweep
```

Measures per-device authentication time, aggregate verification time, and threshold key generation time as the message vector dimension k varies over {5, 10, 20, 40, 80, 160, 320}. Uses fixed μ = 40, ℓ = 5, t = 3. Verification timing is the median of 5 repetitions.

### TKG Sweep Experiment

```bash
cargo run --release -- tkgsweep
```

Measures threshold key generation time for increasing values of the number of dealers ℓ and threshold t: (ℓ, t) ∈ {(3, 2), (5, 3), (7, 4), (10, 6), (15, 8), (20, 11)}. Uses μ = 1, k = 20. Each measurement is the median of 3 repetitions.

### Invalid-ρ Experiment

```bash
cargo run --release -- invalid
```

Evaluates the cost of judge execution when varying numbers of audit proofs are corrupted. Uses μ = 80, k = 20, ℓ = 5, t = 3. Corrupts m ∈ {0, 1, 2, 4, 8, 16, 32} audit proofs (without corrupting the corresponding tags or data), then measures the corrected RTAA+ judge in per-party, batched, and hybrid audit modes. Each measurement is the median of 3 repetitions.

### Default Execution

```bash
cargo run --release
```

Runs the `security` experiment followed by the `timing` experiment.

---

## 7. Experimental Outputs

All experiment functions print CSV-formatted output to stdout. The repository includes pre-generated output files from a previous execution.

### `security_rust.csv`

| Column | Description |
|--------|-------------|
| `attack` | Name of the attack scenario |
| `verify_rejects` | Whether aggregate authentication (`auth_check`) rejects the manipulated entries |
| `base_judge` | Party identified by `judge_base` |
| `rtaa_plus_original` | Party identified by the original RTAA+ judge (`judge_plus_orig`) |
| `rtaa_plus_fixed` | Output of the corrected RTAA+ judge with per-party audit (`judge_plus_fixed`, `batched=false`); `bot` denotes ⊥ (no cheater identified) |
| `rtaa_plus_fixed_batched` | Output of the corrected RTAA+ judge with batched audit (`judge_plus_fixed`, `batched=true`); `bot` denotes ⊥ |

Contains 6 data rows, one per attack scenario.

### `timing_rust.csv`

| Column | Description |
|--------|-------------|
| `mu` | Number of parties |
| `tkg_s` | Threshold key generation time (seconds) |
| `auth_per_device_s` | Mean per-device authentication time (seconds) |
| `verify_s` | Aggregate verification time, median (seconds) |
| `base_judge_s` | Base judge execution time, median (seconds) |
| `plus_perparty_s` | Corrected RTAA+ judge with per-party audit, median (seconds) |
| `plus_batched_s` | Corrected RTAA+ judge with batched audit, median (seconds) |
| `culprit_ok` | Whether the correct misbehaving party was identified |

Contains 7 data rows for μ ∈ {5, 10, 20, 40, 80, 160, 320}.

### `counts_rust.csv`

| Column | Description |
|--------|-------------|
| `mu` | Number of parties |
| `verify_miller`, `verify_fe` | Miller loops and final exponentiations for aggregate verification |
| `base_miller`, `base_fe` | Miller loops and final exponentiations for `judge_base` |
| `pp_miller`, `pp_fe` | Miller loops and final exponentiations for `judge_plus_fixed` (per-party) |
| `batch_miller`, `batch_fe` | Miller loops and final exponentiations for `judge_plus_fixed` (batched) |

Contains 7 data rows for μ ∈ {5, 10, 20, 40, 80, 160, 320}.

### `ksweep_rust.csv`

| Column | Description |
|--------|-------------|
| `k` | Message vector dimension |
| `auth_per_device_s` | Mean per-device authentication time (seconds) |
| `verify_s` | Aggregate verification time, median (seconds) |
| `tkg_s` | Threshold key generation time (seconds) |

Contains 7 data rows for k ∈ {5, 10, 20, 40, 80, 160, 320}.

### `tkgsweep_rust.csv`

| Column | Description |
|--------|-------------|
| `ell` | Number of dealers in Pedersen-VSS |
| `t` | Reconstruction threshold |
| `tkg_s` | Threshold key generation time, median (seconds) |

Contains 6 data rows for (ℓ, t) ∈ {(3, 2), (5, 3), (7, 4), (10, 6), (15, 8), (20, 11)}.

### `invalid_rust.csv`

| Column | Description |
|--------|-------------|
| `invalid` | Number of corrupted audit proofs |
| `perparty_s` | Judge time with per-party audit, median (seconds) |
| `batched_s` | Judge time with batched audit, median (seconds) |
| `hybrid_s` | Judge time with hybrid audit, median (seconds) |
| `batched_fe` | Number of final exponentiations in batched mode |

Contains 7 data rows for invalid ∈ {0, 1, 2, 4, 8, 16, 32}.

---

## 8. Experimental Methodology

### Round Setup

All experiments use the `make_round(mu, k, ell, t)` function, which performs:

1. **Threshold key generation (Pedersen-VSS)**: `ell` dealers each generate random polynomial pairs of degree `t - 1`. All parties verify all dealers' shares against Pedersen commitments. A subset of `t` parties reconstructs the shared secret θ via Lagrange interpolation. A round key α is derived as `H(θ, round_number, group_id)` using SHA-512, and public parameters γ_j = g₁ · α^(j+1) for j = 0, …, k−1 are computed.

2. **Per-device report generation**: Each of μ devices generates a key pair (sk, pk), a random message vector m of dimension k, and computes w = Σ m_j · α^(j+1). The authentication tag is τ = (H₀(id) + g₁ · w) · sk. Both the corrected audit proof ρ = H₃(id, w, τ) · sk and the original audit proof ρ_old = H₃(id, w) · sk are computed.

### Malicious Scenarios

In the timing, counts, and invalid-ρ experiments, a single party at index μ/2 is made malicious by replacing its tag with a random group element and recomputing the corrected audit proof for the new tag (simulating a party that submits incorrect data with a structurally valid proof for the corrected scheme).

### Timing Methodology

Wall-clock times are measured using `std::time::Instant`. Each measured operation is repeated multiple times and the **median** value is reported:

| Experiment | Repetitions |
|------------|-------------|
| `timing` (μ ≤ 80) | 7 |
| `timing` (μ > 80) | 3 |
| `ksweep` | 5 |
| `tkgsweep` | 3 |
| `invalid` | 3 |

### Pairing Count Methodology

Global atomic counters (`MILLER`, `FINALEXP`) are incremented by the `pairing_check` function each time it is called. The counters are reset before each measured operation. The Miller counter is incremented by the number of pairs in each multi-pairing call; the final exponentiation counter is incremented by one per call.

### Protocol Parameters

Unless otherwise stated, the default parameters across experiments are:

| Parameter | Default | Description |
|-----------|---------|-------------|
| k | 20 | Message vector dimension |
| ℓ | 5 | Number of Pedersen-VSS dealers |
| t | 3 | Reconstruction threshold |
| GID | `b"grp0"` | Group identifier |
| RND | 1 | Round number |

---

## 9. Security Evaluation

The `security` experiment generates an honest round with μ = 4, k = 20, ℓ = 5, t = 3, verifies that the honest round passes full verification, then applies six attack scenarios:

| Attack | Description |
|--------|-------------|
| `swap_w` | Swap the w values of parties P0 and P1, leaving their tags unchanged. |
| `sub_tau` | Replace P0's tag with a random group element, leaving the audit proofs unchanged. |
| `sub_tau_garbage_rho` | Replace P0's tag and both audit proofs with random group elements. |
| `swap_tau` | Swap the tags of P0 and P1, leaving all other fields unchanged. |
| `garbage_rho` | Replace P0's audit proofs with random group elements, leaving the tag and data intact. |
| `malicious_P2` | Replace P2's tag with a random element, then recompute valid audit proofs for the new tag using P2's secret key. This simulates a genuinely malicious party submitting fraudulent data with a structurally consistent proof. |

For each attack, the experiment records:

- Whether aggregate verification (`auth_check`) rejects.
- The output of `judge_base` (binary-search judge without audit filtering).
- The output of `judge_plus_orig` (original RTAA+ judge with unbound audit proofs).
- The output of `judge_plus_fixed` in both per-party and batched modes (corrected RTAA+ judge with tag-bound audit proofs). An output of `bot` (⊥) indicates no data-level cheater was found after filtering entries with invalid audit proofs.

The pre-generated results in `security_rust.csv` show that the corrected judge outputs ⊥ for all attacks that involve only structural manipulation (where no party has actually submitted fraudulent data with a valid proof for the corrected scheme) and correctly identifies P2 in the `malicious_P2` scenario. By contrast, the original judge misidentifies P0 as the culprit in the `garbage_rho` scenario, where P0's audit proof was corrupted but P0's data was not.

---

## 10. Reproducibility

### Regenerating Results

To regenerate any CSV file, run the corresponding experiment and redirect stdout:

```bash
cargo run --release -- security   > security_rust.csv
cargo run --release -- timing     > timing_rust.csv
cargo run --release -- counts     > counts_rust.csv
cargo run --release -- ksweep     > ksweep_rust.csv
cargo run --release -- tkgsweep   > tkgsweep_rust.csv
cargo run --release -- invalid    > invalid_rust.csv
```

### Determinism

- The **security** experiment: structural outcomes (which judge variants detect each attack and whether they output ⊥ or identify a specific party) are deterministic, although the specific party indices identified by `judge_base` may depend on randomised key and tag generation.
- The **counts** experiment: pairing operation counts are deterministic for a given μ and fixed protocol logic.
- The **timing**, **ksweep**, **tkgsweep**, and **invalid** experiments: wall-clock measurements will vary across runs and hardware. The measured values and observed scaling trends may vary across hardware, compiler versions, and execution environments.

### Dependencies

All dependencies are pinned in `Cargo.lock`. Running `cargo build` will fetch the exact versions recorded there, provided internet access is available.

---

## 11. Limitations

- **Build and execution have not been independently verified** on the machine used to prepare this repository documentation. The `Cargo.toml` specifies `edition = "2024"`, which requires Rust ≥ 1.85.0.
- **Timing measurements are hardware-dependent.** Absolute values in the provided CSV files correspond to a specific machine and may differ on other hardware. The measured values and observed scaling trends may vary across hardware, compiler versions, and execution environments.
- **No unit test suite.** Correctness is validated through runtime assertions (`assert!`) within the experiment functions rather than through a formal `#[test]` suite.
- **Single-file architecture.** All protocol logic and experiments reside in `src/main.rs`. No library crate is exposed for external use.
- **No network or communication simulation.** All computation is local; the implementation does not model communication costs between parties.
- **Randomised data generation.** Protocol inputs (keys, messages) are generated randomly at runtime. The existing CSV files reflect one particular execution.

---

## 12. License

No license file has been provided with this repository. The licensing terms have not been specified.

