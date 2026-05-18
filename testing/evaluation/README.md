# BBS+ Performance Evaluation and Benchmarking Suite

This directory contains a cohesive, multi-dimensional benchmarking framework designed to evaluate the computational efficiency, coordination overhead, and space complexity of the BBS-ISS prototype. By executing these benchmarks, we gather empirical evidence to validate protocol scaling, identify architectural bottle-necks, and isolate marshalling costs.

---

## 3-Layer Performance Architecture

We evaluate the BBS-ISS prototype across three distinct levels of abstraction to isolate the exact computational profile of each boundary layer:

```
┌────────────────────────────────────────────────────────────────────────┐
│  Layer 3: Python Orchestrator (State Management & Serialization)        │
│  - Implementation: src/bbs_iss/endpoints/orchestrator.py                │
│  - Mechanics: State machines exchanging JSON messages over Local Loopback│
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Layer 2: Python Entity FFI Wrapper (Core Business Logic)              │
│  - Implementation: src/bbs_iss/entities/                                │
│  - Mechanics: Python classes calling FFI bindings in-memory           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Layer 1: Pure Rust Native Primitives (Underlying Cryptography)        │
│  - Implementation: vendor/ffi-bbs-signatures/                          │
│  - Mechanics: Pure Rust compiled release code executing natively       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Unified Performance Matrix

Our evaluation is structured across five core axes:

### Axis A: Credential Issuance Latency (Completed Baseline)
* **Benchmark A.1 (Hidden Fields Scaling in Blind Issuance):** Fixes total attributes $N = 100$, varies hidden fields $H \in [1, 100]$ in steps of 1. Evaluates Layer 2 in-memory.
* **Benchmark A.2 (Attribute Count Scaling in Blind Issuance):** Varies total attributes $N \in [10, 1250]$ in steps of 50. Evaluates Layer 2 in-memory.

### Axis B: Coordination and Serialization Overhead
* **Benchmark B.1 (Orchestrator vs. Entity Overhead):** Executes the blind issuance protocol using `HolderOrchestrator` driven by the `LocalLoopbackEndpoint` (forcing JSON serialization/deserialization on every transport exchange). Comparing this RTT to raw Layer 2 Entity in-memory latency isolates the coordination and serialization cost.

### Axis C: Space Complexity (Payload Sizes)
* **Benchmark C.1 (VC Payload Size Scaling):** Measures the size in bytes of the serialized `ForwardVCResponse` JSON payload against total attributes $N \in [10, 1250]$.
* **Benchmark C.2 (VP Payload Size Scaling):** Measures the size in bytes of the serialized `ForwardVPResponse` JSON payload under varying selective disclosure configurations.

### Axis D: Verifiable Presentation (VP) & Re-issuance Latency
* **Benchmark D.1 (Selective Disclosure ZKP Latencies):** Measures ZKP generation (`HolderInstance.present_credential`) and ZKP verification (`VerifierInstance.complete_presentation`) across two sweeps:
  * **Test D.1.1 (ZKP Hidden Fields Scaling):** Fixes total attributes at $N = 100$. Varies hidden attributes $H \in [0, 100]$ in steps of 5.
  * **Test D.1.2 (Total Attributes Scaling under Presentation):** Fixes hidden attributes at $H = 5$. Scales total attributes $N \in [10, 1250]$ in steps of 50.
* **Benchmark D.2 (Credential Re-issuance Latency Scaling):** Measures the coordinated RTT of the composite re-issuance protocol (`HolderOrchestrator.execute_re_issuance`) under varying total attributes $N \in [10, 1250]$. 
  * *Cryptographic Justification:* Re-issuance combines a ZKP proof of possession (expiring credential verification) with blind signature generation (rotation).

### Axis E: Native Language Overhead (Rust vs. Python FFI)
* **Benchmark E.1 (FFI Boundary Jitter Analysis):** Compiles a standalone native Rust binary directly executing underlying `bbs` cryptographic signatures. Compares native Rust execution speeds side-by-side with Python's C-FFI wrapper execution (Layer 2) to quantify the marshalling cost.

---

## Script Architecture Index

The suite is composed of five modular files:

1. **[run_evaluation.sh](file:///home/ilya/BBS-ISS-Prototype-DMU/testing/evaluation/run_evaluation.sh):** The master CLI orchestrator script.
2. **[benchmark_issuance.py](file:///home/ilya/BBS-ISS-Prototype-DMU/testing/evaluation/benchmark_issuance.py):** Baseline python benchmark for Axis A.
3. **[benchmark_orchestrator.py](file:///home/ilya/BBS-ISS-Prototype-DMU/testing/evaluation/benchmark_orchestrator.py):** Python benchmark for Axis B.
4. **[benchmark_vp.py](file:///home/ilya/BBS-ISS-Prototype-DMU/testing/evaluation/benchmark_vp.py):** Python benchmark for Axis C and D (VP scaling, payload sizes, and re-issuance RTT).
5. **[rust_benchmark.rs](file:///home/ilya/BBS-ISS-Prototype-DMU/vendor/ffi-bbs-signatures/src/bin/rust_benchmark.rs):** Standalone Rust binary for Axis E.
6. **[plot_results.py](file:///home/ilya/BBS-ISS-Prototype-DMU/testing/evaluation/plot_results.py):** Unified plotting script. Detects present JSON files and selectively renders Plots 1 to 7.

---

## Output Metrics & Plots

Execution populates datasets in `data/` and generates premium visualizations in `plots/`:

* **`issuance_hidden_scaling.png` (Plot 1):** Blind issuance latency vs. hidden fields $H$ ($N=100$).
* **`issuance_attribute_scaling.png` (Plot 2):** Blind issuance latency vs. total attributes $N$ (with a linear regression trend line).
* **`issuance_orchestrator_overhead.png` (Plot 3):** Dual Y-axis plot comparing Python Entity FFI vs. Python Orchestrator latency alongside absolute coordination overhead (ms).
* **`payload_space_complexity.png` (Plot 4):** Serialized JSON VC and VP footprints in bytes vs. total attributes $N$.
* **`vp_hidden_scaling.png` (Plot 5):** VP generation and VP verification latencies vs. hidden fields $H$.
* **`vp_reissue_attribute_scaling.png` (Plot 6):** VP generation, verification, and re-issuance RTT vs. total attributes $N$.
* **`rust_vs_python_ffi.png` (Plot 7):** Side-by-side comparative panel plotting Python FFI vs. Pure Native Rust signature generation and verification.

---

## Execution Guide

Always execute the master orchestrator from the project root directory:

### 1. Show Help Interface
```bash
bash testing/evaluation/run_evaluation.sh --help
```

### 2. Rapid Dry-Run Smoke Test (~2 minutes)
Smoke-tests the entire stack by compiling the Rust binary, executing small-iteration python sweeps, and exporting dummy plots to verify all code paths.
```bash
bash testing/evaluation/run_evaluation.sh --dry-run
```

### 3. Run Axis A Baseline Only
```bash
bash testing/evaluation/run_evaluation.sh --baseline
```

### 4. Execute Complete Multi-Dimensional Benchmarking Sweep (~40 minutes)
Compiles in release mode and executes 50 iterations per data point across all axes.
```bash
bash testing/evaluation/run_evaluation.sh --full
```

### 5. Regenerate Plots from Existing JSONs
```bash
bash testing/evaluation/run_evaluation.sh --plot-only
```
