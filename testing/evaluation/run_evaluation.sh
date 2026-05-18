#!/bin/bash
set -e

# Master Performance Evaluation Orchestrator
# Set working directory to project root
cd "$(dirname "$0")/../.."

PYTHON_BIN=".venv/bin/python"

if [ ! -f "$PYTHON_BIN" ]; then
    echo "Error: Local virtual environment python not found at $PYTHON_BIN"
    echo "Please configure the project environment first."
    exit 1
fi

show_help() {
    echo "============================================================"
    echo "BBS+ Unified Performance Evaluation Orchestrator"
    echo "============================================================"
    echo "Usage: bash testing/evaluation/run_evaluation.sh [options]"
    echo ""
    echo "Options:"
    echo "  --help          Show this help menu"
    echo "  --baseline      Run baseline issuance benchmarks (Axis A) [DEFAULT]"
    echo "  --dry-run       Run smoke-test of all modules with minimal iterations (~2 mins)"
    echo "  --full          Run complete 50-iteration benchmark suite (~40 mins)"
    echo "  --plot-only     Regenerate plots from existing JSON data"
    echo "============================================================"
}

run_baseline() {
    echo "Step 1: Running baseline issuance benchmarks (H and N scaling)..."
    $PYTHON_BIN testing/evaluation/benchmark_issuance.py --iterations 50 --step-size 50
    echo ""
    echo "Step 2: Generating baseline plots..."
    $PYTHON_BIN testing/evaluation/plot_results.py
}

run_dry_run() {
    echo "Starting Dry-Run Performance Smoke-Test..."
    echo "=========================================="
    
    # 1. Compile Rust benchmark
    echo "1. Compiling Native Rust benchmark..."
    (cd vendor/ffi-bbs-signatures && cargo build --release --bin rust_benchmark)
    
    # 2. Run Rust benchmark (dry run - binary has fixed loops, but is fast)
    echo "2. Running Native Rust benchmark..."
    ./vendor/ffi-bbs-signatures/target/release/rust_benchmark
    
    # 3. Run baseline issuance
    echo "3. Running Baseline Issuance benchmark (Axis A)..."
    $PYTHON_BIN testing/evaluation/benchmark_issuance.py --iterations 2 --step-size 300
    
    # 4. Run Orchestrator overhead benchmark (Axis B)
    echo "4. Running Orchestrator Overhead benchmark (Axis B)..."
    $PYTHON_BIN testing/evaluation/benchmark_orchestrator.py --iterations 2 --step-size 300
    
    # 5. Run VP/Re-issuance benchmark (Axis C & D)
    echo "5. Running VP and Re-issuance benchmarks (Axis C & D)..."
    $PYTHON_BIN testing/evaluation/benchmark_vp.py --iterations 2 --step-size 300
    
    # 6. Generate dashboard
    echo "6. Rendering Multi-Dimensional Dashboard (Plots 1 to 7)..."
    $PYTHON_BIN testing/evaluation/plot_results.py
    
    echo "=========================================="
    echo "Dry-run verification completed successfully!"
    echo "All scripts compiled, executed, and rendered plots correctly."
}

run_full() {
    echo "Starting Full Performance Evaluation Sweep..."
    echo "=========================================="
    
    echo "1. Compiling Native Rust benchmark..."
    (cd vendor/ffi-bbs-signatures && cargo build --release --bin rust_benchmark)
    
    echo "2. Running Native Rust benchmark (Axis E)..."
    ./vendor/ffi-bbs-signatures/target/release/rust_benchmark
    
    echo "3. Running Baseline Issuance benchmark (Axis A)..."
    $PYTHON_BIN testing/evaluation/benchmark_issuance.py --iterations 50 --step-size 50
    
    echo "4. Running Orchestrator Overhead benchmark (Axis B)..."
    $PYTHON_BIN testing/evaluation/benchmark_orchestrator.py --iterations 50 --step-size 50
    
    echo "5. Running VP and Re-issuance benchmarks (Axis C & D)..."
    $PYTHON_BIN testing/evaluation/benchmark_vp.py --iterations 50 --step-size 50
    
    # 6. Rendering Multi-Dimensional Dashboard
    $PYTHON_BIN testing/evaluation/plot_results.py
    
    echo "=========================================="
    echo "Full evaluation sweep completed successfully!"
}

# Parse command line options
case "$1" in
    --help)
        show_help
        exit 0
        ;;
    --baseline|"")
        run_baseline
        ;;
    --dry-run)
        run_dry_run
        ;;
    --full)
        run_full
        ;;
    --plot-only)
        $PYTHON_BIN testing/evaluation/plot_results.py
        ;;
    *)
        echo "Error: Unknown option '$1'"
        show_help
        exit 1
        ;;
esac
