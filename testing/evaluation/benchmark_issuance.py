import os
import time
import json
import statistics
import sys
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
import bbs_iss.interfaces.requests_api as api

def run_single_blind_issuance(num_total_attrs, num_hidden):
    """
    Executes a single end-to-end blind issuance flow and records individual step durations.
    Returns a dictionary with latency details.
    """
    issuer = IssuerInstance()
    holder = HolderInstance()
    
    attributes = api.IssuanceAttributes()
    # Add hidden attributes
    for i in range(num_hidden):
        attributes.append(f"hidden_{i}", f"val_{i}", api.AttributeType.HIDDEN)
    
    # Add revealed attributes
    num_revealed = num_total_attrs - num_hidden
    for i in range(num_revealed):
        attributes.append(f"revealed_{i}", f"val_{i}", api.AttributeType.REVEALED)
        
    issuer_name = "Mock-Issuer"
    data = api.IssuerPublicData(
        issuer_name=issuer_name,
        public_key=issuer.public_key,
        revocation_bitstring=issuer.bitstring_manager.get_revocation_bitstring_hex(),
        epoch_size_days=52,
        validity_window_days=7
    )
    holder.public_data_cache.update(issuer_name, data)
    
    # --- STEP 1: Holder prepares issuance request ---
    t_start = time.perf_counter()
    init_req = holder.issuance_request(
        issuer_name=issuer_name,
        attributes=attributes,
        cred_name="benchmark-doc"
    )
    t_holder_init = time.perf_counter() - t_start
    
    # --- STEP 2: Issuer freshness challenge ---
    t_start = time.perf_counter()
    freshness_resp = issuer.process_request(init_req)
    t_issuer_freshness = time.perf_counter() - t_start
    
    # --- STEP 3: Holder builds blinded commitment ---
    t_start = time.perf_counter()
    blind_sign_req = holder.process_request(freshness_resp)
    t_holder_commitment = time.perf_counter() - t_start
    
    # --- STEP 4: Issuer signs the commitment and revealed attributes ---
    t_start = time.perf_counter()
    forward_vc_resp = issuer.process_request(blind_sign_req)
    t_issuer_signing = time.perf_counter() - t_start
    
    # --- STEP 5: Holder unblinds signature, verifies, and stores VC ---
    t_start = time.perf_counter()
    is_valid = holder.process_request(forward_vc_resp)
    t_holder_verification = time.perf_counter() - t_start
    
    if not is_valid:
        raise RuntimeError("Credential verification failed during benchmark cycle")
        
    total_time = t_holder_init + t_issuer_freshness + t_holder_commitment + t_issuer_signing + t_holder_verification
    
    return {
        "holder_init": t_holder_init,
        "issuer_freshness": t_issuer_freshness,
        "holder_commitment": t_holder_commitment,
        "issuer_signing": t_issuer_signing,
        "holder_verification": t_holder_verification,
        "total": total_time
    }

def calculate_stats(data_list):
    """Calculates statistics for a list of values."""
    if not data_list:
        return {}
    mean = statistics.mean(data_list)
    std_dev = statistics.stdev(data_list) if len(data_list) > 1 else 0.0
    median = statistics.median(data_list)
    return {
        "mean_ms": mean * 1000.0,
        "std_ms": std_dev * 1000.0,
        "median_ms": median * 1000.0,
        "min_ms": min(data_list) * 1000.0,
        "max_ms": max(data_list) * 1000.0
    }

def run_benchmark_1(iterations):
    """
    Test 1: Total Attributes (N) fixed at 100.
    Hidden attributes (H) scale from 1 to 100.
    """
    print(f"Running Benchmark 1: Hidden attributes scaling from 1 to 100 (N=100, iterations={iterations})")
    results = []
    
    for h in range(1, 101):
        print(f"  - Hidden fields: {h}/100...", end="", flush=True)
        times = {
            "holder_init": [],
            "issuer_freshness": [],
            "holder_commitment": [],
            "issuer_signing": [],
            "holder_verification": [],
            "total": []
        }
        
        # Warmup
        try:
            run_single_blind_issuance(100, h)
        except Exception as e:
            print(f"\nError in configuration N=100, H={h}: {e}")
            continue
            
        for _ in range(iterations):
            run_metrics = run_single_blind_issuance(100, h)
            for k in times.keys():
                times[k].append(run_metrics[k])
                
        stats = {k: calculate_stats(times[k]) for k in times.keys()}
        results.append({
            "hidden_count": h,
            "total_count": 100,
            "stats": stats
        })
        print(f" Done. Avg total: {stats['total']['mean_ms']:.2f} ms")
        
    return results

def run_benchmark_2(iterations, step_size):
    """
    Test 2: Hidden attributes (H) fixed at 1.
    Total attributes (N) scale from 10 to 1250.
    """
    # Use N = 10, then 50, 100, 150, ..., 1250
    n_values = [10] + list(range(50, 1251, step_size))
    print(f"Running Benchmark 2: Total attributes scaling from 10 to 1250 (H=1, iterations={iterations})")
    results = []
    
    for n in n_values:
        print(f"  - Total attributes: {n}/1250...", end="", flush=True)
        times = {
            "holder_init": [],
            "issuer_freshness": [],
            "holder_commitment": [],
            "issuer_signing": [],
            "holder_verification": [],
            "total": []
        }
        
        # Warmup
        try:
            run_single_blind_issuance(n, 1)
        except Exception as e:
            print(f"\nError in configuration N={n}, H=1: {e}")
            continue
            
        for _ in range(iterations):
            run_metrics = run_single_blind_issuance(n, 1)
            for k in times.keys():
                times[k].append(run_metrics[k])
                
        stats = {k: calculate_stats(times[k]) for k in times.keys()}
        results.append({
            "hidden_count": 1,
            "total_count": n,
            "stats": stats
        })
        print(f" Done. Avg total: {stats['total']['mean_ms']:.2f} ms")
        
    return results

def main():
    iterations = 50
    step_size = 50
    
    # Parse CLI overrides if provided (useful for fast check)
    if "--iterations" in sys.argv:
        try:
            idx = sys.argv.index("--iterations")
            iterations = int(sys.argv[idx + 1])
        except (ValueError, IndexError):
            pass
            
    if "--step-size" in sys.argv:
        try:
            idx = sys.argv.index("--step-size")
            step_size = int(sys.argv[idx + 1])
        except (ValueError, IndexError):
            pass

    print("=" * 60)
    print("BBS+ BLIND ISSUANCE PERFORMANCE BENCHMARK SUITE")
    print("=" * 60)
    
    t_start = time.perf_counter()
    
    benchmark_1_data = run_benchmark_1(iterations)
    print("-" * 60)
    benchmark_2_data = run_benchmark_2(iterations, step_size)
    
    duration = time.perf_counter() - t_start
    print("=" * 60)
    print(f"All benchmarks completed in {duration:.2f} seconds.")
    print("=" * 60)
    
    # Export results
    output_data = {
        "metadata": {
            "iterations": iterations,
            "step_size": step_size,
            "elapsed_seconds": duration,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        },
        "benchmark_1": benchmark_1_data,
        "benchmark_2": benchmark_2_data
    }
    
    output_path = "testing/evaluation/data/benchmark_results.json"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=4)
        
    print(f"Benchmark data successfully written to {output_path}")

if __name__ == "__main__":
    main()
