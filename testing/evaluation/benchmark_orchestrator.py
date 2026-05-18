import os
import time
import json
import statistics
import argparse
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.registry import RegistryInstance
from bbs_iss.endpoints.loopback import LocalLoopbackEndpoint
from bbs_iss.endpoints.orchestrator import HolderOrchestrator, IssuerOrchestrator
import bbs_iss.interfaces.requests_api as api

def run_raw_entity_issuance(num_total_attrs, num_hidden):
    """Measures raw Entity-level FFI issuance latency (Layer 2)."""
    issuer = IssuerInstance()
    holder = HolderInstance()
    
    attributes = api.IssuanceAttributes()
    for i in range(num_hidden):
        attributes.append(f"hidden_{i}", f"val_{i}", api.AttributeType.HIDDEN)
    for i in range(num_total_attrs - num_hidden):
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
    
    # Run the 5 steps in-memory
    t_start = time.perf_counter()
    init_req = holder.issuance_request(issuer_name, attributes, "benchmark-doc")
    freshness_resp = issuer.process_request(init_req)
    blind_sign_req = holder.process_request(freshness_resp)
    forward_vc_resp = issuer.process_request(blind_sign_req)
    is_valid = holder.process_request(forward_vc_resp)
    duration = time.perf_counter() - t_start
    
    if not is_valid:
        raise RuntimeError("Credential verification failed")
    return duration

def run_orchestrator_issuance(num_total_attrs, num_hidden):
    """Measures full Orchestrator-level coordinated latency (Layer 3)."""
    issuer = IssuerInstance()
    holder = HolderInstance()
    registry = RegistryInstance()
    
    # Configure Loopback Endpoints (simulates network boundary via JSON serialization)
    issuer_ep = LocalLoopbackEndpoint("issuer", issuer)
    registry_ep = LocalLoopbackEndpoint("registry", registry)
    
    # Coordinated state transition orchestrators
    holder_orc = HolderOrchestrator(holder, issuer=issuer_ep, registry=registry_ep)
    issuer_orc = IssuerOrchestrator(issuer, registry=registry_ep)
    
    # Step 1: Register Issuer with Registry
    issuer_orc.register_with_registry()
    
    # Step 2: Prepare issuance attributes
    attributes = api.IssuanceAttributes()
    for i in range(num_hidden):
        attributes.append(f"hidden_{i}", f"val_{i}", api.AttributeType.HIDDEN)
    for i in range(num_total_attrs - num_hidden):
        attributes.append(f"revealed_{i}", f"val_{i}", api.AttributeType.REVEALED)
        
    # Measure orchestrated round-trip
    t_start = time.perf_counter()
    trail = holder_orc.execute_issuance("Mock-Issuer", attributes, "benchmark-doc")
    duration = time.perf_counter() - t_start
    
    if trail.status != api.RequestTrailStatus.COMPLETED:
        raise RuntimeError(f"Orchestration failed: {trail.failure_reason}")
    return duration

def calculate_stats(data_list):
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

def main():
    parser = argparse.ArgumentParser(description="BBS+ Orchestrator Overhead Benchmark")
    parser.add_argument("--iterations", type=int, default=50, help="Number of iterations per data point")
    parser.add_argument("--step-size", type=int, default=50, help="Attribute scaling step size")
    args = parser.parse_args()
    
    iterations = args.iterations
    step_size = args.step_size
    
    print(f"Running Orchestrator Overhead Benchmark (iterations={iterations}, step-size={step_size})")
    print("==================================================================================")
    
    n_values = [10] + list(range(50, 1251, step_size))
    results = []
    
    for n in n_values:
        print(f"Testing attribute count N = {n}...", end="", flush=True)
        raw_durations = []
        orc_durations = []
        
        # Warmup
        try:
            run_raw_entity_issuance(n, 1)
            run_orchestrator_issuance(n, 1)
        except Exception as e:
            print(f"\nWarmup failed for N={n}: {e}")
            continue
            
        for _ in range(iterations):
            raw_durations.append(run_raw_entity_issuance(n, 1))
            orc_durations.append(run_orchestrator_issuance(n, 1))
            
        raw_stats = calculate_stats(raw_durations)
        orc_stats = calculate_stats(orc_durations)
        
        overhead = orc_stats["mean_ms"] - raw_stats["mean_ms"]
        percent_overhead = (overhead / raw_stats["mean_ms"]) * 100.0
        
        print(f" Done. Raw Avg: {raw_stats['mean_ms']:.2f} ms | Orc Avg: {orc_stats['mean_ms']:.2f} ms | Overhead: {overhead:.2f} ms ({percent_overhead:.1f}%)")
        
        results.append({
            "attribute_count": n,
            "raw_stats": raw_stats,
            "orchestrator_stats": orc_stats,
            "overhead_ms": overhead,
            "percent_overhead": percent_overhead
        })
        
    output_dir = "testing/evaluation/data"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "orchestrator_results.json")
    
    with open(output_path, "w") as f:
        json.dump({
            "metadata": {
                "iterations": iterations,
                "step_size": step_size,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            },
            "results": results
        }, f, indent=4)
        
    print(f"==================================================================================")
    print(f"Orchestrator benchmark results successfully written to {output_path}")

if __name__ == "__main__":
    main()
