import os
import time
import json
import statistics
import argparse
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
import bbs_iss.interfaces.requests_api as api
from bbs_iss.utils.utils import gen_link_secret

def setup_issued_credential(num_total_attrs, num_hidden):
    """Issues a credential with specified attributes and returns entities."""
    issuer = IssuerInstance()
    issuer.set_re_issuance_window_days(1000) # Big window for re-issuance tests
    issuer.set_epoch_size_days(7)
    
    holder = HolderInstance()
    
    # Configure verifier and registry for lookup
    verifier = VerifierInstance()
    registry = RegistryInstance()
    
    attributes = api.IssuanceAttributes()
    
    # Hidden keys
    hidden_keys = []
    for i in range(num_hidden):
        key = f"hidden_{i}"
        val = f"val_{i}" if i > 0 else gen_link_secret() # First is link secret
        attributes.append(key, val, api.AttributeType.HIDDEN)
        hidden_keys.append(key)
        
    # Revealed keys
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
    
    # Registry sync for Verifier
    reg_req = issuer.register_issuer()
    reg_resp = registry.process_request(reg_req)
    issuer.process_request(reg_resp)
    
    bulk_req = verifier.fetch_all_issuer_details()
    bulk_resp = registry.process_request(bulk_req)
    verifier.process_request(bulk_resp)
    
    # Issue
    init_req = holder.issuance_request(issuer_name, attributes, "benchmark-doc")
    freshness = issuer.process_request(init_req)
    blind_req = holder.process_request(freshness)
    forward_vc = issuer.process_request(blind_req)
    holder.process_request(forward_vc)
    
    return holder, issuer, verifier, "benchmark-doc", hidden_keys, forward_vc

def run_presentation(holder, verifier, cred_name, hidden_keys, requested_attributes):
    """Executes a single VP generation and verification."""
    # Verifier creates presentation request
    vp_req = verifier.presentation_request(requested_attributes=requested_attributes)
    
    # Holder generates VP
    t_gen_start = time.perf_counter()
    vp_resp = holder.present_credential(vp_req, cred_name, always_hidden_keys=hidden_keys)
    t_gen = time.perf_counter() - t_gen_start
    
    # Verifier verifies VP
    t_ver_start = time.perf_counter()
    is_valid, revealed, _ = verifier.process_request(vp_resp)
    t_ver = time.perf_counter() - t_ver_start
    
    if not is_valid:
        raise RuntimeError("VP verification failed")
        
    payload_size = len(vp_resp.to_json())
    return t_gen, t_ver, payload_size

def run_reissuance(holder, issuer, cred_name, hidden_keys):
    """Executes a single end-to-end credential re-issuance cycle."""
    t_start = time.perf_counter()
    init_req = holder.re_issuance_request(vc_name=cred_name, always_hidden_keys=hidden_keys)
    freshness = issuer.process_request(init_req)
    re_req = holder.process_request(freshness)
    new_vc_resp = issuer.process_request(re_req)
    is_valid = holder.process_request(new_vc_resp)
    duration = time.perf_counter() - t_start
    
    if not is_valid:
        raise RuntimeError("Re-issuance verification failed")
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
    parser = argparse.ArgumentParser(description="BBS+ Verifiable Presentation and Re-issuance Benchmark")
    parser.add_argument("--iterations", type=int, default=50, help="Number of iterations per data point")
    parser.add_argument("--step-size", type=int, default=50, help="Attribute scaling step size")
    args = parser.parse_args()
    
    iterations = args.iterations
    step_size = args.step_size
    
    print(f"Running Verifiable Presentation Benchmarks (iterations={iterations})")
    print("==========================================================================")
    
    # --------------------------------------------------------------------------
    # Test D.1.1: ZKP Hidden Fields Scaling (N=100, H varying 0 to 100 in steps of 5)
    # --------------------------------------------------------------------------
    print("\nBenchmark D.1.1: ZKP Hidden Fields Scaling (N=100)...")
    results_d11 = []
    
    for h in range(0, 96, 5):
        print(f"  - Hidden fields: {h}/100...", end="", flush=True)
        # We need a credential with 100 attributes, of which at least h are hidden (issued as hidden)
        # To make it simple, we issue with h hidden, and 100-h revealed
        holder, issuer, verifier, cred_name, hidden_keys, _ = setup_issued_credential(100, max(1, h))
        
        # We request to disclose only the revealed ones.
        # This means all the h hidden ones remain hidden during presentation.
        revealed_requested = [f"revealed_{i}" for i in range(100 - max(1, h))]
        
        gen_times = []
        ver_times = []
        payload_sizes = []
        
        # Warmup
        run_presentation(holder, verifier, cred_name, hidden_keys, revealed_requested)
        
        for _ in range(iterations):
            t_gen, t_ver, size = run_presentation(holder, verifier, cred_name, hidden_keys, revealed_requested)
            gen_times.append(t_gen)
            ver_times.append(t_ver)
            payload_sizes.append(size)
            
        gen_stats = calculate_stats(gen_times)
        ver_stats = calculate_stats(ver_times)
        avg_size = statistics.mean(payload_sizes)
        
        print(f" Done. Gen Avg: {gen_stats['mean_ms']:.2f} ms | Ver Avg: {ver_stats['mean_ms']:.2f} ms | Size: {avg_size:.0f} B")
        
        results_d11.append({
            "hidden_count": h,
            "gen_stats": gen_stats,
            "ver_stats": ver_stats,
            "avg_payload_size_bytes": avg_size
        })
        
    # --------------------------------------------------------------------------
    # Test D.1.2, D.2, C.1, C.2: Total Attribute Scaling (H=5, N varying 10 to 1250)
    # --------------------------------------------------------------------------
    print("\nBenchmark D.1.2 & D.2: Total Attribute Scaling (H=5)...")
    n_values = [10] + list(range(50, 1251, step_size))
    
    results_scaling = []
    
    for n in n_values:
        print(f"  - Total attributes: {n}...", end="", flush=True)
        # Issue VC with 5 hidden attributes (1 link secret + 4 metadata hidden)
        holder, issuer, verifier, cred_name, hidden_keys, forward_vc = setup_issued_credential(n, 5)
        
        # We request to disclose all except the 5 hidden
        revealed_requested = [f"revealed_{i}" for i in range(n - 5)]
        
        gen_times = []
        ver_times = []
        vp_payload_sizes = []
        reissue_times = []
        
        # Warmups
        run_presentation(holder, verifier, cred_name, hidden_keys, revealed_requested)
        run_reissuance(holder, issuer, cred_name, hidden_keys)
        
        for _ in range(iterations):
            t_gen, t_ver, vp_size = run_presentation(holder, verifier, cred_name, hidden_keys, revealed_requested)
            gen_times.append(t_gen)
            ver_times.append(t_ver)
            vp_payload_sizes.append(vp_size)
            
            t_reissue = run_reissuance(holder, issuer, cred_name, hidden_keys)
            reissue_times.append(t_reissue)
            
        gen_stats = calculate_stats(gen_times)
        ver_stats = calculate_stats(ver_times)
        reissue_stats = calculate_stats(reissue_times)
        
        avg_vp_size = statistics.mean(vp_payload_sizes)
        vc_payload_size = len(forward_vc.to_json())
        
        print(f" Done. Gen: {gen_stats['mean_ms']:.1f} ms | Ver: {ver_stats['mean_ms']:.1f} ms | Reissue: {reissue_stats['mean_ms']:.1f} ms")
        
        results_scaling.append({
            "attribute_count": n,
            "vp_gen_stats": gen_stats,
            "vp_ver_stats": ver_stats,
            "reissue_stats": reissue_stats,
            "vc_payload_size_bytes": vc_payload_size,
            "vp_payload_size_bytes": avg_vp_size
        })
        
    output_dir = "testing/evaluation/data"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "vp_results.json")
    
    with open(output_path, "w") as f:
        json.dump({
            "metadata": {
                "iterations": iterations,
                "step_size": step_size,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            },
            "benchmark_d11": results_d11,
            "benchmark_scaling": results_scaling
        }, f, indent=4)
        
    print(f"==========================================================================")
    print(f"Verifiable Presentation results written to {output_path}")

if __name__ == "__main__":
    main()
