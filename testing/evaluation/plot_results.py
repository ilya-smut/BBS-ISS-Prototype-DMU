import os
import json
import matplotlib.pyplot as plt
import numpy as np

def load_data(filepath):
    """Loads the benchmark results JSON."""
    if not os.path.exists(filepath):
        return None
    with open(filepath, "r") as f:
        return json.load(f)

def plot_benchmark_1(data, output_dir):
    """Generates and saves the plot for Benchmark 1: Hidden Fields Scaling (Axis A)."""
    print("Generating Plot for Benchmark 1: Hidden Fields Scaling...")
    
    hidden_counts = [item["hidden_count"] for item in data]
    total_mean = [item["stats"]["total"]["mean_ms"] for item in data]
    total_std = [item["stats"]["total"]["std_ms"] for item in data]
    
    holder_commit_mean = [item["stats"]["holder_commitment"]["mean_ms"] for item in data]
    issuer_sign_mean = [item["stats"]["issuer_signing"]["mean_ms"] for item in data]
    holder_verify_mean = [item["stats"]["holder_verification"]["mean_ms"] for item in data]
    
    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    ax.grid(True, linestyle="--", alpha=0.5)
    
    ax.plot(hidden_counts, holder_commit_mean, label="Holder Commitment Generation", color="#e74c3c", linestyle="--", linewidth=1.5)
    ax.plot(hidden_counts, issuer_sign_mean, label="Issuer Blind Signing", color="#3498db", linestyle=":", linewidth=1.5)
    ax.plot(hidden_counts, holder_verify_mean, label="Holder Unblind & Verification", color="#2ecc71", linestyle="-.", linewidth=1.5)
    
    ax.plot(hidden_counts, total_mean, label="Total Round-Trip Latency (Mean)", color="#2c3e50", linewidth=2.5)
    ax.fill_between(
        hidden_counts,
        np.array(total_mean) - np.array(total_std),
        np.array(total_mean) + np.array(total_std),
        color="#2c3e50",
        alpha=0.15,
        label="Total Latency Std Dev ($\pm 1\sigma$)"
    )
    
    ax.set_title("BBS+ Blind Issuance Latency vs. Number of Hidden Fields\n(Fixed Total Attributes $N = 100$)", fontsize=13, fontweight="bold", pad=15)
    ax.set_xlabel("Number of Hidden (Blinded) Fields ($H$)", fontsize=11, labelpad=10)
    ax.set_ylabel("Latency (milliseconds)", fontsize=11, labelpad=10)
    ax.set_xlim(1, 100)
    ax.set_ylim(0, max(total_mean) * 1.2)
    
    ax.legend(loc="upper left", frameon=True, facecolor="white", edgecolor="#bdc3c7", framealpha=0.9, fontsize=9)
    
    textstr = (
        f"Attributes Total ($N$): 100\n"
        f"Avg Holder Commit: {np.mean(holder_commit_mean):.2f} ms\n"
        f"Avg Issuer Sign: {np.mean(issuer_sign_mean):.2f} ms\n"
        f"Avg Verification: {np.mean(holder_verify_mean):.2f} ms"
    )
    props = dict(boxstyle="round", facecolor="#f8f9fa", edgecolor="#bdc3c7", alpha=0.9)
    ax.text(0.68, 0.22, textstr, transform=ax.transAxes, fontsize=9, verticalalignment="top", bbox=props)
    
    plt.tight_layout()
    output_path = os.path.join(output_dir, "issuance_hidden_scaling.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"  - Saved to {output_path}")

def plot_benchmark_2(data, output_dir):
    """Generates and saves the plot for Benchmark 2: Total Attributes Scaling (Axis A)."""
    print("Generating Plot for Benchmark 2: Total Attributes Scaling...")
    
    total_counts = [item["total_count"] for item in data]
    total_mean = [item["stats"]["total"]["mean_ms"] for item in data]
    total_std = [item["stats"]["total"]["std_ms"] for item in data]
    
    holder_commit_mean = [item["stats"]["holder_commitment"]["mean_ms"] for item in data]
    issuer_sign_mean = [item["stats"]["issuer_signing"]["mean_ms"] for item in data]
    holder_verify_mean = [item["stats"]["holder_verification"]["mean_ms"] for item in data]
    
    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    ax.grid(True, linestyle="--", alpha=0.5)
    
    ax.plot(total_counts, holder_commit_mean, label="Holder Commitment Generation", color="#e74c3c", linestyle="--", linewidth=1.5)
    ax.plot(total_counts, issuer_sign_mean, label="Issuer Blind Signing", color="#3498db", linestyle=":", linewidth=1.5)
    ax.plot(total_counts, holder_verify_mean, label="Holder Unblind & Verification", color="#2ecc71", linestyle="-.", linewidth=1.5)
    
    ax.plot(total_counts, total_mean, label="Total Round-Trip Latency (Mean)", color="#2c3e50", linewidth=2.5)
    ax.fill_between(
        total_counts,
        np.array(total_mean) - np.array(total_std),
        np.array(total_mean) + np.array(total_std),
        color="#2c3e50",
        alpha=0.15,
        label="Total Latency Std Dev ($\pm 1\sigma$)"
    )
    
    z = np.polyfit(total_counts, total_mean, 1)
    p = np.poly1d(z)
    ax.plot(total_counts, p(total_counts), color="#7f8c8d", linestyle="--", alpha=0.7, label=f"Linear Trend ($y = {z[0]:.3f}x + {z[1]:.1f}$)")
    
    ax.set_title("BBS+ Blind Issuance Latency vs. Total Number of Attributes\n(Fixed Hidden Fields $H = 1$)", fontsize=13, fontweight="bold", pad=15)
    ax.set_xlabel("Total Number of Attributes ($N$)", fontsize=11, labelpad=10)
    ax.set_ylabel("Latency (milliseconds)", fontsize=11, labelpad=10)
    ax.set_xlim(10, 1250)
    ax.set_ylim(0, max(total_mean) * 1.2)
    
    ax.legend(loc="upper left", frameon=True, facecolor="white", edgecolor="#bdc3c7", framealpha=0.9, fontsize=9)
    
    textstr = (
        f"Hidden Fields ($H$): 1\n"
        f"Slope: {z[0]*1000:.2f} μs / attribute\n"
        f"Latency @ N=10: {total_mean[0]:.1f} ms\n"
        f"Latency @ N=1250: {total_mean[-1]:.1f} ms"
    )
    props = dict(boxstyle="round", facecolor="#f8f9fa", edgecolor="#bdc3c7", alpha=0.9)
    ax.text(0.68, 0.22, textstr, transform=ax.transAxes, fontsize=9, verticalalignment="top", bbox=props)
    
    plt.tight_layout()
    output_path = os.path.join(output_dir, "issuance_attribute_scaling.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"  - Saved to {output_path}")

def plot_orchestrator_overhead(data, output_dir):
    """Plot 3: Orchestrator vs. Raw Entity Latency (Axis B)."""
    print("Generating Plot for Benchmark 3: Orchestrator Overhead...")
    results = data["results"]
    attrs = [r["attribute_count"] for r in results]
    raw_mean = [r["raw_stats"]["mean_ms"] for r in results]
    orc_mean = [r["orchestrator_stats"]["mean_ms"] for r in results]
    overhead = [r["overhead_ms"] for r in results]
    
    fig, ax1 = plt.subplots(figsize=(10, 6), dpi=300)
    
    color = "#2980b9"
    ax1.set_xlabel("Number of Attributes ($N$)", fontsize=11, labelpad=10)
    ax1.set_ylabel("Latency (ms)", color="#2c3e50", fontsize=11)
    ax1.plot(attrs, raw_mean, label="Layer 2: Python Entity FFI", color="#27ae60", marker="o", linewidth=2)
    ax1.plot(attrs, orc_mean, label="Layer 3: Python Orchestrator (Loopback)", color=color, marker="s", linewidth=2)
    ax1.tick_params(axis='y', labelcolor="#2c3e50")
    ax1.set_xlim(10, 1250)
    ax1.set_ylim(0, max(orc_mean) * 1.15)
    
    ax2 = ax1.twinx()  
    color = "#e74c3c"
    ax2.set_ylabel("Absolute Overhead (ms)", color=color, fontsize=11)
    ax2.plot(attrs, overhead, label="Orchestration & Serialization Cost", color=color, linestyle="--", marker="^", alpha=0.8)
    ax2.tick_params(axis='y', labelcolor=color)
    
    plt.title("BBS+ Coordination & Serialization Overhead\n(HolderOrchestrator vs. Raw Entity Primitives)", fontsize=13, fontweight="bold", pad=15)
    
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper left", frameon=True, facecolor="white", edgecolor="#bdc3c7")
    
    ax1.grid(True, linestyle=":", alpha=0.6)
    plt.tight_layout()
    
    output_path = os.path.join(output_dir, "issuance_orchestrator_overhead.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"  - Saved to {output_path}")

def plot_payload_sizes(data, output_dir):
    """Plot 4: VC & VP Payload Footprint (Axis C)."""
    print("Generating Plot for Benchmark 4: Payload Space Complexity...")
    scaling = data["benchmark_scaling"]
    attrs = [s["attribute_count"] for s in scaling]
    vc_size = [s["vc_payload_size_bytes"] for s in scaling]
    vp_size = [s["vp_payload_size_bytes"] for s in scaling]
    
    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    
    ax.plot(attrs, vc_size, label="Verifiable Credential (VCForwardResponse)", color="#8e44ad", marker="o", linewidth=2)
    ax.plot(attrs, vp_size, label="Verifiable Presentation (VPForwardResponse)", color="#d35400", marker="s", linewidth=2)
    
    z_vc = np.polyfit(attrs, vc_size, 1)
    z_vp = np.polyfit(attrs, vp_size, 1)
    
    ax.plot(attrs, np.polyval(z_vc, attrs), color="#9b59b6", linestyle=":", alpha=0.7, label=f"VC Fit: {z_vc[0]:.1f} B/attr")
    ax.plot(attrs, np.polyval(z_vp, attrs), color="#e67e22", linestyle=":", alpha=0.7, label=f"VP Fit: {z_vp[0]:.1f} B/attr")
    
    ax.set_title("BBS+ Payload Footprint vs. Attribute Count\n(JSON Serialization Space Complexity)", fontsize=13, fontweight="bold", pad=15)
    ax.set_xlabel("Total Attributes ($N$)", fontsize=11, labelpad=10)
    ax.set_ylabel("Serialized Size (bytes)", fontsize=11, labelpad=10)
    ax.set_xlim(10, 1250)
    ax.set_ylim(0, max(max(vc_size), max(vp_size)) * 1.15)
    
    ax.legend(loc="upper left", frameon=True, facecolor="white", edgecolor="#bdc3c7")
    ax.grid(True, linestyle=":", alpha=0.6)
    plt.tight_layout()
    
    output_path = os.path.join(output_dir, "payload_space_complexity.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"  - Saved to {output_path}")

def plot_vp_hidden_scaling(data, output_dir):
    """Plot 5: VP ZKP Hidden Fields Scaling (Axis D)."""
    print("Generating Plot for Benchmark 5: VP ZKP Hidden Fields Scaling...")
    d11 = data["benchmark_d11"]
    h_counts = [d["hidden_count"] for d in d11]
    gen_mean = [d["gen_stats"]["mean_ms"] for d in d11]
    ver_mean = [d["ver_stats"]["mean_ms"] for d in d11]
    
    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    
    ax.plot(h_counts, gen_mean, label="Holder: ZKP Proof Generation (`build_vp`)", color="#1abc9c", marker="o", linewidth=2)
    ax.plot(h_counts, ver_mean, label="Verifier: ZKP Proof Verification (`verify_vp`)", color="#2c3e50", marker="x", linewidth=2)
    
    ax.set_title("VP Selective Disclosure Latency vs. Number of Hidden Fields\n(Fixed Total Attributes $N = 100$)", fontsize=13, fontweight="bold", pad=15)
    ax.set_xlabel("Number of Hidden Attributes ($H$)", fontsize=11, labelpad=10)
    ax.set_ylabel("Latency (milliseconds)", fontsize=11, labelpad=10)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, max(max(gen_mean), max(ver_mean)) * 1.2)
    
    ax.legend(loc="upper left", frameon=True, facecolor="white", edgecolor="#bdc3c7")
    ax.grid(True, linestyle=":", alpha=0.6)
    plt.tight_layout()
    
    output_path = os.path.join(output_dir, "vp_hidden_scaling.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"  - Saved to {output_path}")

def plot_vp_reissue_scaling(data, output_dir):
    """Plot 6: VP & Re-issuance Scaling (Axis D)."""
    print("Generating Plot for Benchmark 6: VP & Re-issuance Scaling...")
    scaling = data["benchmark_scaling"]
    attrs = [s["attribute_count"] for s in scaling]
    gen_mean = [s["vp_gen_stats"]["mean_ms"] for s in scaling]
    ver_mean = [s["vp_ver_stats"]["mean_ms"] for s in scaling]
    reissue_mean = [s["reissue_stats"]["mean_ms"] for s in scaling]
    
    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    
    ax.plot(attrs, gen_mean, label="Holder: VP Generation", color="#27ae60", marker="o", linewidth=2)
    ax.plot(attrs, ver_mean, label="Verifier: VP Verification", color="#2980b9", marker="s", linewidth=2)
    ax.plot(attrs, reissue_mean, label="Coordinated Credential Re-issuance (RTT)", color="#c0392b", marker="^", linewidth=2)
    
    ax.set_title("VP and Re-issuance Latencies vs. Total Attribute Count\n(Fixed Hidden Fields $H = 5$ / $H = 1$ for Re-issuance)", fontsize=13, fontweight="bold", pad=15)
    ax.set_xlabel("Total Attributes ($N$)", fontsize=11, labelpad=10)
    ax.set_ylabel("Latency (milliseconds)", fontsize=11, labelpad=10)
    ax.set_xlim(10, 1250)
    ax.set_ylim(0, max(reissue_mean) * 1.15)
    
    ax.legend(loc="upper left", frameon=True, facecolor="white", edgecolor="#bdc3c7")
    ax.grid(True, linestyle=":", alpha=0.6)
    plt.tight_layout()
    
    output_path = os.path.join(output_dir, "vp_reissue_attribute_scaling.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"  - Saved to {output_path}")

def plot_rust_vs_python_ffi(baseline_data, rust_data, output_dir):
    """Plot 7: Pure Rust Native vs. Python Entity FFI (Axis E)."""
    print("Generating Plot for Benchmark 7: Rust vs. Python FFI Comparison...")
    py_benchmark = baseline_data["benchmark_2"]
    py_attrs = [p["total_count"] for p in py_benchmark]
    py_sign = [p["stats"]["issuer_signing"]["mean_ms"] for p in py_benchmark]
    py_verify = [p["stats"]["holder_verification"]["mean_ms"] for p in py_benchmark]
    
    rust_benchmark = rust_data["benchmark"]
    rust_attrs = [r["attribute_count"] for r in rust_benchmark]
    rust_sign = [r["stats"]["signing"]["mean_ms"] for r in rust_benchmark]
    rust_verify = [r["stats"]["verification"]["mean_ms"] for r in rust_benchmark]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6), dpi=300)
    
    ax1.plot(py_attrs, py_sign, label="Layer 2: Python Entity FFI", color="#3498db", marker="o", linewidth=2)
    ax1.plot(rust_attrs, rust_sign, label="Layer 1: Pure Rust Native", color="#2c3e50", linestyle="--", marker="s", linewidth=2)
    ax1.set_title("Signature Generation Latency comparison", fontsize=11, fontweight="bold")
    ax1.set_xlabel("Number of Attributes ($N$)", labelpad=10)
    ax1.set_ylabel("Latency (ms)")
    ax1.set_xlim(10, 1250)
    ax1.legend(frameon=True, facecolor="white")
    ax1.grid(True, linestyle=":", alpha=0.6)
    
    ax2.plot(py_attrs, py_verify, label="Layer 2: Python Entity FFI", color="#e74c3c", marker="o", linewidth=2)
    ax2.plot(rust_attrs, rust_verify, label="Layer 1: Pure Rust Native", color="#2c3e50", linestyle="--", marker="s", linewidth=2)
    ax2.set_title("Signature Verification Latency comparison", fontsize=11, fontweight="bold")
    ax2.set_xlabel("Number of Attributes ($N$)", labelpad=10)
    ax2.set_ylabel("Latency (ms)")
    ax2.set_xlim(10, 1250)
    ax2.legend(frameon=True, facecolor="white")
    ax2.grid(True, linestyle=":", alpha=0.6)
    
    plt.suptitle("Pure Native Rust vs. Python FFI Performance Boundaries\n(Isolating C-FFI Data Marshalling & Marshalling Penalties)", fontsize=13, fontweight="bold", y=0.98)
    plt.tight_layout()
    
    output_path = os.path.join(output_dir, "rust_vs_python_ffi.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"  - Saved to {output_path}")

def main():
    data_dir = "testing/evaluation/data"
    output_dir = "testing/evaluation/plots"
    os.makedirs(output_dir, exist_ok=True)
    
    baseline = load_data(os.path.join(data_dir, "benchmark_results.json"))
    orc = load_data(os.path.join(data_dir, "orchestrator_results.json"))
    vp = load_data(os.path.join(data_dir, "vp_results.json"))
    rust = load_data(os.path.join(data_dir, "rust_results.json"))
    
    print("Generating Multi-Dimensional Performance Dashboard...")
    print("-" * 50)
    
    if baseline:
        if "benchmark_1" in baseline:
            plot_benchmark_1(baseline["benchmark_1"], output_dir)
        if "benchmark_2" in baseline:
            plot_benchmark_2(baseline["benchmark_2"], output_dir)
            
    if orc:
        plot_orchestrator_overhead(orc, output_dir)
    else:
        print("  - [SKIP] Orchestrator results not found.")
        
    if vp:
        plot_payload_sizes(vp, output_dir)
        plot_vp_hidden_scaling(vp, output_dir)
        plot_vp_reissue_scaling(vp, output_dir)
    else:
        print("  - [SKIP] VP/Re-issuance results not found.")
        
    if baseline and rust:
        plot_rust_vs_python_ffi(baseline, rust, output_dir)
    else:
        print("  - [SKIP] Rust vs. Python FFI comparison requires both baseline and rust datasets.")
        
    print("=" * 50)
    print("Performance Dashboard generation completed successfully.")

if __name__ == "__main__":
    main()
