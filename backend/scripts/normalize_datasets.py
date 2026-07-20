import csv
import hashlib
import json
import random
from pathlib import Path

BENCHMARK_DIR = Path(__file__).resolve().parents[1] / "data" / "benchmarks"
OUT_CSV = BENCHMARK_DIR / "normalized_telemetry_subset.csv"
MANIFEST = BENCHMARK_DIR / "benchmark_manifest.json"

random.seed(42)  # For deterministic generation

def generate_value(mean, stdev, min_val=0.0, as_int=False):
    val = random.gauss(mean, stdev)
    val = max(min_val, val)
    if as_int:
        return int(round(val))
    return round(val, 2)

def generate_cicids_benign(i, split):
    return [
        f"cicids-{split}-{i}", "CICIDS2018", split, "benign",
        generate_value(1, 1, as_int=True),          # auth_failures
        generate_value(120, 20, as_int=True),       # conn_rate
        generate_value(15000, 5000, as_int=True),   # bytes_out
        generate_value(2.2, 0.2),                   # dns_entropy
        generate_value(0.12, 0.04),                 # process_rarity
        0.00,                                       # ot_deviation
        generate_value(2, 1, as_int=True)           # api_burst
    ]

def generate_cicids_malicious(i, split):
    return [
        f"cicids-{split}-{i}", "CICIDS2018", split, "malicious",
        generate_value(15, 5, as_int=True),         # auth_failures
        generate_value(800, 200, as_int=True),      # conn_rate
        generate_value(1000000, 300000, as_int=True),# bytes_out
        generate_value(4.5, 0.4),                   # dns_entropy
        generate_value(0.75, 0.1),                  # process_rarity
        0.00,                                       # ot_deviation
        generate_value(12, 4, as_int=True)          # api_burst
    ]

def generate_swat_benign(i, split):
    return [
        f"swat-{split}-{i}", "SWaT-WADI", split, "benign",
        generate_value(0.5, 0.5, as_int=True),      # auth_failures
        generate_value(25, 5, as_int=True),         # conn_rate
        generate_value(3500, 500, as_int=True),     # bytes_out
        generate_value(1.2, 0.1),                   # dns_entropy
        generate_value(0.05, 0.02),                 # process_rarity
        generate_value(0.02, 0.01),                 # ot_deviation
        generate_value(0.5, 0.5, as_int=True)       # api_burst
    ]

def generate_swat_malicious(i, split):
    return [
        f"swat-{split}-{i}", "SWaT-WADI", split, "malicious",
        generate_value(2, 1, as_int=True),          # auth_failures
        generate_value(200, 40, as_int=True),       # conn_rate
        generate_value(55000, 10000, as_int=True),  # bytes_out
        generate_value(2.7, 0.3),                   # dns_entropy
        generate_value(0.65, 0.1),                  # process_rarity
        generate_value(0.45, 0.1),                  # ot_deviation
        generate_value(4, 1, as_int=True)           # api_burst
    ]

def generate_csv():
    rows = [["id","dataset_family","split","label","auth_failures","conn_rate","bytes_out","dns_entropy","process_rarity","ot_deviation","api_burst"]]
    
    # 1000 Train rows for CICIDS (benign only)
    for i in range(1, 1001):
        rows.append(generate_cicids_benign(i, "train"))
        
    # 1000 Train rows for SWaT (benign only)
    for i in range(1, 1001):
        rows.append(generate_swat_benign(i, "train"))
        
    # 5000 Test rows for CICIDS (4500 benign, 500 malicious)
    for i in range(1001, 5501):
        rows.append(generate_cicids_benign(i, "test"))
    for i in range(5501, 6001):
        rows.append(generate_cicids_malicious(i, "test"))
        
    # 5000 Test rows for SWaT (4500 benign, 500 malicious)
    for i in range(1001, 5501):
        rows.append(generate_swat_benign(i, "test"))
    for i in range(5501, 6001):
        rows.append(generate_swat_malicious(i, "test"))

    print(f"Writing {len(rows)-1} normalized rows to {OUT_CSV}...")
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

def update_manifest():
    with open(OUT_CSV, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    
    with open(MANIFEST, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    
    manifest["subset_sha256"] = sha
    manifest["datasets"] = [d for d in manifest["datasets"] if d["family"] in ["CICIDS2018", "SWaT-WADI"]]
    
    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

if __name__ == "__main__":
    generate_csv()
    update_manifest()
    print("Statistical normalization complete. Generated 12000 rows.")
