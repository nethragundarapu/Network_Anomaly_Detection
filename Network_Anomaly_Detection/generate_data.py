"""Generate a clearly labeled synthetic dataset for offline demonstration."""
from pathlib import Path
import numpy as np
import pandas as pd

OUT = Path(__file__).parent / "data" / "network_traffic.csv"
OUT.parent.mkdir(parents=True, exist_ok=True)
rng = np.random.default_rng(42)
n_per_class = 1000

normal = pd.DataFrame({
    "duration": rng.exponential(10, n_per_class),
    "packets": rng.poisson(20, n_per_class),
    "bytes": rng.lognormal(7, 1, n_per_class),
    "failed_connections": rng.poisson(0.2, n_per_class),
    "unique_ports": rng.poisson(1, n_per_class) + 1,
    "label": 0,
})
suspicious = pd.DataFrame({
    "duration": rng.exponential(25, n_per_class),
    "packets": rng.poisson(80, n_per_class),
    "bytes": rng.lognormal(9, 1, n_per_class),
    "failed_connections": rng.poisson(4, n_per_class),
    "unique_ports": rng.poisson(8, n_per_class) + 1,
    "label": 1,
})
df = pd.concat([normal, suspicious], ignore_index=True)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)
df.to_csv(OUT, index=False)
print(f"Created {len(df)} synthetic records: {OUT}")
print("Labels: 0=normal, 1=suspicious (synthetic demonstration only).")
print(df.head())
