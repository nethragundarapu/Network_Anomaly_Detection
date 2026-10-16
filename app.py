"""
SENTINEL AI // DEFENSIVE NETWORK ANOMALY DETECTION PLATFORM
Enterprise Security Operations Center (SOC) Anomaly Detection & Threat Intelligence
"""

from pathlib import Path
import io
import json
import time
import numpy as np
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

# Import Watch Face Component
try:
    from watchface_component import generate_watchface_html, generate_mini_watchface_sidebar_html
except ImportError:
    from Network_Anomaly_Detection.watchface_component import generate_watchface_html, generate_mini_watchface_sidebar_html

# Machine Learning & Metrics
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_curve, auc,
    precision_recall_curve, average_precision_score
)

# Plotly Interactive Visualizations
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# ---------------------------------------------------------
# CONSTANTS & CONFIGURATION
# ---------------------------------------------------------
ROOT = Path(__file__).parent
DATA_DIR = ROOT / "data"

# Auto-detect sample dataset location whether running from root or subfolder
POSSIBLE_PATHS = [
    DATA_DIR / "network_traffic.csv",
    ROOT / "Network_Anomaly_Detection" / "data" / "network_traffic.csv",
    Path.cwd() / "Network_Anomaly_Detection" / "data" / "network_traffic.csv",
    Path.cwd() / "data" / "network_traffic.csv"
]

DEFAULT_CSV = None
for p in POSSIBLE_PATHS:
    if p.exists():
        DEFAULT_CSV = p
        break

FEATURES = ["duration", "packets", "bytes", "failed_connections", "unique_ports"]
REQUIRED = FEATURES + ["label"]

# Streamlit Page Configuration
st.set_page_config(
    page_title="Sentinel AI | Network Anomaly Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------------------------------------
# CUSTOM HIGH-TECH CYBERSECURITY CSS
# ---------------------------------------------------------
CUSTOM_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

    /* Global typography & variables */
    :root {
        --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        --font-mono: 'JetBrains Mono', monospace;
        --bg-card: #111827;
        --border-card: #1f2937;
        --accent-cyan: #06b6d4;
        --accent-blue: #3b82f6;
        --accent-emerald: #10b981;
        --accent-amber: #f59e0b;
        --accent-rose: #f43f5e;
    }

    html, body, [class*="css"] {
        font-family: var(--font-sans);
    }

    code, pre {
        font-family: var(--font-mono) !important;
    }

    /* Top Banner / Header */
    .sentinel-header {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.95) 0%, rgba(30, 41, 59, 0.9) 100%);
        border: 1px solid rgba(56, 189, 248, 0.2);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        backdrop-filter: blur(8px);
        border-radius: 16px;
        padding: 24px 28px;
        margin-bottom: 24px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 16px;
    }

    .sentinel-title-box {
        display: flex;
        align-items: center;
        gap: 16px;
    }

    .sentinel-badge-logo {
        background: linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%);
        width: 54px;
        height: 54px;
        border-radius: 14px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 28px;
        box-shadow: 0 0 20px rgba(14, 165, 233, 0.4);
    }

    .sentinel-title {
        font-size: 26px;
        font-weight: 700;
        letter-spacing: -0.5px;
        color: #f8fafc;
        margin: 0;
        line-height: 1.2;
    }

    .sentinel-subtitle {
        font-size: 13px;
        font-weight: 400;
        color: #94a3b8;
        margin: 4px 0 0 0;
        letter-spacing: 0.2px;
    }

    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: rgba(16, 185, 129, 0.12);
        border: 1px solid rgba(16, 185, 129, 0.35);
        color: #34d399;
        padding: 6px 14px;
        border-radius: 9999px;
        font-size: 12px;
        font-weight: 600;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        font-family: var(--font-mono);
    }

    .status-pulse {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: #10b981;
        box-shadow: 0 0 8px #10b981;
        animation: pulse-ring 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
    }

    @keyframes pulse-ring {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.4; transform: scale(1.3); }
    }

    /* KPI Cards */
    .kpi-container {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
        gap: 16px;
        margin-bottom: 24px;
    }

    .kpi-card {
        background: linear-gradient(145deg, #111827 0%, #1a2234 100%);
        border: 1px solid #1f2937;
        border-radius: 14px;
        padding: 18px 20px;
        position: relative;
        overflow: hidden;
        transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
    }

    .kpi-card:hover {
        transform: translateY(-2px);
        border-color: rgba(56, 189, 248, 0.4);
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
    }

    .kpi-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
    }

    .kpi-cyan::before { background: linear-gradient(90deg, #06b6d4, #3b82f6); }
    .kpi-rose::before { background: linear-gradient(90deg, #f43f5e, #fb7185); }
    .kpi-emerald::before { background: linear-gradient(90deg, #10b981, #34d399); }
    .kpi-amber::before { background: linear-gradient(90deg, #f59e0b, #fbbf24); }
    .kpi-indigo::before { background: linear-gradient(90deg, #6366f1, #818cf8); }

    .kpi-label {
        font-size: 12px;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        color: #94a3b8;
        margin-bottom: 6px;
    }

    .kpi-value {
        font-size: 28px;
        font-weight: 700;
        color: #f8fafc;
        line-height: 1.1;
        font-family: var(--font-mono);
    }

    .kpi-subtext {
        font-size: 11px;
        color: #64748b;
        margin-top: 6px;
    }

    /* Threat Severity Tags */
    .threat-tag {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 600;
        font-family: var(--font-mono);
        letter-spacing: 0.4px;
        text-transform: uppercase;
    }

    .tag-critical { background: rgba(244, 63, 94, 0.2); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.4); }
    .tag-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }
    .tag-medium { background: rgba(245, 158, 11, 0.2); color: #fcd34d; border: 1px solid rgba(245, 158, 11, 0.4); }
    .tag-low { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.4); }

    /* Custom Glass Panel */
    .glass-panel {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 20px;
    }

    /* Streamlit tabs enhancement */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: #0f172a;
        padding: 8px 12px;
        border-radius: 12px;
        border: 1px solid #1e293b;
    }

    .stTabs [data-baseweb="tab"] {
        height: 42px;
        border-radius: 8px;
        color: #94a3b8;
        font-weight: 500;
        font-size: 14px;
        border: none !important;
        padding: 0 16px;
        transition: all 0.2s ease;
    }

    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, rgba(14, 165, 233, 0.2) 0%, rgba(99, 102, 241, 0.2) 100%) !important;
        color: #38bdf8 !important;
        border: 1px solid rgba(56, 189, 248, 0.4) !important;
        font-weight: 600;
    }

    /* Disclaimer alert styling */
    .disclaimer-card {
        background: rgba(30, 41, 59, 0.6);
        border-left: 4px solid #38bdf8;
        padding: 12px 18px;
        border-radius: 0 8px 8px 0;
        margin-bottom: 20px;
        font-size: 12px;
        color: #cbd5e1;
    }
</style>
"""

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------
# CORE DATA PROCESSING & VALIDATION
# ---------------------------------------------------------
def generate_synthetic_dataset(n_samples: int = 2000, anomaly_ratio: float = 0.5, random_seed: int = 42) -> pd.DataFrame:
    """Generates synthetic network flow records for testing and demonstration."""
    rng = np.random.default_rng(random_seed)
    n_suspicious = int(n_samples * anomaly_ratio)
    n_normal = n_samples - n_suspicious

    normal = pd.DataFrame({
        "duration": rng.exponential(10, n_normal),
        "packets": rng.poisson(20, n_normal),
        "bytes": rng.lognormal(7, 1, n_normal),
        "failed_connections": rng.poisson(0.2, n_normal),
        "unique_ports": rng.poisson(1, n_normal) + 1,
        "label": 0,
    })

    suspicious = pd.DataFrame({
        "duration": rng.exponential(25, n_suspicious),
        "packets": rng.poisson(80, n_suspicious),
        "bytes": rng.lognormal(9, 1, n_suspicious),
        "failed_connections": rng.poisson(4, n_suspicious),
        "unique_ports": rng.poisson(8, n_suspicious) + 1,
        "label": 1,
    })

    df = pd.concat([normal, suspicious], ignore_index=True)
    df = df.sample(frac=1, random_state=random_seed).reset_index(drop=True)
    return df


def validate_and_prepare_data(df: pd.DataFrame) -> pd.DataFrame:
    """Validates dataframe schema, cleans invalid numeric flow entries, and verifies class diversity."""
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise ValueError(f"Missing mandatory telemetry columns: {', '.join(missing)}")

    clean_df = df.copy()
    for col in REQUIRED:
        clean_df[col] = pd.to_numeric(clean_df[col], errors="coerce")

    clean_df = clean_df.dropna(subset=["label"])
    if clean_df.empty:
        raise ValueError("Dataset contains no valid records after removing empty labels.")

    if not clean_df["label"].isin([0, 1]).all():
        raise ValueError("The 'label' column must be binary: 0 (Normal) or 1 (Suspicious/Anomaly).")

    if clean_df["label"].nunique() < 2:
        raise ValueError("Dataset must contain both Normal (0) and Suspicious (1) records.")

    if clean_df["label"].value_counts().min() < 3:
        raise ValueError("At least 3 records per label class are required for cross-validation.")

    # Invalidate impossible negative flow values
    for col in FEATURES:
        clean_df.loc[clean_df[col] < 0, col] = np.nan

    clean_df = clean_df.dropna(subset=FEATURES, how="all").reset_index(drop=True)
    return clean_df


@st.cache_data(show_spinner=False)
def load_data(uploaded_file, synthetic_seed: int = 42):
    """Loads and validates dataset from file or synthetic sample with caching."""
    if uploaded_file is not None:
        raw_df = pd.read_csv(uploaded_file)
        source_name = f"Uploaded File: {uploaded_file.name}"
    else:
        if DEFAULT_CSV is not None and DEFAULT_CSV.exists():
            raw_df = pd.read_csv(DEFAULT_CSV)
            source_name = f"Sample Database ({DEFAULT_CSV.name})"
        else:
            raw_df = generate_synthetic_dataset(random_seed=synthetic_seed)
            source_name = "Dynamically Generated Synthetic Dataset"

    validated_df = validate_and_prepare_data(raw_df)
    return validated_df, source_name


# ---------------------------------------------------------
# THREAT SCORING & EXPLAINABLE HEURISTICS
# ---------------------------------------------------------
def compute_threat_heuristics(row: pd.Series) -> tuple[str, list[str], int]:
    """
    Computes human-readable SOC threat indicators and calculates an enriched Risk Score (0-100).
    """
    flags = []
    penalty = 0

    # 1. Failed handshakes / authentication brute force
    fc = row.get("failed_connections", 0)
    if pd.notna(fc):
        if fc >= 6:
            flags.append("High Failed Handshakes (Brute-force / auth sweep candidate)")
            penalty += 30
        elif fc >= 3:
            flags.append("Elevated Failed Connections (Connection retry anomalies)")
            penalty += 15

    # 2. Port scanning / horizontal recon
    ports = row.get("unique_ports", 0)
    if pd.notna(ports):
        if ports >= 10:
            flags.append("Extensive Port Sweeping (Horizontal reconnaissance detected)")
            penalty += 25
        elif ports >= 5:
            flags.append("Multi-Port Activity (Elevated port exploration)")
            penalty += 12

    # 3. Volumetric packet bursts (DoS / Flooding)
    pkts = row.get("packets", 0)
    if pd.notna(pkts):
        if pkts >= 75:
            flags.append("Packet Volume Spike (Potential volumetric flood / telemetry burst)")
            penalty += 20
        elif pkts >= 50:
            flags.append("Above-average Packet Count")
            penalty += 10

    # 4. Large Data Volume (Exfiltration)
    bytes_val = row.get("bytes", 0)
    if pd.notna(bytes_val):
        if bytes_val >= 15000:
            flags.append("High Byte Payload (Data exfiltration candidate)")
            penalty += 25
        elif bytes_val >= 8000:
            flags.append("Elevated Byte Transfer")
            penalty += 10

    # 5. Flow Duration Anomaly
    duration = row.get("duration", 0)
    if pd.notna(duration) and duration >= 45:
        flags.append("Extended Connection Persistence (Potential beaconing or slowloris)")
        penalty += 10

    if not flags:
        flags.append("Statistical flow-level anomaly detected by ML classifier")

    primary_reason = "; ".join(flags)
    return primary_reason, flags, min(penalty, 100)


def classify_severity(score: float) -> str:
    """Classifies risk into standardized SOC severity levels."""
    if score >= 0.85:
        return "Critical"
    elif score >= 0.70:
        return "High"
    elif score >= 0.45:
        return "Medium"
    else:
        return "Low"


# ---------------------------------------------------------
# MODEL TRAINING PIPELINE
# ---------------------------------------------------------
@st.cache_resource(show_spinner=False)
def train_detection_model(
    df: pd.DataFrame,
    model_type: str,
    test_size: float,
    n_estimators: int,
    random_seed: int
):
    """Trains the chosen machine learning classifier and returns test evaluations."""
    X = df[FEATURES]
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_seed, stratify=y
    )

    if model_type == "Random Forest":
        clf = RandomForestClassifier(
            n_estimators=n_estimators,
            random_state=random_seed,
            class_weight="balanced"
        )
    elif model_type == "Gradient Boosting":
        clf = GradientBoostingClassifier(
            n_estimators=n_estimators,
            random_state=random_seed
        )
    elif model_type == "Extra Trees":
        clf = ExtraTreesClassifier(
            n_estimators=n_estimators,
            random_state=random_seed,
            class_weight="balanced"
        )
    else:
        clf = RandomForestClassifier(n_estimators=100, random_state=random_seed)

    pipeline = make_pipeline(
        SimpleImputer(strategy="median"),
        clf
    )
    pipeline.fit(X_train, y_train)

    # Classifier is the final estimator in the pipeline
    classifier_step = pipeline.steps[-1][1]
    classes = list(classifier_step.classes_)
    suspicious_idx = classes.index(1)

    y_train_probs = pipeline.predict_proba(X_train)[:, suspicious_idx]
    y_test_probs = pipeline.predict_proba(X_test)[:, suspicious_idx]

    feature_importances = getattr(classifier_step, "feature_importances_", None)

    return {
        "pipeline": pipeline,
        "X_train": X_train,
        "X_test": X_test,
        "y_train": y_train,
        "y_test": y_test,
        "y_test_probs": y_test_probs,
        "y_train_probs": y_train_probs,
        "feature_importances": feature_importances,
        "model_type": model_type
    }


# ---------------------------------------------------------
# SIDEBAR CONTROLS & MODEL CONFIGURATION
# ---------------------------------------------------------
with st.sidebar:
    st.markdown("### ⚙️ Detection Engine Settings")

    # Data Source Selection
    st.markdown("#### 1. Data Ingestion")
    uploaded_file = st.file_uploader(
        "Upload Flow CSV",
        type=["csv"],
        help="Upload standard network flow records with columns: duration, packets, bytes, failed_connections, unique_ports, label."
    )

    st.markdown("---")
    st.markdown("#### 2. Architecture & Parameters")
    model_choice = st.selectbox(
        "Algorithm",
        ["Random Forest", "Gradient Boosting", "Extra Trees"],
        index=0,
        help="Choose detection classifier. Random Forest offers high resilience to outliers; Gradient Boosting provides sharp decision boundaries."
    )

    test_split_pct = st.slider(
        "Held-out Validation Split",
        min_value=15,
        max_value=40,
        value=25,
        step=5,
        format="%d%%",
        help="Percentage of data reserved exclusively for blind model validation."
    )

    n_estimators = st.slider(
        "Model Estimators (Trees)",
        min_value=50,
        max_value=250,
        value=150,
        step=25,
        help="Number of decision trees in the ensemble."
    )

    random_seed = st.number_input("Random State Seed", value=42, step=1)

    st.markdown("---")
    st.markdown("#### 3. Alert Sensitivity")
    threshold = st.slider(
        "Suspicious Decision Threshold",
        min_value=0.10,
        max_value=0.90,
        value=0.50,
        step=0.05,
        help="Probability cut-off for generating an alert. Lower values increase recall (fewer missed threats); higher values increase precision (fewer false positives)."
    )

    st.markdown("---")
    st.caption("🛡️ **Defensive SOC Telemetry**")
    st.caption("Version 2.4.0 • Enterprise Edition")
    components.html(generate_mini_watchface_sidebar_html(), height=95, scrolling=False)


# ---------------------------------------------------------
# APP HEADER
# ---------------------------------------------------------
st.markdown("""
<div class="sentinel-header">
    <div class="sentinel-title-box">
        <div class="sentinel-badge-logo">🛡️</div>
        <div>
            <h1 class="sentinel-title">SENTINEL AI // NETWORK ANOMALY DEFENSE</h1>
            <p class="sentinel-subtitle">Enterprise Flow Telemetry Inspection • Explainable Threat Scoring • Offline Incident Triage</p>
        </div>
    </div>
    <div>
        <div class="status-badge">
            <span class="status-pulse"></span>
            DEFENSIVE MONITORING ACTIVE
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="disclaimer-card">
    <strong>🔒 Defensive & Educational Compliance Notice:</strong> This platform performs passive, offline statistical and machine learning evaluation on synthetic network flow telemetry. It does not scan, intercept, or penetrate live networks. Scores represent anomaly review likelihoods, not conclusive proof of cyber intrusions.
</div>
""", unsafe_allow_html=True)


# ---------------------------------------------------------
# DATA INGESTION & VALIDATION EXECUTION
# ---------------------------------------------------------
try:
    df, source_name = load_data(uploaded_file, synthetic_seed=random_seed)
except Exception as exc:
    st.error(f"❌ Telemetry Data Ingestion Error: {exc}")
    st.info("Ensure the dataset includes required headers: `duration`, `packets`, `bytes`, `failed_connections`, `unique_ports`, and binary `label`.")
    st.stop()

# Train / Evaluate Model
with st.spinner("Training detection ensemble and validating decision boundaries..."):
    model_data = train_detection_model(
        df=df,
        model_type=model_choice,
        test_size=test_split_pct / 100.0,
        n_estimators=n_estimators,
        random_seed=random_seed
    )

X_test = model_data["X_test"]
y_test = model_data["y_test"]
y_probs = model_data["y_test_probs"]
y_pred = (y_probs >= threshold).astype(int)

# Metrics calculation
acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, zero_division=0)
rec = recall_score(y_test, y_pred, zero_division=0)
f1 = f1_score(y_test, y_pred, zero_division=0)
cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
tn, fp, fn, tp = cm.ravel()

# Total anomalies flagged in held-out test set
flagged_count = int(np.sum(y_pred == 1))
total_test = len(y_test)
threat_rate = (flagged_count / total_test) * 100 if total_test > 0 else 0


# ---------------------------------------------------------
# TOP KPI METRIC CARDS
# ---------------------------------------------------------
st.markdown(f"""
<div class="kpi-container">
    <div class="kpi-card kpi-cyan">
        <div class="kpi-label">Total Flows Monitored</div>
        <div class="kpi-value">{len(df):,}</div>
        <div class="kpi-subtext">Validation subset: {len(y_test):,} flows ({test_split_pct}%)</div>
    </div>
    <div class="kpi-card kpi-rose">
        <div class="kpi-label">Anomalies Flagged</div>
        <div class="kpi-value">{flagged_count:,}</div>
        <div class="kpi-subtext">{threat_rate:.1f}% flag rate @ threshold {threshold:.2f}</div>
    </div>
    <div class="kpi-card kpi-emerald">
        <div class="kpi-label">F1-Score (Balanced)</div>
        <div class="kpi-value">{f1:.3f}</div>
        <div class="kpi-subtext">Precision: {prec:.3f} | Recall: {rec:.3f}</div>
    </div>
    <div class="kpi-card kpi-amber">
        <div class="kpi-label">Detection Accuracy</div>
        <div class="kpi-value">{acc * 100:.1f}%</div>
        <div class="kpi-subtext">True Positives: {tp} | True Negatives: {tn}</div>
    </div>
    <div class="kpi-card kpi-indigo">
        <div class="kpi-label">Active Model Engine</div>
        <div class="kpi-value" style="font-size: 20px;">{model_choice}</div>
        <div class="kpi-subtext">Ensemble: {n_estimators} Estimators</div>
    </div>
</div>
""", unsafe_allow_html=True)


# ---------------------------------------------------------
# MAIN INTERFACE TABS
# ---------------------------------------------------------
tab_overview, tab_model, tab_triage, tab_simulator, tab_watchface, tab_data = st.tabs([
    "📊 SOC Telemetry Overview",
    "🧠 Model Diagnostics & ROC",
    "🚨 Incident Triage & Alerts",
    "🔬 Live Flow Simulator",
    "⏱️ SOC Tactical Watch Face",
    "📁 Dataset Studio & EDA"
])


# =========================================================
# TAB 1: SOC TELEMETRY OVERVIEW
# =========================================================
with tab_overview:
    st.markdown("### 🌐 Real-time Telemetry & Threat Vector Space")
    st.write(
        "Interactive multidimensional analysis of network flows. Suspicious anomalies deviate significantly "
        "in packet volume, failed connection retries, and destination port diversity."
    )

    col1, col2 = st.columns([7, 5])

    with col1:
        # 3D Traffic Cluster Scatter Plot
        plot_df = X_test.copy()
        plot_df["Actual"] = y_test.map({0: "Normal Flow", 1: "Suspicious Flow"})
        plot_df["Predicted"] = np.where(y_pred == 1, "Alert Triggered", "Classified Normal")
        plot_df["Threat Score"] = y_probs

        fig_3d = px.scatter_3d(
            plot_df,
            x="packets",
            y="bytes",
            z="unique_ports",
            color="Threat Score",
            color_continuous_scale=["#10b981", "#f59e0b", "#f43f5e"],
            symbol="Predicted",
            symbol_map={"Alert Triggered": "diamond", "Classified Normal": "circle"},
            opacity=0.85,
            title="3D Flow Feature Space (Packets × Bytes × Unique Ports)",
            hover_data=["duration", "failed_connections"]
        )
        fig_3d.update_layout(
            template="plotly_dark",
            margin=dict(l=0, r=0, b=0, t=35),
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            height=480,
            scene=dict(
                xaxis=dict(backgroundcolor="#111827", gridcolor="#1f2937"),
                yaxis=dict(backgroundcolor="#111827", gridcolor="#1f2937"),
                zaxis=dict(backgroundcolor="#111827", gridcolor="#1f2937")
            )
        )
        st.plotly_chart(fig_3d, use_container_width=True)

    with col2:
        # Threat Severity Distribution Donut Chart
        test_scores = pd.Series(y_probs)
        severity_categories = test_scores.apply(classify_severity)
        sev_counts = severity_categories.value_counts().reindex(["Critical", "High", "Medium", "Low"]).fillna(0)

        fig_donut = go.Figure(data=[go.Pie(
            labels=sev_counts.index,
            values=sev_counts.values,
            hole=0.55,
            marker=dict(colors=["#f43f5e", "#f97316", "#f59e0b", "#10b981"]),
            textinfo="label+percent",
            hoverinfo="label+value+percent"
        )])
        fig_donut.update_layout(
            title="Test Set Threat Severity Profile",
            template="plotly_dark",
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            height=240,
            margin=dict(l=20, r=20, b=20, t=40),
            showlegend=False
        )
        st.plotly_chart(fig_donut, use_container_width=True)

        # Quick Health & False Alarm Summary Card
        st.markdown(f"""
        <div class="glass-panel" style="margin-top: 10px;">
            <div style="font-size: 13px; font-weight: 600; color: #94a3b8; text-transform: uppercase; margin-bottom: 8px;">
                SOC Verification Summary
            </div>
            <div style="display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 13px;">
                <span style="color: #cbd5e1;">True Positives (Threats Caught):</span>
                <span style="font-weight: 700; color: #34d399; font-family: var(--font-mono);">{tp}</span>
            </div>
            <div style="display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 13px;">
                <span style="color: #cbd5e1;">False Positives (Benign Flagged):</span>
                <span style="font-weight: 700; color: #fbbf24; font-family: var(--font-mono);">{fp}</span>
            </div>
            <div style="display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 13px;">
                <span style="color: #cbd5e1;">False Negatives (Missed Threats):</span>
                <span style="font-weight: 700; color: #f87171; font-family: var(--font-mono);">{fn}</span>
            </div>
            <div style="display: flex; justify-content: space-between; font-size: 13px;">
                <span style="color: #cbd5e1;">Precision / Purity:</span>
                <span style="font-weight: 700; color: #38bdf8; font-family: var(--font-mono);">{prec * 100:.1f}%</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # Feature Distributions (Normal vs Suspicious)
    st.markdown("#### 📊 Key Feature Signatures Comparison")
    feat_col1, feat_col2 = st.columns(2)

    with feat_col1:
        fig_violin1 = px.violin(
            df,
            x="label",
            y="failed_connections",
            color="label",
            box=True,
            points="all",
            color_discrete_map={0: "#10b981", 1: "#f43f5e"},
            title="Failed Connections: Normal (0) vs Suspicious (1)"
        )
        fig_violin1.update_layout(
            template="plotly_dark",
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            height=280,
            showlegend=False,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        st.plotly_chart(fig_violin1, use_container_width=True)

    with feat_col2:
        fig_violin2 = px.violin(
            df,
            x="label",
            y="unique_ports",
            color="label",
            box=True,
            points="all",
            color_discrete_map={0: "#10b981", 1: "#f43f5e"},
            title="Unique Destination Ports: Normal (0) vs Suspicious (1)"
        )
        fig_violin2.update_layout(
            template="plotly_dark",
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            height=280,
            showlegend=False,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        st.plotly_chart(fig_violin2, use_container_width=True)


# =========================================================
# TAB 2: MODEL DIAGNOSTICS & ROC
# =========================================================
with tab_model:
    st.markdown("### 🧠 Machine Learning Engine Diagnostics & Evaluation")
    st.write(
        "Evaluate the classifier's statistical discriminatory power using Receiver Operating Characteristic (ROC), "
        "Precision-Recall tradeoffs, and feature attribution."
    )

    col_m1, col_m2 = st.columns(2)

    with col_m1:
        # ROC Curve
        fpr, tpr, roc_thresholds = roc_curve(y_test, y_probs)
        roc_auc = auc(fpr, tpr)

        # Find closest index for operating threshold
        idx_thresh = np.argmin(np.abs(roc_thresholds - threshold))
        opt_fpr = fpr[idx_thresh]
        opt_tpr = tpr[idx_thresh]

        fig_roc = go.Figure()
        fig_roc.add_trace(go.Scatter(
            x=fpr, y=tpr,
            mode='lines',
            name=f'ROC Curve (AUC = {roc_auc:.4f})',
            line=dict(color='#06b6d4', width=3)
        ))
        fig_roc.add_trace(go.Scatter(
            x=[0, 1], y=[0, 1],
            mode='lines',
            name='Random Chance Line',
            line=dict(color='#64748b', dash='dash')
        ))
        fig_roc.add_trace(go.Scatter(
            x=[opt_fpr], y=[opt_tpr],
            mode='markers+text',
            name=f'Current Threshold ({threshold:.2f})',
            marker=dict(color='#f43f5e', size=12, symbol='star'),
            text=[f"Cutoff: {threshold:.2f}"],
            textposition="bottom right"
        ))
        fig_roc.update_layout(
            title=f"ROC Curve (Area Under Curve = {roc_auc:.3f})",
            xaxis_title="False Positive Rate (1 - Specificity)",
            yaxis_title="True Positive Rate (Recall / Sensitivity)",
            template="plotly_dark",
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            height=380,
            margin=dict(l=30, r=30, t=50, b=30),
            legend=dict(yanchor="bottom", y=0.05, xanchor="right", x=0.95)
        )
        st.plotly_chart(fig_roc, use_container_width=True)

    with col_m2:
        # Precision-Recall Curve
        prec_arr, rec_arr, pr_thresholds = precision_recall_curve(y_test, y_probs)
        avg_precision = average_precision_score(y_test, y_probs)

        fig_pr = go.Figure()
        fig_pr.add_trace(go.Scatter(
            x=rec_arr, y=prec_arr,
            mode='lines',
            name=f'Precision-Recall (AP = {avg_precision:.4f})',
            line=dict(color='#10b981', width=3)
        ))
        fig_pr.update_layout(
            title=f"Precision-Recall Curve (Avg Precision = {avg_precision:.3f})",
            xaxis_title="Recall (Sensitivity)",
            yaxis_title="Precision (Positive Predictive Value)",
            template="plotly_dark",
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            height=380,
            margin=dict(l=30, r=30, t=50, b=30),
            legend=dict(yanchor="bottom", y=0.05, xanchor="left", x=0.05)
        )
        st.plotly_chart(fig_pr, use_container_width=True)

    # Confusion Matrix & Feature Importance
    col_cm, col_fi = st.columns([5, 7])

    with col_cm:
        st.markdown("#### 🎯 Interactive Confusion Matrix")
        cm_labels = ["Actual Normal (0)", "Actual Suspicious (1)"]
        pred_labels = ["Pred Normal (0)", "Pred Suspicious (1)"]

        cm_text = [
            [f"True Neg (TN)<br><b>{tn}</b>", f"False Pos (FP)<br><b>{fp}</b>"],
            [f"False Neg (FN)<br><b>{fn}</b>", f"True Pos (TP)<br><b>{tp}</b>"]
        ]

        fig_cm = go.Figure(data=go.Heatmap(
            z=cm,
            x=pred_labels,
            y=cm_labels,
            text=cm_text,
            texttemplate="%{text}",
            colorscale=[[0, "#1e293b"], [0.5, "#0284c7"], [1, "#0369a1"]],
            showscale=False
        ))
        fig_cm.update_layout(
            template="plotly_dark",
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            height=320,
            margin=dict(l=40, r=20, t=30, b=30)
        )
        st.plotly_chart(fig_cm, use_container_width=True)

    with col_fi:
        st.markdown("#### 🌟 Model Feature Importance (Gini Impurity)")
        if model_data["feature_importances"] is not None:
            fi_df = pd.DataFrame({
                "Feature": FEATURES,
                "Importance": model_data["feature_importances"]
            }).sort_values("Importance", ascending=True)

            fig_fi = px.bar(
                fi_df,
                x="Importance",
                y="Feature",
                orientation='h',
                color="Importance",
                color_continuous_scale=["#38bdf8", "#6366f1"],
                title="Relative Contribution to Anomaly Detection"
            )
            fig_fi.update_layout(
                template="plotly_dark",
                paper_bgcolor="#111827",
                plot_bgcolor="#111827",
                height=320,
                showlegend=False,
                margin=dict(l=20, r=20, t=30, b=30)
            )
            st.plotly_chart(fig_fi, use_container_width=True)
        else:
            st.info("Feature importance not supported for this model configuration.")

    # Detailed Classification Report
    with st.expander("📄 Full Scikit-Learn Classification Report & Export"):
        report_str = classification_report(
            y_test, y_pred,
            labels=[0, 1],
            target_names=["0 · Normal", "1 · Suspicious"],
            zero_division=0
        )
        st.code(report_str, language="text")
        st.download_button(
            label="📥 Download Detailed Evaluation Report (TXT)",
            data=report_str.encode("utf-8"),
            file_name="sentinel_evaluation_report.txt",
            mime="text/plain"
        )


# =========================================================
# TAB 3: INCIDENT TRIAGE & ALERTS
# =========================================================
with tab_triage:
    st.markdown("### 🚨 Threat Incident Queue & Forensic Triage")
    st.write(
        "Filtered queue of network flow alerts triggered by the anomaly engine. "
        "Review heuristic explanations, assign severity, and export findings."
    )

    # Build alerts dataframe
    alerts_df = X_test.copy()
    alerts_df.insert(0, "flow_id", [f"FLW-{idx:05d}" for idx in X_test.index])
    alerts_df["actual_label"] = y_test.values
    alerts_df["anomaly_prob"] = y_probs
    alerts_df["predicted"] = y_pred

    # Compute forensic explanations and dynamic risk scores
    explanations = []
    severities = []
    risk_scores = []

    for _, r in alerts_df.iterrows():
        reason_str, _, heuristic_penalty = compute_threat_heuristics(r)
        # Composite risk score: Model probability (60%) + heuristic risk (40%)
        composite_score = (r["anomaly_prob"] * 60) + (heuristic_penalty * 0.4)
        composite_score = min(int(round(composite_score)), 100)

        explanations.append(reason_str)
        risk_scores.append(composite_score)
        severities.append(classify_severity(r["anomaly_prob"]))

    alerts_df["risk_score"] = risk_scores
    alerts_df["severity"] = severities
    alerts_df["forensic_reason"] = explanations

    # Filter to only flagged alerts
    active_alerts = alerts_df[alerts_df["predicted"] == 1].sort_values("anomaly_prob", ascending=False).reset_index(drop=True)

    # Filtering toolbar
    f_col1, f_col2, f_col3 = st.columns([3, 3, 4])
    with f_col1:
        sev_filter = st.multiselect(
            "Filter Severity",
            options=["Critical", "High", "Medium", "Low"],
            default=["Critical", "High", "Medium", "Low"]
        )
    with f_col2:
        search_query = st.text_input("🔍 Search Flow ID or Reason", placeholder="e.g., FLW-0012 or Brute-force")
    with f_col3:
        min_risk = st.slider("Minimum Composite Risk Score", 0, 100, 30)

    filtered_alerts = active_alerts[
        (active_alerts["severity"].isin(sev_filter)) &
        (active_alerts["risk_score"] >= min_risk)
    ]

    if search_query:
        query = search_query.lower()
        filtered_alerts = filtered_alerts[
            filtered_alerts["flow_id"].str.lower().str.contains(query) |
            filtered_alerts["forensic_reason"].str.lower().str.contains(query)
        ]

    st.markdown(f"**Showing {len(filtered_alerts)} incident(s) out of {len(active_alerts)} flagged alerts.**")

    if not filtered_alerts.empty:
        # Display styled alerts table
        display_cols = ["flow_id", "severity", "risk_score", "anomaly_prob", "duration", "packets", "bytes", "failed_connections", "unique_ports", "forensic_reason"]
        st.dataframe(
            filtered_alerts[display_cols].style.format({
                "anomaly_prob": "{:.2%}",
                "duration": "{:.2f}s",
                "bytes": "{:,.0f}",
                "risk_score": "{:d}/100"
            }),
            use_container_width=True,
            hide_index=True
        )

        # Single Flow Drill-down Inspector
        st.markdown("#### 🔍 Single Incident Forensic Deep Dive")
        selected_flow_id = st.selectbox(
            "Select Flow ID for Incident Breakdown",
            options=filtered_alerts["flow_id"].tolist()
        )

        selected_row = filtered_alerts[filtered_alerts["flow_id"] == selected_flow_id].iloc[0]

        d_col1, d_col2 = st.columns([6, 6])
        with d_col1:
            st.markdown(f"""
            <div class="glass-panel">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <span style="font-size: 18px; font-weight: 700; color: #f8fafc; font-family: var(--font-mono);">{selected_flow_id}</span>
                    <span class="threat-tag tag-{selected_row['severity'].lower()}">{selected_row['severity']} Risk</span>
                </div>
                <div style="font-size: 13px; color: #94a3b8; margin-bottom: 8px;"><strong>Anomaly Likelihood:</strong> {selected_row['anomaly_prob']:.2%}</div>
                <div style="font-size: 13px; color: #94a3b8; margin-bottom: 8px;"><strong>Calculated Risk Score:</strong> {selected_row['risk_score']}/100</div>
                <div style="font-size: 13px; color: #94a3b8; margin-bottom: 8px;"><strong>Actual Dataset Label:</strong> {'Suspicious (1)' if selected_row['actual_label'] == 1 else 'Normal (0)'}</div>
                <hr style="border-color: #1f2937; margin: 12px 0;">
                <div style="font-size: 13px; color: #cbd5e1;"><strong>Forensic Heuristic Attribution:</strong><br>{selected_row['forensic_reason']}</div>
                <div style="margin-top: 12px; font-size: 12px; color: #64748b;">
                    <em>Recommended Action: Place IP/subflow into temporary rate-limiting quarantine, capture pcap sample, and verify source host endpoint status.</em>
                </div>
            </div>
            """, unsafe_allow_html=True)

        with d_col2:
            # Telemetry Metrics Radar Chart
            baseline_normal = df[df["label"] == 0][FEATURES].median()
            flow_vals = [
                selected_row["duration"] / (baseline_normal["duration"] + 1e-3),
                selected_row["packets"] / (baseline_normal["packets"] + 1e-3),
                selected_row["bytes"] / (baseline_normal["bytes"] + 1e-3),
                selected_row["failed_connections"] / (baseline_normal["failed_connections"] + 1e-3),
                selected_row["unique_ports"] / (baseline_normal["unique_ports"] + 1e-3),
            ]
            radar_cats = ["Duration", "Packets", "Bytes", "Failed Conn", "Unique Ports"]

            fig_radar = go.Figure()
            fig_radar.add_trace(go.Scatterpolar(
                r=flow_vals,
                theta=radar_cats,
                fill='toself',
                name='Ratio vs Normal Baseline',
                line=dict(color='#f43f5e')
            ))
            fig_radar.add_trace(go.Scatterpolar(
                r=[1, 1, 1, 1, 1],
                theta=radar_cats,
                fill='toself',
                name='Normal Baseline (1.0x)',
                line=dict(color='#10b981', dash='dash')
            ))
            fig_radar.update_layout(
                polar=dict(
                    radialaxis=dict(visible=True, range=[0, max(max(flow_vals) * 1.2, 3)], color='#64748b'),
                    bgcolor='#111827'
                ),
                title="Relative Deviation vs Baseline Median",
                template="plotly_dark",
                paper_bgcolor="#111827",
                height=300,
                margin=dict(l=30, r=30, t=40, b=20)
            )
            st.plotly_chart(fig_radar, use_container_width=True)

        # Export Controls
        exp_col1, exp_col2 = st.columns(2)
        with exp_col1:
            csv_data = filtered_alerts.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Download Filtered Incident Log (CSV)",
                data=csv_data,
                file_name="sentinel_incident_alerts.csv",
                mime="text/csv",
                use_container_width=True
            )
        with exp_col2:
            json_data = filtered_alerts.to_json(orient="records", indent=2).encode("utf-8")
            st.download_button(
                "📥 Download Security Audit Log (JSON)",
                data=json_data,
                file_name="sentinel_incident_audit.json",
                mime="application/json",
                use_container_width=True
            )
    else:
        st.success("✅ No alerts match the current filter criteria or decision threshold.")


# =========================================================
# TAB 4: LIVE FLOW SIMULATOR & ATTACK SANDBOX
# =========================================================
with tab_simulator:
    st.markdown("### 🔬 Live Flow Telemetry Sandbox")
    st.write(
        "Inject arbitrary synthetic flow parameters or test pre-configured adversary threat profiles "
        "to observe live model classification and feature attribution in real time."
    )

    # Attack Scenario Presets
    preset = st.radio(
        "Select Threat Profile / Attack Preset:",
        [
            "Custom Input",
            "🟢 Normal HTTP/HTTPS Web Browsing",
            "🔴 Rapid Port Scanning (Reconnaissance)",
            "🟣 Sensitive Data Exfiltration (High Payload)",
            "🟠 Authentication Brute-Force (Failed Logins)",
            "🔵 Volumetric Packet Flood (DDoS Burst)"
        ],
        horizontal=True
    )

    # Preset value mappings
    p_defaults = {
        "Custom Input": (12.0, 35, 3200, 0, 2),
        "🟢 Normal HTTP/HTTPS Web Browsing": (8.5, 22, 2800, 0, 1),
        "🔴 Rapid Port Scanning (Reconnaissance)": (18.0, 95, 4500, 2, 16),
        "🟣 Sensitive Data Exfiltration (High Payload)": (45.0, 75, 48000, 0, 3),
        "🟠 Authentication Brute-Force (Failed Logins)": (20.0, 48, 3800, 9, 2),
        "🔵 Volumetric Packet Flood (DDoS Burst)": (5.0, 115, 18000, 4, 8)
    }

    def_dur, def_pkt, def_byt, def_fail, def_prt = p_defaults[preset]

    sim_col1, sim_col2 = st.columns(2)

    with sim_col1:
        st.markdown("#### 🎛️ Telemetry Flow Attributes")
        sim_duration = st.slider("Duration (seconds)", 0.1, 120.0, float(def_dur), 0.5)
        sim_packets = st.slider("Packets Transferred", 1, 200, int(def_pkt), 1)
        sim_bytes = st.slider("Total Bytes Transferred", 100, 100000, int(def_byt), 500)
        sim_failed = st.slider("Failed Connection Handshakes", 0, 20, int(def_fail), 1)
        sim_ports = st.slider("Unique Destination Ports Contacted", 1, 30, int(def_prt), 1)

    # Run inference for simulated flow
    sim_input = pd.DataFrame([{
        "duration": sim_duration,
        "packets": sim_packets,
        "bytes": sim_bytes,
        "failed_connections": sim_failed,
        "unique_ports": sim_ports
    }])

    sim_prob = model_data["pipeline"].predict_proba(sim_input)[0, 1]
    sim_pred = int(sim_prob >= threshold)
    sim_reason, sim_flags, sim_penalty = compute_threat_heuristics(sim_input.iloc[0])
    sim_sev = classify_severity(sim_prob)

    with sim_col2:
        st.markdown("#### ⚡ Live Inference Output")

        # Threat Gauge Chart
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=sim_prob * 100,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Calculated Threat Probability", 'font': {'size': 18, 'color': '#f8fafc'}},
            number={'suffix': "%", 'font': {'size': 36, 'color': '#f8fafc', 'family': 'JetBrains Mono'}},
            delta={'reference': threshold * 100, 'increasing': {'color': "#f43f5e"}, 'decreasing': {'color': "#10b981"}},
            gauge={
                'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#64748b"},
                'bar': {'color': "#f43f5e" if sim_pred == 1 else "#10b981"},
                'bgcolor': "#111827",
                'borderwidth': 2,
                'bordercolor': "#1f2937",
                'steps': [
                    {'range': [0, 45], 'color': 'rgba(16, 185, 129, 0.2)'},
                    {'range': [45, 70], 'color': 'rgba(245, 158, 11, 0.2)'},
                    {'range': [70, 100], 'color': 'rgba(244, 63, 94, 0.2)'}
                ],
                'threshold': {
                    'line': {'color': "#38bdf8", 'width': 3},
                    'thickness': 0.75,
                    'value': threshold * 100
                }
            }
        ))
        fig_gauge.update_layout(
            template="plotly_dark",
            paper_bgcolor="#111827",
            height=260,
            margin=dict(l=25, r=25, t=30, b=20)
        )
        st.plotly_chart(fig_gauge, use_container_width=True)

        # Verdict Badge
        if sim_pred == 1:
            st.markdown(f"""
            <div style="background: rgba(244, 63, 94, 0.15); border: 1px solid rgba(244, 63, 94, 0.4); border-radius: 10px; padding: 14px; text-align: center;">
                <div style="color: #fb7185; font-weight: 700; font-size: 16px; letter-spacing: 0.5px;">⚠️ SUSPICIOUS FLOW DETECTED</div>
                <div style="color: #cbd5e1; font-size: 12px; margin-top: 4px;">Severity Tier: <strong>{sim_sev}</strong> • Cutoff threshold {threshold:.2f} exceeded</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 10px; padding: 14px; text-align: center;">
                <div style="color: #34d399; font-weight: 700; font-size: 16px; letter-spacing: 0.5px;">✅ BENIGN / NORMAL PATTERN</div>
                <div style="color: #cbd5e1; font-size: 12px; margin-top: 4px;">Within normal operational baseline parameters</div>
            </div>
            """, unsafe_allow_html=True)

    # Forensic heuristic attribution cards
    st.markdown("#### 📑 Real-time Attribution Flags")
    st.info(f"**Identified Telemetry Patterns:** {sim_reason}")


# =========================================================
# TAB 5: SOC TACTICAL WATCH FACE
# =========================================================
with tab_watchface:
    st.markdown("### ⏱️ Sentinel AI // SOC Mission Tactical Watch Face")
    st.write(
        "A live, high-precision tactical chronometer and telemetry watch face designed for Security Operations Center "
        "(SOC) analysts. Features smooth 60 FPS sweeping movement, DEFCON threat condition complication, "
        "real-time anomaly ratio arc, sub-dial gauges, radar sweep, acoustic tactical ticking, and wearable case styles."
    )

    # Top action bar with Download button and info
    w_col1, w_col2 = st.columns([7, 5])
    with w_col1:
        st.markdown(
            f"**Active Telemetry Feed:** `{source_name}` &nbsp;|&nbsp; "
            f"**Threat Rate:** `{threat_rate:.1f}%` &nbsp;|&nbsp; "
            f"**Validation F1:** `{f1:.3f}` &nbsp;|&nbsp; "
            f"**Flagged Alerts:** `{flagged_count:,} / {len(y_test):,}`"
        )
    with w_col2:
        html_code_standalone = generate_watchface_html(
            total_flows=len(df),
            anomalies_flagged=flagged_count,
            threat_rate=threat_rate,
            f1_score_val=f1,
            accuracy_val=acc,
            active_model=model_choice,
            threshold_val=threshold,
            is_standalone=True
        )
        st.download_button(
            label="💾 Download Standalone Watch Face HTML",
            data=html_code_standalone,
            file_name="sentinel_tactical_watchface.html",
            mime="text/html",
            help="Download as a standalone zero-dependency HTML file to run in any browser, wearable emulator, or SOC wall display."
        )

    # Generate watch face HTML with active telemetry parameters
    watchface_html = generate_watchface_html(
        total_flows=len(df),
        anomalies_flagged=flagged_count,
        threat_rate=threat_rate,
        f1_score_val=f1,
        accuracy_val=acc,
        active_model=model_choice,
        threshold_val=threshold,
        is_standalone=False
    )

    components.html(watchface_html, height=760, scrolling=False)

    # Technical Specification & Complications Documentation
    st.markdown("---")
    st.markdown("#### 🧭 Watch Face Complications & Telemetry Specifications")
    spec_col1, spec_col2, spec_col3 = st.columns(3)
    with spec_col1:
        st.markdown("""
        **Sub-dial 1 (12:00 / Top)**:
        - **DEFCON Threat Condition Meter**
        - Computes operational readiness from DEFCON 5 (*Fade Out / Normal*) to DEFCON 1 (*Cocked Pistol / Critical Alert*) based on active flow anomaly ratios.
        - Click **Pusher A** on the watch bezel to test alert states.
        """)
    with spec_col2:
        st.markdown("""
        **Sub-dial 2 & 3 (9:00 & 3:00)**:
        - **Traffic Volume Needle (9:00)**: Displays total monitored flow volume in thousands of flows.
        - **Model Precision Arc (3:00)**: Live F1-score and accuracy confidence gauge from the active classifier.
        """)
    with spec_col3:
        st.markdown("""
        **Sub-dial 4 & Outer Bezel**:
        - **Mission Chronometer (6:00)**: Synchronized UTC Zulu mission time with live packet flow ECG pulse.
        - **Outer Anomaly Arc**: Real-time 360° color-coded anomaly contamination indicator.
        - **Crown**: Tap to toggle Always-On Display (AOD) stealth night mode.
        """)


# =========================================================
# TAB 6: DATASET STUDIO & EDA
# =========================================================
with tab_data:
    st.markdown("### 📁 Telemetry Ingestion Studio & Exploratory Analysis")
    st.write(
        "Inspect data schema integrity, explore pairwise correlations, and synthesize new traffic scenarios."
    )

    d_col1, d_col2 = st.columns([7, 5])

    with d_col1:
        st.markdown(f"#### 📋 Active Telemetry Data: `{source_name}`")
        st.dataframe(df.head(100), use_container_width=True, height=280)

        # Summary statistics table
        st.markdown("#### 📈 Statistical Summary")
        st.dataframe(df.describe().T.style.format("{:.2f}"), use_container_width=True)

    with d_col2:
        # Correlation Matrix Heatmap
        corr = df[REQUIRED].corr()
        fig_corr = px.imshow(
            corr,
            text_auto=".2f",
            color_continuous_scale="RdBu_r",
            aspect="auto",
            title="Feature Correlation Matrix (Pearson)"
        )
        fig_corr.update_layout(
            template="plotly_dark",
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            height=340,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        st.plotly_chart(fig_corr, use_container_width=True)

        # Synthetic Generator Mini-tool
        st.markdown("#### ⚡ Generate Fresh Synthetic Flow Records")
        with st.form("gen_form"):
            g_count = st.number_input("Number of Records", min_value=200, max_value=10000, value=2000, step=200)
            g_ratio = st.slider("Anomaly Contamination Ratio", 0.05, 0.70, 0.50, 0.05)
            g_seed = st.number_input("Generator Seed", value=int(time.time()) % 10000)
            submitted = st.form_submit_button("Generate & Overwrite Active Database")
            if submitted:
                new_df = generate_synthetic_dataset(n_samples=g_count, anomaly_ratio=g_ratio, random_seed=g_seed)
                # Save to disk
                target_save = DEFAULT_CSV if DEFAULT_CSV is not None else DATA_DIR / "network_traffic.csv"
                target_save.parent.mkdir(parents=True, exist_ok=True)
                new_df.to_csv(target_save, index=False)
                st.cache_data.clear()
                st.cache_resource.clear()
                st.success(f"Generated {g_count} fresh records saved to `{target_save.name}`! Refreshing...")
                st.rerun()


# ---------------------------------------------------------
# FOOTER
# ---------------------------------------------------------
st.markdown("---")
st.markdown("""
<div style="display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: #64748b; flex-wrap: wrap; gap: 10px;">
    <div><strong>Sentinel AI</strong> • Defensive Network Anomaly Detection Platform • MIT License</div>
    <div>Engineered for SOC Analysts, Incident Responders & Cybersecurity Researchers</div>
</div>
""", unsafe_allow_html=True)
