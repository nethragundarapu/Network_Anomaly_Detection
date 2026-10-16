# 🛡️ Sentinel AI — Defensive Network Anomaly Detection Platform

An enterprise-grade, **defensive cyber telemetry dashboard** designed for Security Operations Centers (SOCs), incident responders, and cybersecurity researchers. Sentinel AI combines machine learning classification (Random Forest, Gradient Boosting, Extra Trees) with explainable heuristics, interactive multidimensional visualization, and live attack simulation.

---

## 🌟 Key Highlights & Capabilities

### 1. 📊 SOC Telemetry Overview
- **3D Feature Space Visualization**: Interactive Plotly scatter plot rendering packet volume, byte transfer, and destination port diversity in 3D.
- **Executive Metric Cards**: Real-time KPI summaries for total flows monitored, flagged anomalies, F1-score, accuracy, and threat rates.
- **Threat Severity Breakdown**: Color-coded categorization into *Critical*, *High*, *Medium*, and *Low* severity tiers.
- **Feature Signature Comparisons**: Violin and box plots contrasting normal versus anomalous network flows.

### 2. 🧠 Machine Learning Engine & Model Diagnostics
- **Algorithm Selection**: Switch between **Random Forest Classifier**, **Gradient Boosting**, and **Extra Trees** with adjustable estimator count and validation split.
- **Interactive ROC & Precision-Recall Curves**: Area Under Curve (AUC) calculations with live markers tracking the active decision threshold.
- **Interactive Confusion Matrix**: Annotated heatmap showing True Positives, False Positives, True Negatives, and False Negatives.
- **Feature Attribution**: Gini-impurity feature importance metrics explaining key model drivers.

### 3. 🚨 Incident Triage & Forensic Queue
- **Dynamic Risk Scoring**: Weighted composite threat score ($0-100$) combining ML anomaly probability with rule-based heuristics.
- **Forensic Attribution**: Human-readable explanations highlighting brute-force retries, horizontal port sweeps, packet bursts, or data exfiltration.
- **Incident Drill-Down**: Radar chart comparing individual suspicious flows against baseline normal medians.
- **Export Center**: One-click downloads for filtered incident logs in **CSV** or security audit trails in **JSON**.

### 4. 🔬 Live Flow Simulator & Attack Sandbox
- **Adversary Threat Presets**: Test live responses against simulated scenarios:
  - 🟢 Normal HTTP/HTTPS Web Browsing
  - 🔴 Rapid Port Scanning (Reconnaissance)
  - 🟣 Sensitive Data Exfiltration (Payload Burst)
  - 🟠 Authentication Brute-Force (Failed Logins)
  - 🔵 Volumetric Packet Flood (DDoS Pattern)
- **Live Speedometer / Threat Gauge**: Instant model inference, threat tier assignment, and heuristic rule verification.

### 5. ⏱️ Tactical SOC Mission Watch Face & Wearable Telemetry
- **60 FPS Real-time Canvas Rendering**: High-precision horological dial with smooth automatic sweeping seconds and live rotating radar sweep.
- **DEFCON Threat Condition Gauge**: Dynamic operational readiness sub-dial calculating levels from DEFCON 5 (*Fade Out / Normal*) to DEFCON 1 (*Cocked Pistol / Maximum Alert*).
- **Telemetry Complications**:
  - *Traffic Volume Dial* (9:00): Analog flow count needle.
  - *Model Precision Arc* (3:00): Live F1-score and accuracy gauge.
  - *Mission Chrono & UTC Zulu* (6:00): High-precision UTC clock with live packet flow ECG pulse.
  - *Outer Chapter Ring*: 360° color-coded anomaly ratio meter.
- **Customizable Ergonomics**:
  - 4 Military & Cyber Themes: *Stealth Cyber*, *Red Alert*, *Aviator Chrono*, *Matrix Terminal*.
  - 3 Wearable Case Geometries: *44mm Round Tactical*, *Squircle Ultra*, *Hex Stealth*.
  - Realistic Controls: AOD (Always-On Display) night glow, acoustic mechanical tick & sonar ping via Web Audio API.
- **Standalone Mode**: Exportable zero-dependency `watchface.html` for secondary monitors, tablets, or smart wearable displays.

### 6. 📁 Telemetry Ingestion Studio & EDA
- **CSV Ingestion with Schema Validation**: Checks for required columns, binary labels, missing values, and negative flow boundaries.
- **Correlation Heatmap**: Pairwise Pearson correlation matrix for flow features.
- **Built-in Synthetic Generator**: Generate customized synthetic datasets with custom sample sizes and anomaly contamination ratios directly from the UI.

---

## 🔒 Safety and Defensive Scope
- **Passive & Offline**: Does not scan, sniff, probe, or connect to any live networks.
- **Synthetic Data**: The bundled data is synthetic for demonstration and training workflows.
- **Review Candidates**: Flags represent candidate anomalies for human analyst verification, not conclusive proof of cyber intrusion.

---

## 🛠️ Installation & Setup (Windows)

1. Open PowerShell or Command Prompt in the project folder:
   ```powershell
   cd c:\Users\Nethra\Downloads\Network_Anomaly_Detection
   ```

2. Activate the virtual environment:
   ```powershell
   .\.venv\Scripts\activate
   ```

3. Install / Verify dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

4. Launch the application:
   ```powershell
   streamlit run app.py
   ```

5. The dashboard will automatically open in your browser at `http://localhost:8501`.

---

## 📐 Dataset Schema

| Column | Type | Description |
| :--- | :--- | :--- |
| `duration` | Float | Flow duration in seconds |
| `packets` | Integer | Total count of packets in the flow |
| `bytes` | Float | Total bytes transferred across the flow |
| `failed_connections` | Integer | Count of failed connection / handshake attempts |
| `unique_ports` | Integer | Count of unique destination ports contacted |
| `label` | Integer | `0` = Benign / Normal, `1` = Suspicious / Anomaly |

---

## 📂 Project Structure

```
Network_Anomaly_Detection/
├── app.py                      # Root launcher entrypoint with SOC Watch Face
├── watchface_component.py      # Tactical Watch Face generator & complications
├── watchface.html              # Standalone interactive wearable watch face
├── requirements.txt            # Project dependencies
├── README.md                   # System documentation
├── Network_Anomaly_Detection/
│   ├── app.py                  # Core Sentinel AI application
│   ├── watchface_component.py  # Subfolder watch face component
│   ├── watchface.html          # Subfolder standalone watch face
│   ├── generate_data.py        # Standalone synthetic dataset generator
│   ├── requirements.txt        # Subfolder dependencies
│   ├── data/
│   │   └── network_traffic.csv # Baseline synthetic network flow dataset
│   └── results/
│       └── README.txt          # Output directory marker
└── .venv/                      # Python virtual environment
```

---

## 📜 License
Licensed under the MIT License. Designed for defensive cybersecurity research and educational workflows.
