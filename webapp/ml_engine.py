"""
SENTINEL AI // CORE MACHINE LEARNING & THREAT INTELLIGENCE ENGINE
High-performance feature attribution, anomaly scoring, and model diagnostics.
"""

from pathlib import Path
import time
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_curve, auc,
    precision_recall_curve, average_precision_score
)

ROOT = Path(__file__).resolve().parent.parent

POSSIBLE_CSV_PATHS = [
    ROOT / "Network_Anomaly_Detection" / "data" / "network_traffic.csv",
    ROOT / "data" / "network_traffic.csv",
    Path.cwd() / "Network_Anomaly_Detection" / "data" / "network_traffic.csv",
    Path.cwd() / "data" / "network_traffic.csv"
]

FEATURES = ["duration", "packets", "bytes", "failed_connections", "unique_ports"]
REQUIRED = FEATURES + ["label"]


class MLEngine:
    def __init__(self):
        self.df = None
        self.csv_path = None
        self.model = None
        self.model_type = "Random Forest"
        self.n_estimators = 150
        self.test_size = 0.25
        self.threshold = 0.50
        self.random_seed = 42

        # Data partitions
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.y_test_probs = None
        self.feature_importances = None
        self.baseline_median = {}

        self._find_and_load_data()
        self.train_model()

    def _find_and_load_data(self):
        for path in POSSIBLE_CSV_PATHS:
            if path.exists():
                self.csv_path = path
                break

        if self.csv_path and self.csv_path.exists():
            raw_df = pd.read_csv(self.csv_path)
        else:
            raw_df = self.generate_synthetic_data(2000, 0.5, 42)
            save_path = ROOT / "Network_Anomaly_Detection" / "data" / "network_traffic.csv"
            save_path.parent.mkdir(parents=True, exist_ok=True)
            raw_df.to_csv(save_path, index=False)
            self.csv_path = save_path

        # Validate & clean
        df_clean = raw_df.copy()
        for col in REQUIRED:
            df_clean[col] = pd.to_numeric(df_clean[col], errors="coerce")
        df_clean = df_clean.dropna(subset=["label"])
        for col in FEATURES:
            df_clean.loc[df_clean[col] < 0, col] = np.nan
        df_clean = df_clean.dropna(subset=FEATURES, how="all").reset_index(drop=True)

        self.df = df_clean
        self.baseline_median = df_clean[df_clean["label"] == 0][FEATURES].median().to_dict()

    def generate_synthetic_data(self, n_samples=2000, anomaly_ratio=0.5, seed=42):
        rng = np.random.default_rng(seed)
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
        df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
        return df

    def train_model(self, model_type="Random Forest", n_estimators=150, test_size=0.25, threshold=0.50):
        self.model_type = model_type
        self.n_estimators = n_estimators
        self.test_size = test_size
        self.threshold = threshold

        X = self.df[FEATURES]
        y = self.df["label"].astype(int)

        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=self.test_size, random_state=self.random_seed, stratify=y
        )

        if model_type == "Gradient Boosting":
            clf = GradientBoostingClassifier(n_estimators=self.n_estimators, random_state=self.random_seed)
        elif model_type == "Extra Trees":
            clf = ExtraTreesClassifier(n_estimators=self.n_estimators, random_state=self.random_seed, class_weight="balanced")
        else:
            clf = RandomForestClassifier(n_estimators=self.n_estimators, random_state=self.random_seed, class_weight="balanced")

        pipeline = make_pipeline(
            SimpleImputer(strategy="median"),
            clf
        )
        pipeline.fit(self.X_train, self.y_train)
        self.model = pipeline

        # Get probabilities
        classifier_step = pipeline.steps[-1][1]
        classes = list(classifier_step.classes_)
        suspicious_idx = classes.index(1)
        self.y_test_probs = pipeline.predict_proba(self.X_test)[:, suspicious_idx]
        self.feature_importances = getattr(classifier_step, "feature_importances_", None)

        return self.get_diagnostics(self.threshold)

    def explain_flow(self, flow: dict) -> dict:
        """Computes explainable cyber heuristic tags and a composite risk score (0-100)."""
        flags = []
        heuristic_penalty = 0

        fc = flow.get("failed_connections", 0)
        if fc >= 6:
            flags.append({
                "type": "danger",
                "title": "Severe Connection Failures",
                "desc": f"{fc} failed handshakes indicate active credential brute-force or service probe."
            })
            heuristic_penalty += 35
        elif fc >= 3:
            flags.append({
                "type": "warning",
                "title": "Elevated Connection Failures",
                "desc": f"{fc} failed connection attempts above normal baseline."
            })
            heuristic_penalty += 15

        ports = flow.get("unique_ports", 0)
        if ports >= 10:
            flags.append({
                "type": "danger",
                "title": "Port Sweep Pattern",
                "desc": f"Contacted {ports} unique destination ports — classic horizontal port reconnaissance."
            })
            heuristic_penalty += 30
        elif ports >= 5:
            flags.append({
                "type": "warning",
                "title": "Multi-Port Query",
                "desc": f"{ports} unique destination ports contacted in single flow."
            })
            heuristic_penalty += 12

        pkts = flow.get("packets", 0)
        if pkts >= 75:
            flags.append({
                "type": "danger",
                "title": "Packet Volume Spike",
                "desc": f"{pkts} packets sent — consistent with volumetric flood or buffer exhaust."
            })
            heuristic_penalty += 20
        elif pkts >= 50:
            flags.append({
                "type": "info",
                "title": "High Packet Frequency",
                "desc": f"{pkts} packets recorded."
            })
            heuristic_penalty += 10

        bytes_val = flow.get("bytes", 0)
        if bytes_val >= 15000:
            flags.append({
                "type": "danger",
                "title": "Large Payload Volume",
                "desc": f"{bytes_val:,.0f} bytes transferred — matches unauthorized data exfiltration."
            })
            heuristic_penalty += 25
        elif bytes_val >= 8000:
            flags.append({
                "type": "warning",
                "title": "Substantial Data Transfer",
                "desc": f"{bytes_val:,.0f} bytes."
            })
            heuristic_penalty += 10

        dur = flow.get("duration", 0)
        if dur >= 45:
            flags.append({
                "type": "warning",
                "title": "Prolonged Flow Duration",
                "desc": f"Session persisted for {dur:.1f}s — potential C2 beacon or slowloris idle."
            })
            heuristic_penalty += 10

        if not flags:
            flags.append({
                "type": "info",
                "title": "Statistical Anomaly",
                "desc": "Flow vector deviates from the benign clustering manifold in multi-feature space."
            })

        return {
            "flags": flags,
            "heuristic_penalty": min(heuristic_penalty, 100)
        }

    def predict_single(self, flow: dict, threshold: float = None) -> dict:
        """Inference for a single flow payload with instant forensic explanation."""
        if threshold is None:
            threshold = self.threshold

        input_df = pd.DataFrame([{
            "duration": float(flow.get("duration", 10)),
            "packets": int(flow.get("packets", 20)),
            "bytes": float(flow.get("bytes", 1500)),
            "failed_connections": int(flow.get("failed_connections", 0)),
            "unique_ports": int(flow.get("unique_ports", 1)),
        }])

        prob = float(self.model.predict_proba(input_df)[0, 1])
        is_anomaly = prob >= threshold

        explanation = self.explain_flow(flow)
        composite_risk = int(round((prob * 60) + (explanation["heuristic_penalty"] * 0.4)))
        composite_risk = min(max(composite_risk, 0), 100)

        if composite_risk >= 80 or prob >= 0.85:
            severity = "Critical"
        elif composite_risk >= 65 or prob >= 0.70:
            severity = "High"
        elif composite_risk >= 45 or prob >= 0.40:
            severity = "Medium"
        else:
            severity = "Low"

        # Deviation ratios relative to baseline
        deviations = {}
        for feat in FEATURES:
            val = float(flow.get(feat, 0))
            base = float(self.baseline_median.get(feat, 0.0))
            if base <= 0:
                ratio = round(val, 2)
            else:
                ratio = round(val / base, 2)
            deviations[feat] = {
                "value": val,
                "baseline": base,
                "ratio": ratio
            }

        # Plain english recommendation
        if is_anomaly:
            if flow.get("failed_connections", 0) >= 4:
                action = "Isolate source host immediately; enforce account lockout and examine SSH/RDP auth logs."
            elif flow.get("unique_ports", 0) >= 8:
                action = "Drop connection at perimeter firewall; inspect host for automated scanner binaries."
            elif flow.get("bytes", 0) >= 15000:
                action = "Block outbound egress to destination IP; collect memory dump for exfiltration analysis."
            else:
                action = "Flag session for SOC analyst review; route subflow through deep packet inspection sandbox."
        else:
            action = "Routine benign flow. Maintain standard passive monitoring without intervention."

        return {
            "is_anomaly": is_anomaly,
            "anomaly_probability": round(prob, 4),
            "threat_percentage": round(prob * 100, 1),
            "composite_risk_score": composite_risk,
            "severity": severity,
            "threshold_used": threshold,
            "flags": explanation["flags"],
            "deviations": deviations,
            "recommended_action": action,
            "input": flow
        }

    def get_overview_stats(self, threshold=None):
        if threshold is None:
            threshold = self.threshold

        y_pred = (self.y_test_probs >= threshold).astype(int)
        cm = confusion_matrix(self.y_test, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        acc = accuracy_score(self.y_test, y_pred)
        prec = precision_score(self.y_test, y_pred, zero_division=0)
        rec = recall_score(self.y_test, y_pred, zero_division=0)
        f1 = f1_score(self.y_test, y_pred, zero_division=0)

        flagged_count = int(np.sum(y_pred == 1))
        total_test = len(self.y_test)

        # Build recent active alerts preview
        alerts_list = []
        test_indices = self.X_test.index.tolist()
        for i, idx in enumerate(test_indices[:60]):
            prob = float(self.y_test_probs[i])
            if prob >= threshold:
                row = self.X_test.loc[idx].to_dict()
                explanation = self.explain_flow(row)
                comp_risk = int(round((prob * 60) + (explanation["heuristic_penalty"] * 0.4)))
                comp_risk = min(comp_risk, 100)

                sev = "Critical" if comp_risk >= 80 else ("High" if comp_risk >= 65 else ("Medium" if comp_risk >= 45 else "Low"))
                alerts_list.append({
                    "id": f"FLW-{idx:05d}",
                    "row_index": idx,
                    "probability": round(prob, 3),
                    "risk_score": comp_risk,
                    "severity": sev,
                    "duration": round(float(row["duration"]), 1),
                    "packets": int(row["packets"]),
                    "bytes": int(row["bytes"]),
                    "failed_connections": int(row["failed_connections"]),
                    "unique_ports": int(row["unique_ports"]),
                    "reason": explanation["flags"][0]["title"] if explanation["flags"] else "Anomaly Detected",
                    "actual_label": int(self.y_test.iloc[i])
                })

        # Sort by risk score
        alerts_list.sort(key=lambda x: x["risk_score"], reverse=True)

        return {
            "total_records": len(self.df),
            "test_records": total_test,
            "train_records": len(self.X_train),
            "flagged_threats": flagged_count,
            "threat_rate_pct": round((flagged_count / max(total_test, 1)) * 100, 1),
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": {
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp)
            },
            "active_model": self.model_type,
            "threshold": threshold,
            "recent_alerts": alerts_list[:15]
        }

    def get_diagnostics(self, threshold=None):
        if threshold is None:
            threshold = self.threshold

        y_pred = (self.y_test_probs >= threshold).astype(int)

        # ROC Curve
        fpr, tpr, roc_thresh = roc_curve(self.y_test, self.y_test_probs)
        roc_auc = auc(fpr, tpr)

        # Sample points to keep payload snappy (max 40 points)
        step = max(1, len(fpr) // 35)
        roc_points = [{"fpr": round(float(fpr[i]), 3), "tpr": round(float(tpr[i]), 3)} for i in range(0, len(fpr), step)]
        if {"fpr": 1.0, "tpr": 1.0} not in roc_points:
            roc_points.append({"fpr": 1.0, "tpr": 1.0})

        # Precision-Recall Curve
        prec_arr, rec_arr, _ = precision_recall_curve(self.y_test, self.y_test_probs)
        pr_auc = average_precision_score(self.y_test, self.y_test_probs)
        pr_step = max(1, len(prec_arr) // 35)
        pr_points = [{"recall": round(float(rec_arr[i]), 3), "precision": round(float(prec_arr[i]), 3)} for i in range(0, len(prec_arr), pr_step)]

        # Feature Importance
        fi = []
        if self.feature_importances is not None:
            for feat, imp in zip(FEATURES, self.feature_importances):
                fi.append({"feature": feat, "importance": round(float(imp), 4)})
            fi.sort(key=lambda x: x["importance"], reverse=True)

        cm = confusion_matrix(self.y_test, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        return {
            "model_type": self.model_type,
            "n_estimators": self.n_estimators,
            "threshold": threshold,
            "test_size": self.test_size,
            "accuracy": round(accuracy_score(self.y_test, y_pred), 4),
            "precision": round(precision_score(self.y_test, y_pred, zero_division=0), 4),
            "recall": round(recall_score(self.y_test, y_pred, zero_division=0), 4),
            "f1_score": round(f1_score(self.y_test, y_pred, zero_division=0), 4),
            "roc_auc": round(float(roc_auc), 4),
            "pr_auc": round(float(pr_auc), 4),
            "roc_curve": roc_points,
            "pr_curve": pr_points,
            "feature_importance": fi,
            "confusion_matrix": {
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp)
            }
        }


# Singleton engine instance
engine = MLEngine()
