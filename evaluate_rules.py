import joblib
import pandas as pd
import numpy as np
import os
import glob
from sklearn.metrics import classification_report, accuracy_score
from preprocess import engineer_features
from config import PORT_MAP

# Configuration
DATASET_DIR = "/home/elijah/Documents/CPS373/Interp-ML-IDS/CSECICIDS2018_improved"
BATCH_SIZE = 100000
SAMPLE_FRACTION = 0.05  # Use smaller fraction for rule evaluation to be faster


def load_artifacts():
    print("Loading model artifacts...")
    model = joblib.load("xgb_model.joblib")
    scaler = joblib.load("scaler.joblib")
    le = joblib.load("label_encoder.joblib")
    feature_list = joblib.load("feature_list.joblib")

    if hasattr(model, "get_booster"):
        model.get_booster().set_param("device", "cpu")

    return model, scaler, le, feature_list


def clean_labels(df, label_col="Label"):
    # Label mapping (Must match preprocess.py)
    label_mapping = {
        "BENIGN": "Benign",
        "DoS Hulk": "DoS",
        "DoS GoldenEye": "DoS",
        "DoS Slowloris": "DoS",
        "DDoS-LOIC-HTTP": "DDoS",
        "DDoS-LOIC-UDP": "DDoS",
        "DDoS-HOIC": "DDoS",
        "FTP-BruteForce": "Brute Force",
        "SSH-BruteForce": "Brute Force",
        "Web Attack - Brute Force": "Web Attack",
        "Web Attack - SQL": "Web Attack",
        "Web Attack - XSS": "Web Attack",
        "Botnet Ares": "Bot/Infiltration",
        "Infiltration - Communication Victim Attacker": "Bot/Infiltration",
        "Infiltration - NMAP Portscan": "Bot/Infiltration",
        "Infiltration - Dropbox Download": "Bot/Infiltration",
    }

    def clean_label_func(label):
        if str(label).endswith(" - Attempted"):
            return "Benign"
        return label_mapping.get(label, "Benign")

    df[label_col] = df[label_col].apply(clean_label_func)
    return df


def preprocess_batch(df, scaler, le, feature_list):
    try:
        df = clean_labels(df)

        mask = df["Label"].isin(le.classes_)
        if not mask.all():
            df = df[mask]

        y = le.transform(df["Label"])

        if "Timestamp" in df.columns:
            try:
                df["Timestamp"] = pd.to_datetime(df["Timestamp"])
                df["Hour"] = df["Timestamp"].dt.hour
            except Exception:
                df["Hour"] = 0
        elif "Hour" not in df.columns:
            df["Hour"] = 0

        column_renames = {
            "Total Fwd Packet": "Total Fwd Packets",
            "Total Length of Fwd Packet": "Fwd Packets Length Total",
            "Fwd Packet Length Max": "Fwd Packet Length Max",
            "FIN Flag Count": "FIN Flag Count",
            "SYN Flag Count": "SYN Flag Count",
            "RST Flag Count": "RST Flag Count",
            "FWD Init Win Bytes": "Init Fwd Win Bytes",
        }
        df = df.rename(columns=column_renames)

        base_features = [
            "Dst Port",
            "Protocol",
            "Hour",
            "Total Fwd Packets",
            "Fwd Packets Length Total",
            "Flow Duration",
            "Flow IAT Mean",
            "Fwd Packet Length Max",
            "FIN Flag Count",
            "SYN Flag Count",
            "RST Flag Count",
            "Init Fwd Win Bytes",
        ]

        for f in base_features:
            if f not in df.columns:
                df[f] = 0

        df = engineer_features(df)

        missing_cols = [c for c in feature_list if c not in df.columns]
        for c in missing_cols:
            df[c] = 0

        X = df[feature_list]
        X = X.apply(pd.to_numeric, errors="coerce")
        X = X.astype(np.float32)
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(0)

        # Keep original values for Z-score calculation before scaling
        X_original = X.values

        X_scaled = scaler.transform(X)

        return X_scaled, y, X_original

    except Exception as e:
        print(f"Error in batch preprocessing: {e}")
        return None, None, None


def detect_attack_pattern(predicted_class, input_data, z_scores, feature_list):
    """
    Detect and describe attack patterns based on feature combinations.
    Copied from app.py for evaluation.
    """

    def get_z(feature_name):
        try:
            idx = feature_list.index(feature_name)
            return z_scores[idx]
        except (ValueError, IndexError):
            return 0

    def is_high(feature_name):
        return get_z(feature_name) > 1.5

    def is_low(feature_name):
        return get_z(feature_name) < -1.5

    dst_port = int(input_data.get("Dst Port", 0))
    protocol = int(input_data.get("Protocol", 6))

    patterns = {
        "DoS": [
            (
                lambda: is_high("Flow Duration")
                and is_high("Flow IAT Mean")
                and dst_port in [80, 443],
                "Slowloris-style attack",
            ),
            (
                lambda: is_high("Total Fwd Packets") and is_low("Flow Duration"),
                "Volumetric flood",
            ),
            (
                lambda: is_high("Total Fwd Packets") and protocol != 6,
                "Protocol abuse attack",
            ),
            (
                lambda: is_high("Flow Duration") and is_high("Total Fwd Packets"),
                "Resource exhaustion attack",
            ),
            (lambda: is_high("Total Fwd Packets"), "High packet volume DoS pattern"),
        ],
        "Brute Force": [
            (
                lambda: is_high("SYN Flag Count") and dst_port in [21, 22, 23],
                f"Credential brute force on {PORT_MAP.get(dst_port, 'service')}",
            ),
            (
                lambda: is_high("FIN Flag Count") and is_low("Flow Duration"),
                "Rapid-fire authentication attempts",
            ),
            (lambda: dst_port == 23, "Telnet brute force"),
            (
                lambda: dst_port in [21, 22, 25, 3389],
                f"Targeted attack on {PORT_MAP.get(dst_port, 'authentication')} service",
            ),
        ],
        "Web Attack": [
            (
                lambda: is_high("Fwd Packet Length Max")
                and is_high("Fwd Packets Length Total")
                and dst_port in [80, 443],
                "SQL Injection pattern",
            ),
            (
                lambda: is_high("Total Fwd Packets")
                and dst_port in [80, 443]
                and not is_high("Fwd Packet Length Max"),
                "Cross-Site Scripting (XSS) pattern",
            ),
            (
                lambda: is_high("Total Fwd Packets")
                and is_low("Flow Duration")
                and dst_port in [80, 443],
                "Web application fuzzing",
            ),
            (
                lambda: is_high("Fwd Packets Length Total") and dst_port in [80, 443],
                "Web application exploit",
            ),
            (lambda: dst_port in [80, 443], "HTTP/HTTPS service targeted"),
        ],
        "DDoS": [
            (
                lambda: is_high("SYN Flag Count") and is_high("Total Fwd Packets"),
                "Distributed SYN flood",
            ),
            (
                lambda: is_high("Total Fwd Packets") and is_low("Flow Duration"),
                "Amplification DDoS",
            ),
            (lambda: is_high("Total Fwd Packets"), "Distributed volumetric attack"),
        ],
        "Bot/Infiltration": [
            (
                lambda: dst_port > 8000 and is_high("Total Fwd Packets"),
                "Command & Control (C2) communication",
            ),
            (
                lambda: is_high("Flow Duration")
                and dst_port not in [80, 443, 21, 22, 23, 25, 53],
                "Backdoor communication",
            ),
            (
                lambda: is_high("Fwd Packets Length Total")
                and dst_port not in [80, 443],
                "Potential data exfiltration",
            ),
            (lambda: True, "Automated malicious behavior detected"),
        ],
        "Benign": [
            (
                lambda: is_high("Flow Duration")
                and dst_port in [80, 443]
                and not is_high("SYN Flag Count"),
                "Legitimate high-bandwidth session",
            ),
            (
                lambda: is_high("Flow Duration")
                and dst_port in [22, 3389]
                and is_low("Total Fwd Packets"),
                "Interactive remote session",
            ),
            (lambda: dst_port == 53, "Normal DNS query traffic"),
            (
                lambda: not any(
                    [
                        is_high(f)
                        for f in [
                            "Flow Duration",
                            "Total Fwd Packets",
                            "Flow IAT Mean",
                            "SYN Flag Count",
                        ]
                    ]
                ),
                "Clean traffic",
            ),
            (lambda: True, "Traffic within expected baseline"),
        ],
    }

    class_patterns = patterns.get(predicted_class, [])
    for condition, description in class_patterns:
        try:
            if condition():
                return description
        except Exception:
            continue

    return None  # Return None if no specific pattern matched (fallback)


def evaluate_rules():
    model, scaler, le, feature_list = load_artifacts()

    print(f"\nStarting Rule Evaluation (Sample Fraction: {SAMPLE_FRACTION})")

    csv_files = glob.glob(os.path.join(DATASET_DIR, "*.csv"))
    if not csv_files:
        print("No CSV files found.")
        return

    usecols = [
        "Dst Port",
        "Protocol",
        "Timestamp",
        "Total Fwd Packet",
        "Total Length of Fwd Packet",
        "Flow Duration",
        "Flow IAT Mean",
        "Fwd Packet Length Max",
        "FIN Flag Count",
        "SYN Flag Count",
        "RST Flag Count",
        "FWD Init Win Bytes",
        "Label",
    ]

    total_samples = 0
    rule_matches = 0
    class_stats = {}

    for file_path in csv_files:
        print(f"\nProcessing file: {os.path.basename(file_path)}")

        try:
            chunk_iterator = pd.read_csv(
                file_path,
                usecols=lambda c: c in usecols,
                chunksize=BATCH_SIZE,
                low_memory=False,
            )

            for i, chunk in enumerate(chunk_iterator):
                if SAMPLE_FRACTION < 1.0:
                    chunk = chunk.sample(frac=SAMPLE_FRACTION, random_state=42)

                if len(chunk) == 0:
                    continue

                X_scaled, y_batch, X_original = preprocess_batch(
                    chunk, scaler, le, feature_list
                )

                if X_scaled is None:
                    continue

                # Predict
                y_pred_idx = model.predict(X_scaled)
                y_pred_class = le.inverse_transform(y_pred_idx)

                # Evaluate rules for each sample
                for j in range(len(X_original)):
                    sample_features = X_original[j]
                    pred_class = y_pred_class[j]

                    # Calculate Z-scores
                    z_scores = (sample_features - scaler.mean_) / scaler.scale_

                    # Create input dict for rule function
                    input_data = {
                        feature_list[k]: sample_features[k]
                        for k in range(len(feature_list))
                    }

                    # Check rule
                    rule_desc = detect_attack_pattern(
                        pred_class, input_data, z_scores, feature_list
                    )

                    # Update stats
                    if pred_class not in class_stats:
                        class_stats[pred_class] = {"total": 0, "matched": 0}

                    class_stats[pred_class]["total"] += 1
                    if rule_desc:
                        class_stats[pred_class]["matched"] += 1
                        rule_matches += 1

                total_samples += len(chunk)
                print(f"  Processed {total_samples} samples...", end="\r")

        except Exception as e:
            print(f"Error processing file: {e}")
            continue

    print(f"\n\nRule Evaluation Complete. Total Samples: {total_samples}")
    print(f"Overall Rule Coverage: {rule_matches / total_samples * 100:.2f}%")

    print("\nPer-Class Rule Coverage:")
    print(f"{'Class':<20} {'Total':<10} {'Matched':<10} {'Coverage':<10}")
    print("-" * 50)
    for cls, stats in class_stats.items():
        coverage = stats["matched"] / stats["total"] * 100 if stats["total"] > 0 else 0
        print(
            f"{cls:<20} {stats['total']:<10} {stats['matched']:<10} {coverage:<10.2f}%"
        )


if __name__ == "__main__":
    evaluate_rules()
