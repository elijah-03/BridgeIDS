import joblib
import pandas as pd
import numpy as np
import os
import glob
from sklearn.metrics import classification_report, accuracy_score, f1_score
from preprocess import engineer_features

# Configuration
DATASET_DIR = "/home/elijah/Documents/CPS373/Interp-ML-IDS/CSECICIDS2018_improved"
BATCH_SIZE = 100000  # Process 100k rows at a time
SAMPLE_FRACTION = 0.20  # Evaluate on 20% of the data (much higher than 1%)


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
    """
    Preprocesses a batch of data using PRE-FITTED artifacts.
    Does NOT fit anything.
    """
    try:
        # 1. Label Cleaning
        df = clean_labels(df)

        # 2. Label Encoding (Transform only)
        # Handle unseen labels by mapping to Benign (0) or skipping
        # For safety, we map unseen to Benign (index 0 usually, but let's check)
        # Actually, let's filter out unseen labels to be safe, or print warning
        mask = df["Label"].isin(le.classes_)
        if not mask.all():
            # print(f"Warning: Dropping { (~mask).sum() } rows with unseen labels")
            df = df[mask]

        y = le.transform(df["Label"])

        # 3. Feature Selection & Engineering
        # Extract Hour
        if "Timestamp" in df.columns:
            try:
                df["Timestamp"] = pd.to_datetime(df["Timestamp"])
                df["Hour"] = df["Timestamp"].dt.hour
            except Exception:
                df["Hour"] = 0
        elif "Hour" not in df.columns:
            df["Hour"] = 0

        # Rename columns
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

        # Ensure all expected features exist (fill 0 if missing)
        # Note: feature_list contains the names of features expected by the model (after engineering?)
        # Wait, feature_list from train_model.py is X.columns.tolist() AFTER engineering.
        # So we need to engineer first, then select.

        # Base features needed for engineering
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

        # Engineer features
        df = engineer_features(df)

        # Select only the features the model was trained on
        # Verify feature_list matches df columns
        missing_cols = [c for c in feature_list if c not in df.columns]
        if missing_cols:
            # print(f"Warning: Missing columns {missing_cols}, filling with 0")
            for c in missing_cols:
                df[c] = 0

        X = df[feature_list]

        # Numeric conversion and cleanup
        X = X.apply(pd.to_numeric, errors="coerce")
        X = X.astype(np.float32)
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(0)

        # 4. Scaling (Transform only)
        X_scaled = scaler.transform(X)

        return X_scaled, y

    except Exception as e:
        print(f"Error in batch preprocessing: {e}")
        return None, None


def evaluate():
    model, scaler, le, feature_list = load_artifacts()

    print(f"\nStarting Batch Evaluation (Sample Fraction: {SAMPLE_FRACTION})")
    print(f"Batch Size: {BATCH_SIZE}")

    csv_files = glob.glob(os.path.join(DATASET_DIR, "*.csv"))
    if not csv_files:
        print("No CSV files found.")
        return

    y_true_all = []
    y_pred_all = []
    y_conf_all = []  # Store max confidence for average calculation

    total_processed = 0

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

    for file_path in csv_files:
        print(f"\nProcessing file: {os.path.basename(file_path)}")

        # Read file in chunks
        try:
            # First, estimate rows to skip for sampling if we want to be fancy,
            # but for simplicity with pandas chunksize, we'll read everything and sample in memory
            # OR read random chunks.
            # Given we want 20%, reading everything then sampling 20% might still be heavy if file is 4GB.
            # Better: Read in chunks, sample 20% of each chunk, then process.

            chunk_iterator = pd.read_csv(
                file_path,
                usecols=lambda c: c in usecols,
                chunksize=BATCH_SIZE,
                low_memory=False,
            )

            for i, chunk in enumerate(chunk_iterator):
                # Sample the chunk
                if SAMPLE_FRACTION < 1.0:
                    chunk = chunk.sample(frac=SAMPLE_FRACTION, random_state=42)

                if len(chunk) == 0:
                    continue

                # Preprocess
                X_batch, y_batch = preprocess_batch(chunk, scaler, le, feature_list)

                if X_batch is None:
                    continue

                # Predict
                y_pred_batch = model.predict(X_batch)
                y_prob_batch = model.predict_proba(X_batch)
                y_conf_batch = np.max(y_prob_batch, axis=1)

                # Accumulate
                y_true_all.extend(y_batch)
                y_pred_all.extend(y_pred_batch)
                y_conf_all.extend(y_conf_batch)

                total_processed += len(chunk)
                print(
                    f"  Processed chunk {i + 1} ({len(chunk)} samples) - Total: {total_processed}",
                    end="\r",
                )

                # Memory cleanup
                del chunk, X_batch, y_batch, y_pred_batch, y_prob_batch

        except Exception as e:
            print(f"Error processing file {file_path}: {e}")
            continue

    print(f"\n\nEvaluation Complete. Total Samples: {len(y_true_all)}")

    # Calculate Metrics
    y_true_all = np.array(y_true_all)
    y_pred_all = np.array(y_pred_all)
    y_conf_all = np.array(y_conf_all)

    accuracy = accuracy_score(y_true_all, y_pred_all)
    f1_weighted = f1_score(y_true_all, y_pred_all, average="weighted")

    print(f"\n{'OVERALL PERFORMANCE METRICS':^80}")
    print("=" * 80)
    print(f"Overall Accuracy: {accuracy:.4f} ({accuracy * 100:.2f}%)")
    print(f"F1-Score (Weighted): {f1_weighted:.4f}")

    print("\n" + "=" * 80)
    print(f"{'DETAILED CLASSIFICATION REPORT':^80}")
    print("=" * 80)
    print(
        classification_report(
            y_true_all, y_pred_all, target_names=le.classes_, digits=4
        )
    )

    # Per-class confidence
    print("\n" + "=" * 80)
    print(f"{'AVERAGE CONFIDENCE PER TRUE CLASS':^80}")
    print("=" * 80)
    for i, cls in enumerate(le.classes_):
        mask = y_true_all == i
        if mask.sum() > 0:
            avg_conf = y_conf_all[mask].mean()
            print(f"{cls:20s}: {avg_conf:.4f} ({avg_conf * 100:.2f}%)")


if __name__ == "__main__":
    evaluate()
