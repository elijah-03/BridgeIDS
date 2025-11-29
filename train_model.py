import sys
import joblib
import numpy as np
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight
import pandas as pd
import time

# Import the functions from your scripts
try:
    from load_dataset import load_and_inspect
    from preprocess import preprocess
except ImportError:
    print("Error: Could not import from 'load_dataset.py' or 'preprocess.py'.", file=sys.stderr)
    sys.exit(1)

# Configuration
SAMPLE_FRACTION = 0.15  # 15% of the dataset
RANDOM_STATE = 42

"""
Model Training Pipeline
-----------------------
This script handles the end-to-end training process for the IDS model:
1.  Loads data from CSV files using `load_dataset.py`.
2.  Preprocesses data (cleaning, scaling, splitting) using `preprocess.py`.
3.  Trains an XGBoost classifier with GPU acceleration (if available).
4.  Evaluates the model on a test set (F1, Precision, Recall).
5.  Benchmarks inference latency.
6.  Saves the trained model and artifacts (scaler, label encoder) for the backend.
"""

def train_models():
    """
    Loads, preprocesses, and trains XGBoost model, saving artifacts to disk.
    """
    
    # 1. Define data path
    # 1. Define data path
    DATASET_DIR = "/home/elijah/Documents/CPS373/Interp-ML-IDS/CSECICIDS2018_improved"
    
    try:
        # 2. Load Data
        print(f"--- Loading Data (Sample Fraction: {SAMPLE_FRACTION}) ---")
        raw_df = load_and_inspect(DATASET_DIR, sample_fraction=SAMPLE_FRACTION)
        
        if raw_df is None:
            print("Failed to load data.")
            return

        # 3. Preprocess
        print("--- Preprocessing Data ---")
        # preprocess returns: X_train, X_test, y_train, y_test, X_train_final, y_train_final, feature_list, le, scaler
        # We use X_train_final (X_train) and y_train_final (y_train) for training
        X_train_orig, X_test, y_train_orig, y_test, X_train, y_train, feature_list, label_encoder, scaler = preprocess(raw_df)
        
        # 4. Split training data into Train and Validation for hyperparameter tuning
        print("Splitting training data for validation...")
        X_train_split, X_val, y_train_split, y_val = train_test_split(
            X_train, y_train, test_size=0.2, random_state=RANDOM_STATE, stratify=y_train
        )
        
        # 5. Compute sample weights for class imbalance
        print("Computing sample weights...")
        sample_weights = compute_sample_weight(
            class_weight='balanced',
            y=y_train_split
        )
        
        # 6. XGBoost Configuration
        # Using 'hist' for GPU acceleration (requires device='cuda')
        xgb_params = {
            'objective': 'multi:softprob',
            'num_class': len(label_encoder.classes_),
            'tree_method': 'hist',
            'device': 'cuda',  # Enable GPU
            'eval_metric': ['merror', 'mlogloss'],
            'learning_rate': 0.1,
            'max_depth': 6,
            'subsample': 0.8,
            'colsample_bytree': 0.8,
            'random_state': RANDOM_STATE
        }
        
        print("Training XGBoost model...")
        start_time = time.time()
        xgb_model = XGBClassifier(**xgb_params)
        
        # Train with validation set
        xgb_model.fit(
            X_train_split, y_train_split,
            sample_weight=sample_weights,
            eval_set=[(X_train_split, y_train_split), (X_val, y_val)],
            verbose=True
        )
        training_time = time.time() - start_time
        print(f"Training completed in {training_time:.2f} seconds.")
        
        # 7. Benchmarking
        print("\n--- Benchmarking ---")
        
        # Inference Latency
        print("Measuring inference latency...")
        # Measure on a subset of test data (e.g., 1000 samples)
        latency_samples = X_test[:1000]
        start_latency = time.time()
        xgb_model.predict(latency_samples)
        end_latency = time.time()
        # Calculate average latency per sample in milliseconds
        if len(latency_samples) > 0:
            avg_latency_ms = ((end_latency - start_latency) / len(latency_samples)) * 1000
            print(f"Average Inference Latency: {avg_latency_ms:.4f} ms per sample")
        else:
            print("Not enough samples for latency measurement.")
        
        # Evaluation Metrics
        print("Evaluating on Test Set...")
        y_pred = xgb_model.predict(X_test)
        
        # Weighted F1, Precision, Recall
        report = classification_report(y_test, y_pred, target_names=[str(c) for c in label_encoder.classes_], output_dict=True)
        print(classification_report(y_test, y_pred, target_names=[str(c) for c in label_encoder.classes_]))
        
        print(f"Weighted F1-Score: {report['weighted avg']['f1-score']:.4f}")
        print(f"Weighted Precision: {report['weighted avg']['precision']:.4f}")
        print(f"Weighted Recall: {report['weighted avg']['recall']:.4f}")
        
        # 8. Save artifacts
        print("Saving artifacts...")
        joblib.dump(xgb_model, 'xgb_model.joblib')
        joblib.dump(scaler, 'scaler.joblib')
        joblib.dump(label_encoder, 'label_encoder.joblib')
        joblib.dump(feature_list, 'feature_list.joblib')
        
        print("All artifacts saved successfully.")

    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    train_models()
