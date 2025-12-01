import sys
import joblib
import numpy as np
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight
from imblearn.over_sampling import SMOTE
import pandas as pd
import time
import gc

# Import the functions from your scripts
try:
    from load_dataset import load_and_inspect
    from preprocess import preprocess
except ImportError:
    print("Error: Could not import from 'load_dataset.py' or 'preprocess.py'.", file=sys.stderr)
    sys.exit(1)

import resource

# Define memory limit function
def set_memory_limit(max_gb=28):
    """Set a hard memory limit to prevent system crashes (leave 4GB for OS)"""
    try:
        max_bytes = int(max_gb * 1024 * 1024 * 1024)
        resource.setrlimit(resource.RLIMIT_AS, (max_bytes, max_bytes))
        print(f"✓ Memory limit set to {max_gb}GB to prevent system freeze")
    except Exception as e:
        print(f"⚠ Could not set memory limit: {e}")

# Call immediately
set_memory_limit(28)  # Leave 4GB for system

# Configuration
RANDOM_STATE = 42
SAMPLE_FRACTION = 0.15  # Keeping 15% as requested, but optimizing memory usage

def optimize_dtypes(df):
    """Downcast numeric types to save 50%+ memory"""
    for col in df.select_dtypes(include=['float64']).columns:
        df[col] = df[col].astype('float32')
    for col in df.select_dtypes(include=['int64']).columns:
        df[col] = df[col].astype('int32')
    return df

"""
Model Training Pipeline
-----------------------
This script handles the end-to-end training process for the IDS model:
1.  Loads data from CSV files using `load_dataset.py` with stratified sampling.
2.  Preprocesses data (cleaning, scaling, splitting) using `preprocess.py`.
3.  Applies SMOTE to balance minority classes in training data.
4.  Trains an XGBoost classifier with GPU acceleration (if available).
5.  Evaluates the model on a test set (F1, Precision, Recall).
6.  Benchmarks inference latency.
7.  Saves the trained model and artifacts (scaler, label encoder) for the backend.
"""

def train_models():
    """
    Loads, preprocesses, and trains XGBoost model, saving artifacts to disk.
    """
    
    # 1. Define data path
    DATASET_DIR = "/home/elijah/Documents/CPS373/Interp-ML-IDS/CSECICIDS2018_improved"
    
    try:
        # 2. Load Data
        print(f"--- Loading Data (Sample Fraction: {SAMPLE_FRACTION}) ---")
        raw_df = load_and_inspect(DATASET_DIR, sample_fraction=SAMPLE_FRACTION)
        
        if raw_df is None:
            print("Failed to load data.")
            return

        # OPTIMIZATION: Downcast types immediately
        print("Optimizing memory (downcasting types)...")
        raw_df = optimize_dtypes(raw_df)

        # 3. Preprocess
        print("--- Preprocessing Data ---")
        # preprocess returns: X_train, X_test, y_train, y_test, X_train_final, y_train_final, feature_list, le, scaler
        # We use X_train_final (X_train) and y_train_final (y_train) for training
        X_train_orig, X_test, y_train_orig, y_test, X_train_preprocessed, y_train_preprocessed, feature_list, label_encoder, scaler = preprocess(raw_df)
        
        # Free up memory from raw_df after preprocessing
        del raw_df
        gc.collect()  # Re-enabled!


        # 4. Split training data into Train and Validation for hyperparameter tuning
        print("Splitting training data for validation...")
        X_train_split, X_val, y_train_split, y_val = train_test_split(
            X_train_preprocessed, y_train_preprocessed, test_size=0.2, random_state=RANDOM_STATE, stratify=y_train_preprocessed
        )
        
        # Free up memory from X_train_preprocessed, y_train_preprocessed
        del X_train_preprocessed, y_train_preprocessed
        gc.collect()
        
        # 5. RESEARCH PAPER STRATEGY: Aggressive Benign Downsampling
        # Based on "Deep Learning for Improving Attack Detection System Using CSE-CICIDS2018" (2022)
        # Paper showed: Benign 16M -> 1M improved performance from various issues to 98.31% accuracy
        # Key insight: Class balance matters MORE than total data volume
        print("\n--- STEP 1: Aggressive Benign Downsampling (Research Paper Strategy) ---")
        print(f"Before downsampling: {X_train_split.shape}")
        print("Class distribution before downsampling:")
        unique, counts = np.unique(y_train_split, return_counts=True)
        class_counts_before = dict(zip(unique, counts))
        for cls, count in zip(unique, counts):
            print(f"  {label_encoder.inverse_transform([cls])[0]}: {count:,}")
        
        # Downsample Benign to 500K (balance between paper's 1M and 5min training time)
        benign_idx = list(label_encoder.classes_).index('Benign')
        benign_mask = y_train_split == benign_idx
        attack_mask = ~benign_mask
        
        benign_indices = np.where(benign_mask)[0]
        attack_indices = np.where(attack_mask)[0]
        
        # Target: 500K Benign samples (balanced for 32GB RAM)
        benign_target = 500000
        print(f"\nDownsampling Benign from {len(benign_indices):,} to {benign_target:,}...")
        
        if len(benign_indices) > benign_target:
            # Use numpy's RandomState for reproducibility
            rng = np.random.RandomState(RANDOM_STATE)
            benign_sampled = rng.choice(
                benign_indices,
                size=benign_target,
                replace=False
            )
        else:
            benign_sampled = benign_indices
        
        # Combine downsampled Benign with all attacks
        combined_indices = np.concatenate([benign_sampled, attack_indices])
        np.random.shuffle(combined_indices)
        
        X_train_split = X_train_split.iloc[combined_indices]
        y_train_split = y_train_split.iloc[combined_indices]
        
        # Free memory immediately
        del benign_indices, attack_indices, benign_sampled, combined_indices
        gc.collect()
        
        # Recalculate counts for printing after downsampling
        unique_after_downsample, counts_after_downsample = np.unique(y_train_split, return_counts=True)
        benign_count_after_downsample = counts_after_downsample[list(unique_after_downsample).index(benign_idx)]
        attack_counts_after_downsample = [c for i, c in enumerate(counts_after_downsample) if unique_after_downsample[i] != benign_idx]
        
        print(f"After downsampling: {X_train_split.shape}")
        print(f"Benign:Attack ratio changed from {class_counts_before.get(benign_idx, 0)/max(sum(v for k,v in class_counts_before.items() if k != benign_idx), 1):.1f}:1 to {benign_count_after_downsample/max(sum(attack_counts_after_downsample), 1):.1f}:1")
        
        # 6. STEP 2: Balanced SMOTE - Upsample ALL attacks to same level
        print("\n--- STEP 2: Balanced SMOTE (Equal Representation) ---")
        print("Class distribution after Benign downsampling:")
        unique, counts = np.unique(y_train_split, return_counts=True)
        class_counts = dict(zip(unique, counts))
        for cls, count in zip(unique, counts):
            print(f"  {label_encoder.inverse_transform([cls])[0]}: {count:,}")
        
        # Balanced strategy: Target 100K per attack class
        # This ensures model learns each attack type equally (not drowned out by Benign)
        target_samples_per_class = 100000
        sampling_strategy = {}
        
        for cls_idx, cls_name in enumerate(label_encoder.classes_):
            current_count = class_counts.get(cls_idx, 0)
            
            if cls_name == 'Benign':
                # Don't upsample Benign (already downsampled to 500K)
                continue
            else:
                # Upsample ALL attack classes to same target
                sampling_strategy[cls_idx] = max(current_count, target_samples_per_class)
        
        print(f"\nBalanced SMOTE Strategy (Target: {target_samples_per_class:,} per attack class):")
        for cls_idx, target in sampling_strategy.items():
            cls_name = label_encoder.inverse_transform([cls_idx])[0]
            current = class_counts.get(cls_idx, 0)
            print(f"  {cls_name}: {current:,} -> {target:,} ({(target/current):.1f}x)")
        
        # Apply SMOTE with k_neighbors=5 for quality synthetic samples
        print("\nApplying SMOTE (this may take 2-3 minutes)...")
        smote = SMOTE(random_state=RANDOM_STATE, k_neighbors=5, sampling_strategy=sampling_strategy)
        X_train_resampled, y_train_resampled = smote.fit_resample(X_train_split, y_train_split)
        
        # Free memory from original split
        del X_train_split, y_train_split, smote
        gc.collect()
        
        print(f"\nAfter Balanced SMOTE: {X_train_resampled.shape}")
        print("\nFinal balanced class distribution:")
        unique, counts = np.unique(y_train_resampled, return_counts=True)
        for cls, count in zip(unique, counts):
            cls_name = label_encoder.inverse_transform([cls])[0]
            pct = (count / len(y_train_resampled)) * 100
            print(f"  {cls_name}: {count:,} ({pct:.1f}%)")
        
        # Calculate final balance ratio
        benign_final = counts[list(unique).index(benign_idx)]
        avg_attack = np.mean([c for i, c in enumerate(counts) if unique[i] != benign_idx])
        print(f"\nFinal Benign:Attack ratio: {benign_final/avg_attack:.1f}:1 (MUCH better than before!)")
        
        # 7. Compute balanced sample weights
        print("\nComputing balanced sample weights...")
        sample_weights = compute_sample_weight(
            class_weight='balanced',
            y=y_train_resampled
        )
        
        # 8. XGBoost Configuration (Optimized for ~5min training + strong performance)
        # Based on both research papers' findings + optimization for speed
        xgb_params = {
            'objective': 'multi:softprob',
            'num_class': len(label_encoder.classes_),
            'tree_method': 'hist',  # Fast histogram-based algorithm
            'device': 'cpu',
            
            # Tuned for balanced dataset (100K per class)
            'learning_rate': 0.05,      # Moderate learning rate
            'max_depth': 7,              # Not too deep to avoid overfitting
            'n_estimators': 250,         # Reduced from 300 for speed (still sufficient)
            'min_child_weight': 5,       # Prevent overfitting on minority classes
            'gamma': 0.2,                # Moderate regularization
            'subsample': 0.75,           # Use 75% of samples per tree
            'colsample_bytree': 0.75,    # Use 75% of features per tree
            'reg_alpha': 0.1,            # L1 regularization
            'reg_lambda': 1.0,           # L2 regularization
            
            # Performance optimization
            'n_jobs': -1,                # Use all CPU cores
            'random_state': RANDOM_STATE,
            'verbosity': 1
        }
        
        print("\n--- Training XGBoost Model (Optimized for ~5min) ---")
        start_time = time.time()
        xgb_model = XGBClassifier(**xgb_params)
        
        # Free memory before training
        # Note: X_train_orig and y_train_orig are from preprocess, X_train_preprocessed and y_train_preprocessed were deleted earlier.
        # X_val, y_val are needed for eval_set
        # Memory cleanup before training
        del X_train_orig, y_train_orig
        gc.collect()
        print(f"Memory cleanup done. Training on {X_train_resampled.shape[0]:,} samples...")
        
        # Training with memory-efficient settings
        xgb_model.fit(
            X_train_resampled, y_train_resampled,
            sample_weight=sample_weights,
            eval_set=[(X_val, y_val)],  # Only validate on val set to save memory
            verbose=50  # Print every 50 rounds instead of every round
        )
        training_time = time.time() - start_time
        print(f"Training completed in {training_time:.2f} seconds.")
        
        # Clear resampled data to free memory
        del X_train_resampled, y_train_resampled, sample_weights
        gc.collect()
        
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
