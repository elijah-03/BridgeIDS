import pandas as pd
import numpy as np
import sys
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder

# Import the load function from load_dataset.py
try:
    from load_dataset import load_and_inspect
except ImportError:
    print("Error: Could not import 'load_and_inspect' from 'load_dataset.py'.", file=sys.stderr)
    sys.exit(1)

"""
Data Preprocessing Module
-------------------------
This module prepares the raw network traffic data for machine learning.
Key steps:
1.  **Label Cleaning**: Maps granular attack labels (e.g., 'DoS Hulk') to broad categories ('DoS').
2.  **Feature Selection**: Selects the 12 core features used by the IDS.
3.  **Feature Engineering**: Creates derived features from base features.
4.  **Data Cleaning**: Handles missing values, NaNs, and infinities.
5.  **Splitting**: Splits data into training and testing sets.
6.  **Scaling**: Normalizes features using StandardScaler.
"""

def engineer_features(X):
    """
    Creates derived features from base network traffic features.
    These features help the model better distinguish attack patterns.
    
    Args:
        X: DataFrame with base features
        
    Returns:
        DataFrame with base + engineered features
    """
    X = X.copy()
    
    # Rate-based features (attacks often have unusual rates)
    X['Packet_Rate'] = X['Total Fwd Packets'] / (X['Flow Duration'] + 1)
    X['Bytes_Per_Packet'] = X['Fwd Packets Length Total'] / (X['Total Fwd Packets'] + 1)
    X['IAT_To_Duration_Ratio'] = X['Flow IAT Mean'] / (X['Flow Duration'] + 1)
    
    # Flag-based features (attacks have unusual flag patterns)
    total_flags = X['FIN Flag Count'] + X['SYN Flag Count'] + X['RST Flag Count']
    X['Flag_Density'] = total_flags / (X['Total Fwd Packets'] + 1)
    X['SYN_Ratio'] = X['SYN Flag Count'] / (total_flags + 1)
    X['RST_Ratio'] = X['RST Flag Count'] / (total_flags + 1)
    
    # Port-based features
    common_ports = [80, 443, 22, 21, 23]
    X['Is_Common_Port'] = X['Dst Port'].isin(common_ports).astype(np.float32)
    
    # Port range category
    X['Port_Category'] = X['Dst Port'].apply(lambda p: 
        0 if p <= 1023 else (1 if p <= 49151 else 2)
    ).astype(np.float32)
    
    # Clean any NaN/Inf created during feature engineering
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)
    
    print(f"Added {8} engineered features:")
    print("  - Packet_Rate, Bytes_Per_Packet, IAT_To_Duration_Ratio")
    print("  - Flag_Density, SYN_Ratio, RST_Ratio")
    print("  - Is_Common_Port, Port_Category")
    
    return X


def preprocess(df):
    """
    Takes the raw DataFrame and preprocesses it for machine learning.
    
    - Cleans labels (Attempted -> Benign)
    - Encodes labels (Benign=0, Attacks=1..N)
    - Cleans NaN/Infinity values
    - Splits data into train/test sets
    - Scales features using StandardScaler
    - Applies SMOTE to the training data
    """
    
    TARGET_COLUMN = 'Label'
    
    try:
        # --- 1. Label Cleaning & Encoding ---
        print("--- Label Cleaning & Encoding ---")
        
        # Map 'Attempted' labels to 'Benign' (assuming they are not successful attacks or just noise)
        # Also map 'BENIGN' to 'Benign'
        
        # We can use a function or dictionary. Dictionary is faster.
        # Based on inspect_labels.py output:
        label_mapping = {
            'BENIGN': 'Benign',
            'DoS Hulk': 'DoS',
            'DoS GoldenEye': 'DoS',
            'DoS Slowloris': 'DoS',
            'DDoS-LOIC-HTTP': 'DDoS',
            'DDoS-LOIC-UDP': 'DDoS',
            'DDoS-HOIC': 'DDoS',
            'FTP-BruteForce': 'Brute Force',
            'SSH-BruteForce': 'Brute Force',
            'Web Attack - Brute Force': 'Web Attack',
            'Web Attack - SQL': 'Web Attack',
            'Web Attack - XSS': 'Web Attack',
            'Botnet Ares': 'Bot/Infiltration',
            'Infiltration - Communication Victim Attacker': 'Bot/Infiltration',
            'Infiltration - NMAP Portscan': 'Bot/Infiltration',
            'Infiltration - Dropbox Download': 'Bot/Infiltration'
        }
        
        # Handle 'Attempted' labels dynamically or add them to mapping
        # It seems many attacks have an '- Attempted' version.
        # We will map them to 'Benign' as per previous logic 'Attempted-relabel-as-Benign'
        
        def clean_label(label):
            if str(label).endswith(' - Attempted'):
                return 'Benign'
            return label_mapping.get(label, 'Benign') # Default to Benign if unknown
            
        df[TARGET_COLUMN] = df[TARGET_COLUMN].apply(clean_label)
        
        # Encode labels
        le = LabelEncoder()
        
        # Fit label encoder
        df['Label_Encoded'] = le.fit_transform(df[TARGET_COLUMN])
        
        # Print mapping
        mapping = dict(zip(le.classes_, le.transform(le.classes_)))
        print(f"Label Mapping: {mapping}")
        
        y = df['Label_Encoded']
        
        # --- 2. Feature Selection & Cleaning ---
        print("\n--- Feature Selection & Cleaning ---")
        
        # Define the 12 Control Panel Features
        # Note: 'Hour' needs to be extracted first
        
        # Extract Hour if Timestamp exists
        if 'Timestamp' in df.columns:
            print("Extracting Hour from Timestamp...")
            try:
                df['Timestamp'] = pd.to_datetime(df['Timestamp'])
                df['Hour'] = df['Timestamp'].dt.hour
            except Exception as e:
                print(f"Could not process Timestamp: {e}. Using 0 for Hour.")
                df['Hour'] = 0
        elif 'Hour' not in df.columns:
             df['Hour'] = 0 # Default if missing
             
        # Rename columns to match our expected feature names
        column_renames = {
            'Total Fwd Packet': 'Total Fwd Packets',
            'Total Length of Fwd Packet': 'Fwd Packets Length Total',
            'Fwd Packet Length Max': 'Fwd Packet Length Max', # Matches but good to be explicit
            'FIN Flag Count': 'FIN Flag Count',
            'SYN Flag Count': 'SYN Flag Count',
            'RST Flag Count': 'RST Flag Count',
            'FWD Init Win Bytes': 'Init Fwd Win Bytes'
        }
        df = df.rename(columns=column_renames)

        # Select Features
        # Now we include 'Dst Port' as it is present in the CSVs
        selected_features = [
            'Dst Port',
            'Protocol',
            'Hour',
            'Total Fwd Packets',
            'Fwd Packets Length Total',
            'Flow Duration',
            'Flow IAT Mean',
            'Fwd Packet Length Max',
            'FIN Flag Count',
            'SYN Flag Count',
            'RST Flag Count',
            'Init Fwd Win Bytes'
        ]
        
        # Check if all features exist
        missing_features = [f for f in selected_features if f not in df.columns]
        if missing_features:
            print(f"Warning: Missing features: {missing_features}")
            # Handle missing features (e.g., fill with 0)
            for f in missing_features:
                df[f] = 0
                
        X = df[selected_features]
        
        # Ensure all feature columns are numeric
        X = X.apply(pd.to_numeric, errors='coerce')
        
        # Downcast to float32 to save memory
        X = X.astype(np.float32)
        
        # Replace Infinity with NaN
        X = X.replace([np.inf, -np.inf], np.nan)
        
        # Fill all NaN values with 0
        X = X.fillna(0)
        
        print("Cleaned NaN and Infinity values.")
        
        # --- 2.7 Feature Engineering ---
        print("\n--- Engineering Additional Features ---")
        X = engineer_features(X)
        
        print(f"Final X shape after feature engineering: {X.shape}")
        
        # --- 2.5 Filter Rare Classes ---
        # Remove classes with fewer than 6 samples to allow for SMOTE (k_neighbors=5) if we were using it
        # But for XGBoost it's fine. However, let's keep the logic to be safe.
        class_counts = y.value_counts()
        valid_classes = class_counts[class_counts >= 6].index
        
        if len(valid_classes) < len(class_counts):
            print(f"Dropping classes with < 6 samples: {list(set(class_counts.index) - set(valid_classes))}")
            mask = y.isin(valid_classes)
            X = X[mask]
            y = y[mask]
            
            # Re-encode labels to be contiguous (0 to N-1)
            print("Re-encoding labels after filtering...")
            le = LabelEncoder()
            y = le.fit_transform(y)
            y = pd.Series(y) # Convert back to Series for consistency
            
            # Update mapping print
            mapping = dict(zip(le.classes_, le.transform(le.classes_)))
            print(f"New Label Mapping: {mapping}")
            
        # --- 3. Split the data ---
        print("\n--- Splitting Data ---")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=0.2,     # 80/20 split
            random_state=42,   # For reproducible results
            stratify=y         # Maintain class proportions
        )
        
        print(f"X_train shape: {X_train.shape}")
        print(f"y_train shape: {y_train.shape}")
        
        # --- 4. Scale the features ---
        print("\n--- Scaling Features ---")
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Convert back to DataFrame to keep column names (Force float32)
        X_train_scaled = pd.DataFrame(X_train_scaled, columns=X.columns, dtype=np.float32)
        X_test_scaled = pd.DataFrame(X_test_scaled, columns=X.columns, dtype=np.float32)
        
        # --- 5. Apply SMOTE ---
        # We will use class weights in XGBoost instead.
        
        # Just return the scaled training data as "resampled" to keep API consistent
        X_resampled = X_train_scaled
        y_resampled = y_train
        
        print(f"Training Data shape (No SMOTE): {X_resampled.shape}")
        
        return (
            X_train_scaled, X_test_scaled, y_train, y_test, 
            X_resampled, y_resampled, X.columns.tolist(), le, scaler
        )

    except Exception as e:
        print(f"An error occurred during preprocessing: {e}", file=sys.stderr)
        return None

if __name__ == "__main__":
    # Test run
    DATASET_DIR = "/home/elijah/Documents/CPS373/Interp-ML-IDS/UNSW-Distrinet-CSE-CIC-IDS2018/Parquet/CSVs"
    
    # Load small sample
    df = load_and_inspect(DATASET_DIR, sample_fraction=0.01)
    
    if df is not None:
        preprocess(df)



