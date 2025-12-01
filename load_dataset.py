import pandas as pd
import sys
import os
import glob

"""
Dataset Loader Module
---------------------
This module handles the loading of the CSE-CIC-IDS2018 dataset from CSV files.
It supports:
1.  **Directory Scanning**: Finds all CSV files in a specified directory.
2.  **Stratified Sampling**: Ensures minimum samples per class while respecting overall fraction.
3.  **Type Enforcement**: Ensures columns are loaded with efficient data types.
4.  **Concatenation**: Combines all sampled data into a single DataFrame.
"""

def stratified_sample_with_min(df, frac=0.1, min_samples=100, random_state=42):
    """
    Performs stratified sampling ensuring each class has at least min_samples.
    
    Args:
        df: DataFrame with 'Label' column
        frac: Target fraction to sample (applied to each class)
        min_samples: Minimum samples to keep for each class
        random_state: Random seed for reproducibility
        
    Returns:
        pd.DataFrame: Stratified sampled DataFrame
    """
    if 'Label' not in df.columns:
        print("Warning: 'Label' column not found, returning full DataFrame")
        return df
    
    sampled_dfs = []
    for label in df['Label'].unique():
        class_df = df[df['Label'] == label]
        
        # Calculate how many samples to take
        n_target = int(len(class_df) * frac)
        n_samples = max(n_target, min(min_samples, len(class_df)))
        
        # Sample
        if n_samples >= len(class_df):
            sampled_dfs.append(class_df)
        else:
            sampled_dfs.append(class_df.sample(n=n_samples, random_state=random_state))
    
    result = pd.concat(sampled_dfs, ignore_index=True)
    print(f"Stratified sampling: {len(df)} -> {len(result)} samples")
    print("Class distribution after sampling:")
    print(result['Label'].value_counts())
    return result


def load_and_inspect(directory_path, sample_fraction=0.1):
    """
    Loads CSV files from a directory, samples them, and concatenates into a single DataFrame.
    
    Args:
        directory_path (str): Path to the directory containing .csv files.
        sample_fraction (float): Fraction of data to sample from each file.
    
    Returns:
        pd.DataFrame: The loaded and sampled DataFrame.
    """
    try:
        print(f"Searching for CSV files in: {directory_path} ...")
        csv_files = glob.glob(os.path.join(directory_path, "*.csv"))
        
        if not csv_files:
            print("No .csv files found in the specified directory.")
            return None
            
        print(f"Found {len(csv_files)} files: {[os.path.basename(f) for f in csv_files]}")
        
        # Define columns to load and their types
        # Note: We use the CSV column names here
        usecols = [
            'Dst Port', 'Protocol', 'Timestamp',
            'Total Fwd Packet', 'Total Length of Fwd Packet',
            'Flow Duration', 'Flow IAT Mean',
            'Fwd Packet Length Max',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
            'FWD Init Win Bytes',
            'Label'
        ]
        
        dtypes = {
            'Dst Port': 'uint32', # Use uint32 to be safe for 65535 and potential bad values
            'Protocol': 'uint8',
            'Total Fwd Packet': 'uint32',
            'Total Length of Fwd Packet': 'float32',
            'Flow Duration': 'float32',
            'Flow IAT Mean': 'float32',
            'Fwd Packet Length Max': 'float32',
            'FIN Flag Count': 'uint8',
            'SYN Flag Count': 'uint8',
            'RST Flag Count': 'uint8',
            'FWD Init Win Bytes': 'uint32',
            'Label': 'object'
        }

        df_list = []
        
        for file in csv_files:
            print(f"Loading and sampling {os.path.basename(file)}...")
            try:
                # Read specific columns with types
                df = pd.read_csv(
                    file, 
                    usecols=lambda c: c in usecols, # Handle potential missing columns gracefully? No, better to fail or check.
                    # Actually, usecols list is stricter.
                    # But some files might have slightly different names? 
                    # Let's assume consistency for now based on inspection.
                    # If 'Timestamp' is missing, it will error.
                    dtype=dtypes,
                    low_memory=False
                )
                
                # Filter to only required columns (double check)
                df = df[[c for c in usecols if c in df.columns]]
                
                # OPTIMIZATION: Sample IMMEDIATELY to save memory
                # Instead of loading all 16M rows then sampling, we sample each file
                if sample_fraction < 1.0:
                    # We can't do perfect stratified sampling per file without knowing global distribution,
                    # but we can do random sampling or stratified per file.
                    # Stratified per file is safer to preserve rare classes if they are concentrated in one file.
                    print(f"  Sampling {sample_fraction*100}% of {os.path.basename(file)}...")
                    df = stratified_sample_with_min(df, frac=sample_fraction, min_samples=100)
                
                df_list.append(df)
                
            except Exception as e:
                print(f"Error loading {file}: {e}")
                
        if not df_list:
            print("No data loaded.")
            return None
            
        print("Concatenating dataframes...")
        full_df = pd.concat(df_list, ignore_index=True)
        
        # No need to sample again
        # print(f"Applying stratified sampling (fraction={sample_fraction})...")
        # full_df = stratified_sample_with_min(full_df, frac=sample_fraction, min_samples=100)
        
        print("Dataset loaded successfully.\n")
        print("--- Dataset Info ---")
        print(f"Total Rows: {full_df.shape[0]}")
        print(f"Total Columns: {full_df.shape[1]}")
        print("\n")
        
        print("--- Target Column Distribution ---")
        if 'Label' in full_df.columns:
            print(full_df['Label'].value_counts())
        else:
            print("'Label' column not found.")
            
        return full_df

    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        return None

if __name__ == "__main__":
    # Path to the directory containing CSV files
    DATASET_DIR = "/home/elijah/Documents/CPS373/Interp-ML-IDS/CSECICIDS2018_improved"
    
    # Load data with 1% sampling for quick inspection (adjust as needed for training)
    df = load_and_inspect(DATASET_DIR, sample_fraction=0.01)



