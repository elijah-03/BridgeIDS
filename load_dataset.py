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
2.  **Sampling**: Loads a fraction of data from each file to manage memory usage.
3.  **Type Enforcement**: Ensures columns are loaded with efficient data types.
4.  **Concatenation**: Combines all sampled data into a single DataFrame.
"""

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
                
                # Sample the data
                if sample_fraction < 1.0:
                    df = df.sample(frac=sample_fraction, random_state=42)
                
                df_list.append(df)
                
            except Exception as e:
                print(f"Error loading {file}: {e}")
                
        if not df_list:
            print("No data loaded.")
            return None
            
        print("Concatenating dataframes...")
        full_df = pd.concat(df_list, ignore_index=True)
        
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



