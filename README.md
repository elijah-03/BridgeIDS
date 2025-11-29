# Interpretable Machine Learning for Intrusion Detection

A web-based interface for an XGBoost-based Intrusion Detection System (IDS) trained on the CSE-CIC-IDS2018 dataset. This project focuses on **interpretability**, providing real-time insights into why specific network traffic is classified as malicious or benign.

## Features

-   **Real-time Prediction**: Classifies traffic into 6 categories: Benign, DoS, DDoS, Brute Force, Web Attack, and Bot/Infiltration.
-   **Interpretability Insights**:
    -   **Key Drivers**: Identifies the top features contributing to the prediction using Z-score analysis.
    -   **Pattern Detection**: Maps feature combinations to known attack patterns (e.g., "Slowloris-style attack", "SQL Injection").
    -   **Sensitivity Analysis**: Performs "what-if" scenarios to determine boundary conditions (e.g., "Reducing Flow Duration by 30% would change prediction to Benign").
-   **Interactive Control Panel**:
    -   Adjust feature values using sliders with logarithmic scaling for wide-range inputs.
    -   Apply presets for common attack scenarios.
    -   View confidence levels and probability distributions.

## Installation

1.  **Clone the repository**:
    ```bash
    git clone <repository-url>
    cd Interp-ML-IDS
    ```

2.  **Create and activate a virtual environment**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  **Train the Model** (Optional if artifacts already exist):
    ```bash
    python train_model.py
    ```
    This script loads the dataset, preprocesses it, trains the XGBoost model, and saves the necessary artifacts (`xgb_model.joblib`, `scaler.joblib`, etc.).

2.  **Run the Web Interface**:
    ```bash
    flask run
    ```
    Or directly:
    ```bash
    python app.py
    ```

3.  **Access the Dashboard**:
    Open your browser and navigate to `http://127.0.0.1:5000`.

## File Structure

-   `app.py`: Main Flask application backend. Handles predictions and interpretability logic.
-   `train_model.py`: Script to train the XGBoost model and save artifacts.
-   `preprocess.py`: Data cleaning, feature selection, and preprocessing logic.
-   `load_dataset.py`: Utility to load and sample the CSE-CIC-IDS2018 dataset.
-   `static/`: CSS styles and JavaScript logic for the frontend.
-   `templates/`: HTML templates for the web interface.
-   `dataset-notes`: Notes on the dataset source and characteristics.
-   `Improved_CSE-CIC-IDS_2018_Documentation`: Documentation for the improved dataset.
-   `*.joblib`: Serialized model and preprocessing artifacts.

## Dataset

This project uses the **CSE-CIC-IDS2018** dataset. The `CSECICIDS2018_improved` directory should contain the CSV files. The loader handles sampling and concatenation automatically.
