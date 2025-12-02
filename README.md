# Interpretable Machine Learning for Intrusion Detection

A web-based interface for an XGBoost-based Intrusion Detection System (IDS) trained on the CSE-CIC-IDS2018 dataset. This project focuses on **"Bridging the Gap"** between high-performance machine learning and human interpretability, providing real-time, interactive insights into why specific network traffic is classified as malicious.

## Research Report
A comprehensive research report detailing the methodology, system design, and evaluation results is available here:
**[Read the Full Report](docs/BridgeIDS_Report.md)**

## Test Server
-   https://interp-ml-ids.coryandcody.digital/

## Key Features

### High-Performance Detection
-   **Model**: XGBoost Classifier with Histogram-based optimization.
-   **Accuracy**: **97.66%** (Evaluated on 12.6 million samples).
-   **Classes**: Benign, DoS, DDoS, Brute Force, Web Attack, Bot/Infiltration.

### Interactive Interpretability
-   **"What-If" Analysis**: Adjust feature values (e.g., ports, flow duration) in real-time to see how the prediction changes.
-   **Key Drivers**: Identifies the top features contributing to the prediction using Z-score analysis and SHAP concepts.
-   **Pattern Detection**: Maps feature combinations to known attack patterns (e.g., "Slowloris-style attack", "SQL Injection").
-   **Safety Prescriptions**: Suggests counterfactuals (minimal changes) to reclassify traffic as benign.

### Interactive Control Panel
-   **Logarithmic Sliders**: Handle the wide dynamic range of network features (0 to 120M+).
-   **Attack Presets**: Pre-configured buttons to simulate common attacks (DoS GoldenEye, Brute Force SSH, etc.) with high-confidence configurations.
-   **Real-time Visualization**: Dynamic probability charts and confidence gauges.
-   **Enhanced Tooltips**: Comprehensive explanations for all controls and presets, ensuring clarity for users.

## Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/elijah-03/Interp-ML-IDS
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
    This script loads the dataset, preprocesses it (using Benign Downsampling + SMOTE), trains the XGBoost model, and saves the artifacts (`xgb_model.joblib`, `scaler.joblib`, etc.).

2.  **Evaluate the Model**:
    ```bash
    python evaluate_model.py
    ```
    Runs a batch evaluation on the dataset to generate performance metrics.

3.  **Evaluate Rule-Based System**:
    ```bash
    python evaluate_rules.py
    ```
    Evaluates the surrogate model's rule-based logic against the main XGBoost model to ensure interpretability alignment.

4.  **Generate Report Visuals**:
    ```bash
    python generate_report_visuals.py
    ```
    Generates static plots (confusion matrices, feature importance) for the research report.

5.  **Run the Web Interface**:
    ```bash
    flask run
    ```
    Or directly:
    ```bash
    python app.py
    ```

6.  **Access the Dashboard**:
    Open your browser and navigate to `http://127.0.0.1:5000`.

## File Structure

-   `app.py`: Main Flask application backend. Handles predictions and interpretability logic.
-   `train_model.py`: Script to train the XGBoost model and save artifacts.
-   `evaluate_model.py`: Script for batch evaluation of the model.
-   `evaluate_rules.py`: Script to evaluate the rule-based surrogate system.
-   `generate_report_visuals.py`: Script to generate plots for the report.
-   `preprocess.py`: Data cleaning, feature selection, and preprocessing logic.
-   `load_dataset.py`: Utility to load and sample the CSE-CIC-IDS2018 dataset.
-   `static/`: CSS styles and JavaScript logic for the frontend.
-   `templates/`: HTML templates for the web interface.
-   `docs/`: Documentation and research reports.
    -   `BridgeIDS_Report.md`: Full project report.
    -   `Latex/`: LaTeX source code and figures for the PDF report.
-   `*.joblib`: Serialized model and preprocessing artifacts.

## Dataset

This project uses the **CSE-CIC-IDS2018** dataset. The `CSECICIDS2018_improved` directory should contain the CSV files. The loader handles sampling and concatenation automatically.
