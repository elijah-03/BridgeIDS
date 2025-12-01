"""
IDS Control Panel - Flask Backend
Provides ML-based network traffic analysis with SHAP interpretability.

Key Features:
- Real-time traffic classification (Benign, DoS, DDoS, etc.)
- SHAP-based feature importance
- Local decision rules
- Sensitivity analysis
- Pattern detection
"""

import io
import joblib
import pandas as pd
import numpy as np
from flask import Flask, request, jsonify, render_template
from datetime import datetime
import shap
import matplotlib

# Local config import
from config import (
    MODEL_PATH,
    SCALER_PATH,
    LE_PATH,
    FEATURE_LIST_PATH,
    PORT_MAP,
    FEATURE_DISPLAY_NAMES,
)

matplotlib.use("Agg")  # Non-interactive backend for server use
import matplotlib.pyplot as plt
import base64

app = Flask(__name__)

# Load artifacts
print("Loading model and artifacts...")
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    le = joblib.load(LE_PATH)
    feature_list = joblib.load(FEATURE_LIST_PATH)

    # Force model to use CPU for inference to avoid mismatch warnings
    if hasattr(model, "set_params"):
        try:
            model.set_params(tree_method="hist", device="cpu")
        except Exception:
            pass  # Model may not support these params

    # Create SHAP explainer
    # Use a representative background dataset for faster computation
    # Using the scaler's mean as a simple background (single point for speed)
    background = pd.DataFrame([scaler.mean_], columns=feature_list)
    explainer = shap.TreeExplainer(model, background)
    print("✓ Model loaded successfully")
    print(f"✓ Features: {len(feature_list)}")
    print(f"✓ Classes: {list(le.classes_)}")
except Exception as e:
    print(f"✗ Error loading model: {e}")
    model = None
    scaler = None
    le = None
    feature_list = []
    explainer = None

# Surrogate model removed - we now always use SHAP-based local rules
# SHAP val are already computed for every prediction, so there's no performance penalty


@app.route("/")
def index() -> str:
    """
    Render the main dashboard.
    Passes the list of features to the template for dynamic form generation.

    Returns:
        str: Rendered HTML template
    """
    return render_template("index.html", features=feature_list)


def engineer_features_for_prediction(df: pd.DataFrame) -> pd.DataFrame:
    """
    Auto-calculate derived features from base features for prediction.
    Keeps UI simple - users only adjust base features, derived features calculated automatically.

    Args:
        df: DataFrame with base features

    Returns:
        DataFrame with both base and derived features
    """
    # Rate-based features (attacks often have unusual rates)
    df["Packet_Rate"] = df["Total Fwd Packets"] / (df["Flow Duration"] + 1)
    df["Bytes_Per_Packet"] = df["Fwd Packets Length Total"] / (
        df["Total Fwd Packets"] + 1
    )
    df["IAT_To_Duration_Ratio"] = df["Flow IAT Mean"] / (df["Flow Duration"] + 1)

    # Flag-based features (attacks have unusual flag patterns)
    total_flags = df["FIN Flag Count"] + df["SYN Flag Count"] + df["RST Flag Count"]
    df["Flag_Density"] = total_flags / (df["Total Fwd Packets"] + 1)
    df["SYN_Ratio"] = df["SYN Flag Count"] / (total_flags + 1)
    df["RST_Ratio"] = df["RST Flag Count"] / (total_flags + 1)

    # Port-based features
    common_ports = [80, 443, 22, 21, 23]
    df["Is_Common_Port"] = df["Dst Port"].isin(common_ports).astype(float)

    # Port range category
    df["Port_Category"] = (
        df["Dst Port"]
        .apply(lambda p: 0 if p <= 1023 else (1 if p <= 49151 else 2))
        .astype(float)
    )

    # Clean any NaN/Inf created during feature engineering
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.fillna(0)

    return df


def detect_attack_pattern(predicted_class, input_data, z_scores, feature_list):
    """
    Detect and describe attack patterns based on feature combinations.
    Returns a human-readable description of the pattern.
    """

    # Helper to get z-score for a feature
    def get_z(feature_name):
        try:
            idx = feature_list.index(feature_name)
            return z_scores[idx]
        except (ValueError, IndexError):
            return 0

    # Helper to check if feature is unusually high (z > 1.5)
    def is_high(feature_name):
        return get_z(feature_name) > 1.5

    # Helper to check if feature is unusually low (z < -1.5)
    def is_low(feature_name):
        return get_z(feature_name) < -1.5

    dst_port = int(input_data.get("Dst Port", 0))
    protocol = int(input_data.get("Protocol", 6))

    patterns = {
        "DoS": [
            # Slowloris-style: long duration, low packet rate
            (
                lambda: is_high("Flow Duration")
                and is_high("Flow IAT Mean")
                and dst_port in [80, 443],
                "Slowloris-style attack - sustained slow connections exhausting server resources",
            ),
            # Volumetric flood: massive packets, short duration
            (
                lambda: is_high("Total Fwd Packets") and is_low("Flow Duration"),
                "Volumetric flood - massive packet burst to overwhelm target",
            ),
            # Protocol abuse
            (
                lambda: is_high("Total Fwd Packets") and protocol != 6,
                "Protocol abuse attack - non-TCP flood (likely UDP/ICMP)",
            ),
            # Generic high volume
            (
                lambda: is_high("Flow Duration") and is_high("Total Fwd Packets"),
                "Resource exhaustion attack - prolonged high-volume traffic",
            ),
            (lambda: is_high("Total Fwd Packets"), "High packet volume DoS pattern"),
        ],
        "Brute Force": [
            # Targeted service attacks
            (
                lambda: is_high("SYN Flag Count") and dst_port in [21, 22, 23],
                f"Credential brute force on {PORT_MAP.get(dst_port, 'service')} - rapid connection attempts",
            ),
            (
                lambda: is_high("FIN Flag Count") and is_low("Flow Duration"),
                "Rapid-fire authentication attempts - failed connection pattern",
            ),
            (
                lambda: dst_port == 23,
                "Telnet brute force - extremely high-risk legacy protocol attack",
            ),
            (
                lambda: dst_port in [21, 22, 25, 3389],
                f"Targeted attack on {PORT_MAP.get(dst_port, 'authentication')} service",
            ),
        ],
        "Web Attack": [
            # SQL Injection: large payloads + web ports
            (
                lambda: is_high("Fwd Packet Length Max")
                and is_high("Fwd Packets Length Total")
                and dst_port in [80, 443],
                "SQL Injection pattern - complex queries with large payloads targeting database",
            ),
            # XSS: moderate payloads + many packets
            (
                lambda: is_high("Total Fwd Packets")
                and dst_port in [80, 443]
                and not is_high("Fwd Packet Length Max"),
                "Cross-Site Scripting (XSS) pattern - multiple requests with script injection attempts",
            ),
            # Web brute force / fuzzing
            (
                lambda: is_high("Total Fwd Packets")
                and is_low("Flow Duration")
                and dst_port in [80, 443],
                "Web application fuzzing - rapid enumeration or path traversal attack",
            ),
            # Generic web exploit
            (
                lambda: is_high("Fwd Packets Length Total") and dst_port in [80, 443],
                "Web application exploit - abnormal HTTP request patterns",
            ),
            (
                lambda: dst_port in [80, 443],
                "HTTP/HTTPS service targeted with suspicious traffic",
            ),
        ],
        "DDoS": [
            # SYN flood
            (
                lambda: is_high("SYN Flag Count") and is_high("Total Fwd Packets"),
                "Distributed SYN flood - coordinated connection saturation from multiple sources",
            ),
            # Burst flood
            (
                lambda: is_high("Total Fwd Packets") and is_low("Flow Duration"),
                "Amplification DDoS - massive burst traffic from distributed botnet",
            ),
            # Sustained distributed attack
            (
                lambda: is_high("Total Fwd Packets"),
                "Distributed volumetric attack - coordinated high-volume assault",
            ),
        ],
        "Bot/Infiltration": [
            # C&C communication
            (
                lambda: dst_port > 8000 and is_high("Total Fwd Packets"),
                "Command & Control (C2) communication - botnet traffic to high port",
            ),
            # Backdoor/persistence
            (
                lambda: is_high("Flow Duration")
                and dst_port not in [80, 443, 21, 22, 23, 25, 53],
                "Backdoor communication - persistent connection to unusual port",
            ),
            # Data exfiltration
            (
                lambda: is_high("Fwd Packets Length Total")
                and dst_port not in [80, 443],
                "Potential data exfiltration - large data transfer to non-standard port",
            ),
            (lambda: True, "Automated malicious behavior detected"),
        ],
        "Benign": [
            # Legitimate high-load (e.g., file downloads, streaming)
            (
                lambda: is_high("Flow Duration")
                and dst_port in [80, 443]
                and not is_high("SYN Flag Count"),
                "Legitimate high-bandwidth session - likely file download or media streaming",
            ),
            # Interactive session (SSH, RDP)
            (
                lambda: is_high("Flow Duration")
                and dst_port in [22, 3389]
                and is_low("Total Fwd Packets"),
                "Interactive remote session - normal SSH/RDP administrative traffic",
            ),
            # Normal DNS
            (lambda: dst_port == 53, "Normal DNS query traffic"),
            # Clean traffic
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
                "Clean traffic - all metrics within normal parameters",
            ),
            (lambda: True, "Traffic within expected baseline"),
        ],
    }

    # Get patterns for predicted class
    class_patterns = patterns.get(predicted_class, [])

    # Find first matching pattern
    for condition, description in class_patterns:
        try:
            if condition():
                return description
        except Exception:
            continue

    # Default fallback
    return f"Detected as {predicted_class} based on traffic characteristics"


def format_value(feature_name: str, value: float) -> str:
    """
    Format feature values for human readability.

    Args:
        feature_name: Name of the feature
        value: Numeric value to format

    Returns:
        Human-readable formatted string
    """
    if feature_name == "Flow Duration" or feature_name == "Connection Duration":
        # Duration is in microseconds, convert to seconds
        seconds = value / 1_000_000
        if seconds < 1:
            return f"{value / 1000:.1f} ms"
        elif seconds < 60:
            return f"{seconds:.1f} sec"
        else:
            return f"{seconds / 60:.1f} min"
    elif feature_name == "Dst Port" or feature_name == "Destination Port":
        # Show port with service name if known
        port_name = PORT_MAP.get(int(value), "")
        if port_name:
            return f"{int(value)} ({port_name})"
        return f"{int(value)}"
    elif (
        "Packet" in feature_name
        or "Count" in feature_name
        or feature_name == "Hour"
        or feature_name == "Hour of Day"
    ):
        # Integer counts
        return f"{int(value):,}"
    elif "Bytes" in feature_name:
        # Byte sizes
        if value < 1024:
            return f"{int(value)} bytes"
        elif value < 1024 * 1024:
            return f"{value / 1024:.1f} KB"
        else:
            return f"{value / (1024 * 1024):.1f} MB"
    elif "Rate" in feature_name or "Ratio" in feature_name or "Density" in feature_name:
        # Ratios and rates as percentages or decimals
        if value < 1:
            return f"{value:.3f}"
        else:
            return f"{value:.2f}"
    else:
        # Default formatting
        if value > 1000:
            return f"{value:,.1f}"
        elif value > 1:
            return f"{value:.2f}"
        else:
            return f"{value:.3f}"


def generate_shap_based_rule(
    shap_values,
    feature_list,
    feature_values,
    z_scores,
    predicted_class,
    prediction_confidence,
):
    """
    Generate a dynamic local rule from SHAP values.
    This is used as a fallback when the surrogate model has no matching rule.

    Returns a rule structure matching the format of surrogate rules.
    """
    # Get top features by absolute SHAP contribution
    top_indices = np.argsort(np.abs(shap_values))[::-1][:5]  # Top 5 features

    formatted_conditions = []

    for idx in top_indices:
        feature_name = feature_list[idx]
        shap_val = shap_values[idx]
        z_val = z_scores[idx]
        current_val = feature_values[idx]

        # Skip if SHAP contribution is negligible
        if abs(shap_val) < 0.01:
            continue

        display_name = FEATURE_DISPLAY_NAMES.get(feature_name, feature_name)
        formatted_val = format_value(feature_name, current_val)

        # Create natural language description
        if z_val > 2.5:
            intensity = "extremely high"
        elif z_val > 1.5:
            intensity = "high"
        elif z_val < -2.5:
            intensity = "extremely low"
        elif z_val < -1.5:
            intensity = "low"
        else:
            intensity = "moderate"

        # Build natural language description
        if z_val > 1.5 or z_val < -1.5:
            description = (
                f"{intensity.capitalize()} {display_name.lower()} ({formatted_val})"
            )
        else:
            description = f"{display_name} is {formatted_val}"

        formatted_conditions.append(
            {
                "feature": display_name,
                "operator": "",  # Not needed for natural language
                "value": float(current_val),
                "description": description,
            }
        )

    # Limit to top 3-4 most important conditions for readability
    formatted_conditions = formatted_conditions[:4]

    return {
        "rules": formatted_conditions,
        "prediction": predicted_class,
        "confidence": prediction_confidence,  # Use actual prediction confidence
        "source": "shap",  # Mark as SHAP-generated for UI
    }


@app.route("/predict", methods=["POST"])
def predict():
    """
    Handle prediction requests.

    Expects JSON input with feature values.
    Returns JSON response containing:
    - prediction: The predicted class (e.g., 'Benign', 'DoS').
    - confidence_level: 'High', 'Medium', or 'Low'.
    - timestamp: ISO format timestamp.
    - probabilities: List of class probabilities.
    - insights: Key drivers based on Z-scores.
    - pattern_description: Human-readable attack pattern description.
    - sensitivity_analysis: 'What-if' scenarios and boundary detection.
    - shap_plot: Base64 encoded image of SHAP force plot.
    """
    if not model:
        return jsonify({"error": "Model not loaded"}), 500
    try:
        # The frontend sends the features dictionary directly
        data = request.json

        # Create DataFrame from input data (12 base features)
        # Ensure all features are present, fill missing with 0
        base_feature_list = [
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
        input_data = {
            feature: float(data.get(feature, 0)) for feature in base_feature_list
        }
        df = pd.DataFrame([input_data])

        # Engineer derived features (auto-calculated from base features)
        df = engineer_features_for_prediction(df)

        # Create feature array in correct order
        # Ensure df columns are in the correct order for the scaler
        df = df[feature_list]
        features = df.values  # Keep features as numpy array for other calculations

        print("\n--- Received Features ---")
        for i, feature in enumerate(feature_list):
            print(f"{feature}: {features[0][i]}")

        # Scale features using the DataFrame to preserve feature names
        features_scaled = scaler.transform(df)

        # Predict
        prediction = model.predict(features_scaled)
        probs = model.predict_proba(features_scaled)[0]

        predicted_class_idx = prediction[0]
        predicted_class = le.inverse_transform([predicted_class_idx])[0]

        # Calculate Z-scores for insights
        # z = (x - mean) / scale
        z_scores = (features[0] - scaler.mean_) / scaler.scale_

        # Find top 3 features with highest absolute Z-scores
        top_indices = np.argsort(np.abs(z_scores))[::-1][:3]

        insights = []
        for idx in top_indices:
            feature_name = feature_list[idx]
            z_val = z_scores[idx]
            feature_value = features[0][idx]

            # Skip if not significant
            if abs(z_val) < 1.0:
                continue

            # Use full display name
            display_name = FEATURE_DISPLAY_NAMES.get(feature_name, feature_name)

            # Format the value readably
            readable_value = format_value(feature_name, feature_value)

            # Determine magnitude descriptor
            abs_z = abs(z_val)
            if abs_z > 2.5:
                magnitude = "Very high" if z_val > 0 else "Very low"
            elif abs_z > 1.5:
                magnitude = "High" if z_val > 0 else "Low"
            else:
                magnitude = "Slightly high" if z_val > 0 else "Slightly low"

            # Create description: state the value + context
            description_parts = []
            description_parts.append(
                f"{magnitude} {display_name.lower()} ({readable_value})"
            )

            # Add context based on feature and prediction
            context = ""
            if feature_name == "Total Fwd Packets":
                if z_val > 2.0:
                    context = "suggesting bulk data transfer or flooding"
                elif z_val < -1.5:
                    context = "minimal activity"
            elif (
                feature_name == "Flow Duration" or feature_name == "Connection Duration"
            ):
                if z_val > 2.0:
                    context = "long-lived connection"
                elif z_val < -1.5:
                    context = "very brief connection"
            elif feature_name == "Fwd Packets Length Total":
                if z_val > 2.0:
                    context = "large data transfer"
                elif z_val < -1.5:
                    context = "minimal data transfer"
            elif (
                feature_name == "Flow IAT Mean"
                or feature_name == "Avg Time Between Packets"
            ):
                if z_val > 2.0:
                    context = "slow packet rate"
                elif z_val < -1.5:
                    context = "rapid packet rate"
            elif feature_name == "Dst Port" or feature_name == "Destination Port":
                if feature_value == 80 or feature_value == 443:
                    context = "web traffic"
                elif feature_value == 22:
                    context = "SSH traffic"
                elif feature_value == 21:
                    context = "FTP traffic"
            elif "Flag" in feature_name:
                if z_val > 1.5:
                    context = "abnormal flag behavior"

            # Combine parts
            if context:
                description = f"{description_parts[0]} - {context}"
            else:
                description = description_parts[0]

            insights.append(
                {
                    "feature": feature_name,
                    "z_score": float(z_val),
                    "direction": "High" if z_val > 0 else "Low",
                    "description": description,
                }
            )

        # Calculate confidence level based on top probability
        max_prob = float(np.max(probs))
        if max_prob > 0.95:
            confidence_level = "High"
        elif max_prob > 0.75:
            confidence_level = "Medium"
        else:
            confidence_level = "Low"

        # Calculate SHAP values (Moved up for Counterfactuals)
        shap_values = explainer.shap_values(features_scaled)

        # Robustly handle SHAP output structure
        shap_values_for_class = None

        # Case 1: List of arrays (one per class) - standard for multi-class
        if isinstance(shap_values, list):
            # Check if predicted_class_idx is valid
            if predicted_class_idx < len(shap_values):
                shap_values_for_class = shap_values[predicted_class_idx]
            else:
                # Fallback: try the first one or last one?
                # Usually len(shap_values) == n_classes
                shap_values_for_class = shap_values[-1]

        # Case 2: Single array (binary or specific output format)
        elif isinstance(shap_values, np.ndarray):
            # If 3D array (samples, features, classes), extract for class
            if len(shap_values.shape) == 3:
                shap_values_for_class = shap_values[:, :, predicted_class_idx]
            # If 2D array (samples, features), use as is
            else:
                shap_values_for_class = shap_values

        # Extract contributions for the single sample
        # shap_values_for_class is now (n_samples, n_features) -> (1, 12)
        if shap_values_for_class is not None and len(shap_values_for_class) > 0:
            sample_shap = shap_values_for_class[0]
        else:
            # Fallback if something fails
            sample_shap = np.zeros(len(feature_list))

        # Create dictionary for frontend
        shap_contributions = {
            feature_list[i]: float(sample_shap[i]) for i in range(len(feature_list))
        }

        # Enhanced Feature Sensitivity Analysis & Counterfactuals
        sensitivity_analysis = []
        counterfactuals = []

        # Identify top drivers using SHAP (more accurate than Z-score)
        # Get indices of features with highest positive contribution
        top_shap_indices = np.argsort(sample_shap)[::-1]

        # For attack predictions: find what would make it benign
        if predicted_class != "Benign":
            # Try top 3 SHAP drivers
            for idx in top_shap_indices[:3]:
                feature_name = feature_list[idx]

                # Skip if SHAP contribution is not positive (not driving the attack)
                if sample_shap[idx] <= 0:
                    continue

                display_name = FEATURE_DISPLAY_NAMES.get(feature_name, feature_name)
                current_value = features[0][idx]

                # Boundary detection: find tipping point
                modification_found = False

                # Try reducing by percentage, including aggressive reduction
                for reduction_pct in [10, 20, 30, 40, 50, 60, 70, 80, 90, 95, 99, 100]:
                    modified_features = features.copy()

                    if reduction_pct == 100:
                        modified_features[0][idx] = 0  # Set to 0
                    else:
                        modified_features[0][idx] = current_value * (
                            1 - reduction_pct / 100
                        )

                    # Convert to DataFrame to preserve feature names for scaler
                    modified_df = pd.DataFrame(modified_features, columns=feature_list)
                    modified_scaled = scaler.transform(modified_df)
                    new_pred_probs = model.predict_proba(modified_scaled)[0]
                    new_pred_class = le.inverse_transform([np.argmax(new_pred_probs)])[
                        0
                    ]
                    new_max_prob = float(np.max(new_pred_probs))

                    # Check if prediction changed to Benign
                    if new_pred_class == "Benign":
                        target_val = modified_features[0][idx]
                        counterfactuals.append(
                            {
                                "feature": feature_name,
                                "current_value": float(current_value),
                                "target_value": float(target_val),
                                "action": f"Reduce {display_name} to < {target_val:.1f}",
                                "impact": "Changes prediction to Benign",
                            }
                        )
                        modification_found = True
                        break

                    # Check if prediction changed to ANY other class
                    elif new_pred_class != predicted_class and not modification_found:
                        sensitivity_analysis.append(
                            {
                                "feature": feature_name,
                                "type": "boundary",
                                "current_value": float(current_value),
                                "threshold_value": float(modified_features[0][idx]),
                                "reduction_percent": reduction_pct,
                                "would_change_to": new_pred_class,
                                "description": f"Reducing {display_name} by {reduction_pct}% would change prediction to {new_pred_class}",
                            }
                        )
                        modification_found = (
                            True  # Don't break, keep looking for Benign
                        )

                    # Check for significant confidence drop
                    elif max_prob - new_max_prob > 0.15 and not modification_found:
                        sensitivity_analysis.append(
                            {
                                "feature": feature_name,
                                "type": "confidence_impact",
                                "current_value": float(current_value),
                                "test_value": float(modified_features[0][idx]),
                                "reduction_percent": reduction_pct,
                                "confidence_drop": f"{max_prob:.0%} → {new_max_prob:.0%}",
                                "description": f"Reducing {display_name} by {reduction_pct}% significantly lowers confidence",
                            }
                        )
                        modification_found = True

        # For benign predictions: find what would trigger an alert
        else:
            suspicious_features = [
                "SYN Flag Count",
                "Total Fwd Packets",
                "Flow Duration",
                "RST Flag Count",
            ]
            for feature_name in suspicious_features:
                try:
                    idx = feature_list.index(feature_name)
                    display_name = FEATURE_DISPLAY_NAMES.get(feature_name, feature_name)
                    current_value = features[0][idx]

                    # Test increasing suspicious features
                    for increase_factor in [2, 3, 5, 10, 20]:
                        modified_features = features.copy()
                        modified_features[0][idx] = current_value * increase_factor
                        # Convert to DataFrame to preserve feature names for scaler
                        modified_df = pd.DataFrame(
                            modified_features, columns=feature_list
                        )
                        modified_scaled = scaler.transform(modified_df)
                        new_pred_probs = model.predict_proba(modified_scaled)[0]
                        new_pred_class = le.inverse_transform(
                            [np.argmax(new_pred_probs)]
                        )[0]

                        if new_pred_class != "Benign":
                            sensitivity_analysis.append(
                                {
                                    "feature": feature_name,
                                    "type": "benign_to_malicious",
                                    "current_value": float(current_value),
                                    "trigger_value": float(
                                        current_value * increase_factor
                                    ),
                                    "increase_factor": increase_factor,
                                    "would_trigger": new_pred_class,
                                    "description": f"Increasing {display_name} by {increase_factor}x would trigger {new_pred_class} detection",
                                }
                            )
                            break
                except (ValueError, IndexError):
                    continue

            # Limit to top 2 most sensitive for benign
            sensitivity_analysis = sensitivity_analysis[:2]

        # Filter redundancy: If a feature has a counterfactual, remove its sensitivity analysis
        cf_features = {cf["feature"] for cf in counterfactuals}
        sensitivity_analysis = [
            s for s in sensitivity_analysis if s["feature"] not in cf_features
        ]

        # Get current timestamp
        timestamp = datetime.now().isoformat()

        # Detect attack pattern based on feature combinations
        pattern_description = detect_attack_pattern(
            predicted_class, input_data, z_scores, feature_list
        )

        # Log input with port mapping
        dst_port = int(input_data.get("Dst Port", 0))
        port_str = PORT_MAP.get(dst_port, str(dst_port))
        print(f"Input Features (first 5): {df.iloc[0].head().to_dict()}")
        print(f"Dst Port: {port_str}")

        # Format results
        result = []
        for i, class_name in enumerate(le.classes_):
            result.append({"class": class_name, "probability": float(probs[i])})

        # Sort by probability descending
        sorted_result = sorted(result, key=lambda x: x["probability"], reverse=True)

        print("\n--- Prediction Probabilities ---")
        for item in sorted_result:
            print(f"{item['class']}: {item['probability']:.4f}")
        print("--------------------------------\n")

        # --- SHAP Plotting ---
        shap_plot_base64 = ""
        try:
            if shap_values_for_class is not None:
                # Create a force plot or bar plot
                # We use matplotlib to save it as an image
                plt.style.use("dark_background")  # Use dark theme for contrast
                plt.figure(figsize=(10, 4))

                # Create a bar plot of the top contributing features
                # Sort by absolute SHAP value
                feature_names_display = [
                    FEATURE_DISPLAY_NAMES.get(f, f) for f in feature_list
                ]

                indices = np.argsort(np.abs(sample_shap))
                top_indices = indices[-10:]  # Top 10 features

                plt.barh(
                    range(len(top_indices)),
                    sample_shap[top_indices],
                    color=[
                        "red" if x > 0 else "blue" for x in sample_shap[top_indices]
                    ],
                )
                plt.yticks(
                    range(len(top_indices)),
                    [feature_names_display[i] for i in top_indices],
                )
                plt.xlabel(f"SHAP Value (Impact on {predicted_class})")
                plt.title(f"Feature Importance for {predicted_class} Prediction")
                plt.tight_layout()

                # Save to buffer
                buf = io.BytesIO()
                plt.savefig(buf, format="png", bbox_inches="tight", transparent=True)
                buf.seek(0)
                shap_plot_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")
                plt.close()
        except Exception as e:
            print(f"Error generating SHAP plot: {e}")
            shap_plot_base64 = ""

        print(
            f"DEBUG: Generated {len(counterfactuals)} counterfactuals: {counterfactuals}"
        )

        # Generate local rule from SHAP values (always - surrogate model removed)
        local_rule = generate_shap_based_rule(
            sample_shap, feature_list, features[0], z_scores, predicted_class, max_prob
        )

        return jsonify(
            {
                "prediction": predicted_class,
                "confidence_level": confidence_level,
                "timestamp": timestamp,
                "probabilities": sorted_result,
                "insights": insights,
                "pattern_description": pattern_description,
                "sensitivity_analysis": sensitivity_analysis,
                "counterfactuals": counterfactuals,
                "shap_plot": shap_plot_base64,
                "shap_contributions": shap_contributions,
                "local_rule": local_rule,
            }
        )

    except Exception as e:
        import traceback

        traceback.print_exc()
        print(f"Error during prediction: {e}")
        return jsonify({"error": str(e)}), 500


# /global_rules endpoint removed - we now use SHAP-based rules exclusively


@app.route("/analyze_feature", methods=["POST"])
def analyze_feature():
    """
    Generate Partial Dependence Plot (PDP) data for a specific feature.

    Expects JSON:
    - feature_name: Name of the feature to analyze
    - current_features: Dictionary of all current feature values

    Returns JSON:
    - feature_name: Name of analyzed feature
    - x_values: List of feature values tested
    - y_values: List of probabilities for the predicted class
    - current_value: The current value of the feature
    """
    if not model:
        return jsonify({"error": "Model not loaded"}), 500

    try:
        data = request.json
        target_feature = data.get("feature_name")
        current_features_dict = data.get("current_features")

        if not target_feature or not current_features_dict:
            return jsonify({"error": "Missing feature_name or current_features"}), 400

        if target_feature not in feature_list:
            return jsonify({"error": f"Unknown feature: {target_feature}"}), 400

        # 1. Prepare Base Input
        base_feature_list = [
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

        # Ensure we have all base features
        input_data = {
            f: float(current_features_dict.get(f, 0)) for f in base_feature_list
        }

        # Determine range for the target feature
        # We need reasonable min/max values.
        # If it's a flag, 0-1. If it's a port, 0-65535.
        # For continuous vars, we can use 0 to 2x current value, or a fixed large range.

        min_val = 0
        max_val = 0
        steps = 20

        if target_feature == "Dst Port":
            # Use linspace but ensure we hit common ports by adding them and sorting
            # This ensures the PDP captures the specific behavior of common services
            common = [21, 22, 23, 53, 80, 443, 3389, 8080]
            linear = np.linspace(0, 65535, steps).astype(int)
            x_values = np.unique(np.concatenate((linear, common)))
            x_values.sort()
            x_values = x_values.tolist()  # Convert to list for JSON serialization

        elif "Flag" in target_feature:
            x_values = [0, 1]
        elif target_feature == "Protocol":
            x_values = [6, 17, 1]  # TCP, UDP, ICMP
        elif target_feature == "Hour":
            x_values = np.linspace(0, 23, 24).astype(int).tolist()
        elif target_feature == "Init Fwd Win Bytes":
            x_values = np.linspace(0, 65535, steps).astype(int).tolist()
        elif "Packet" in target_feature or "Duration" in target_feature:
            # These are also integers (counts, duration in ms/us)
            current_val = input_data.get(target_feature, 0)
            if current_val == 0:
                max_val = 1000
            else:
                max_val = current_val * 3
            if max_val < 10:
                max_val = 100
            x_values = np.linspace(min_val, max_val, steps).astype(int).tolist()
        else:
            # Continuous features (if any remain)
            current_val = input_data.get(target_feature, 0)
            # If current is 0, go up to a reasonable default max
            if current_val == 0:
                max_val = 1000  # Default arbitrary max
            else:
                max_val = current_val * 3  # Go up to 3x current

            # Ensure we cover a good range if the value is small
            if max_val < 10:
                max_val = 100

            x_values = np.linspace(min_val, max_val, steps).tolist()

        # 2. Generate Predictions
        y_values = []

        # We need to know which class we are tracking probability for.
        # Usually the class predicted by the current_features.
        # Let's get the baseline prediction first.

        # ... (Reuse prediction logic to get baseline class) ...
        # Actually, let's just use the class predicted at the current value
        # Or we can return probabilities for ALL classes? No, too much data.
        # Let's return prob for the "Attack" class if it's an attack, or "Benign" if it's benign.
        # Better: Return prob for the class that is currently predicted.

        # Get baseline prediction
        df_base = pd.DataFrame([input_data])
        df_base = engineer_features_for_prediction(df_base)
        df_base = df_base[feature_list]
        features_scaled_base = scaler.transform(df_base)
        pred_base = model.predict(features_scaled_base)[0]
        predicted_class_base = le.inverse_transform([pred_base])[0]
        predicted_class_idx = pred_base

        for val in x_values:
            # Modify input data
            temp_input = input_data.copy()
            temp_input[target_feature] = val

            # Create DataFrame
            df = pd.DataFrame([temp_input])

            # Engineer features (CRITICAL: Derived features must update based on new val)
            df = engineer_features_for_prediction(df)

            # Select and Scale
            df = df[feature_list]
            features_scaled = scaler.transform(df)

            # Predict Prob
            probs = model.predict_proba(features_scaled)[0]

            # Get probability of the BASE predicted class
            # This shows "How stable is this prediction?"
            # OR we could track "Probability of Attack" (sum of all non-benign)

            # Let's track the probability of the class that was originally predicted
            prob = probs[predicted_class_idx]
            y_values.append(float(prob))

        return jsonify(
            {
                "feature_name": target_feature,
                "target_class": predicted_class_base,
                "x_values": list(x_values),
                "y_values": y_values,
                "current_value": float(input_data.get(target_feature, 0)),
            }
        )

    except Exception as e:
        print(f"Error in analysis: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
