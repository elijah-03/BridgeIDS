import os
import joblib
import pandas as pd
import numpy as np
from flask import Flask, request, jsonify, render_template
from scipy.stats import norm
from datetime import datetime

"""
IDS Control Panel Backend
-------------------------
This Flask application serves as the backend for the Intrusion Detection System (IDS) Control Panel.
It handles:
1.  Loading the trained XGBoost model and preprocessing artifacts.
2.  Serving the main web interface.
3.  Processing prediction requests from the frontend.
4.  Generating interpretability insights (Z-scores, pattern detection, sensitivity analysis).
"""

app = Flask(__name__)

# Load artifacts
MODEL_PATH = 'xgb_model.joblib'
SCALER_PATH = 'scaler.joblib'
LE_PATH = 'label_encoder.joblib'
FEATURE_LIST_PATH = 'feature_list.joblib'

print("Loading model and artifacts...")
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    le = joblib.load(LE_PATH)
    feature_list = joblib.load(FEATURE_LIST_PATH)
    print("Artifacts loaded successfully.")
except Exception as e:
    print(f"Error loading artifacts: {e}")
    print("Ensure you have trained the model first.")
    model = None
    scaler = None
    le = None
    feature_list = []

@app.route('/')
def index():
    """
    Render the main dashboard.
    Passes the list of features to the template for dynamic form generation.
    """
    return render_template('index.html', features=feature_list)

# Port mapping for display/logging
PORT_MAP = {
    80: "HTTP (Web)",
    443: "HTTPS (Secure Web)",
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Email)",
    53: "DNS",
    3306: "MySQL",
    8080: "HTTP Alt"
}

# Feature name mapping for displaying full non-abbreviated names
FEATURE_DISPLAY_NAMES = {
    "Dst Port": "Destination Port",
    "Protocol": "Protocol",
    "Hour": "Hour of Day",
    "Total Fwd Packets": "Total Forward Packets",
    "Fwd Packets Length Total": "Forward Packets Length Total",
    "Flow Duration": "Flow Duration",
    "Flow IAT Mean": "Flow Inter-Arrival Time Mean",
    "Fwd Packet Length Max": "Maximum Forward Packet Length",
    "FIN Flag Count": "FIN Flag Count",
    "SYN Flag Count": "SYN Flag Count",
    "RST Flag Count": "RST Flag Count",
    "Init Fwd Win Bytes": "Initial Forward Window Bytes"
}

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
    
    
    dst_port = int(input_data.get('Dst Port', 0))
    protocol = int(input_data.get('Protocol', 6))
    
    patterns = {
        "DoS": [
            # Slowloris-style: long duration, low packet rate
            (lambda: is_high("Flow Duration") and is_high("Flow IAT Mean") and dst_port in [80, 443],
             "Slowloris-style attack - sustained slow connections exhausting server resources"),
            # Volumetric flood: massive packets, short duration
            (lambda: is_high("Total Fwd Packets") and is_low("Flow Duration"),
             "Volumetric flood - massive packet burst to overwhelm target"),
            # Protocol abuse
            (lambda: is_high("Total Fwd Packets") and protocol != 6,
             "Protocol abuse attack - non-TCP flood (likely UDP/ICMP)"),
            # Generic high volume
            (lambda: is_high("Flow Duration") and is_high("Total Fwd Packets"),
             "Resource exhaustion attack - prolonged high-volume traffic"),
            (lambda: is_high("Total Fwd Packets"),
             "High packet volume DoS pattern"),
        ],
        
        "Brute Force": [
            # Targeted service attacks
            (lambda: is_high("SYN Flag Count") and dst_port in [21, 22, 23],
             f"Credential brute force on {PORT_MAP.get(dst_port, 'service')} - rapid connection attempts"),
            (lambda: is_high("FIN Flag Count") and is_low("Flow Duration"),
             "Rapid-fire authentication attempts - failed connection pattern"),
            (lambda: dst_port == 23,
             "Telnet brute force - extremely high-risk legacy protocol attack"),
            (lambda: dst_port in [21, 22, 25, 3389],
             f"Targeted attack on {PORT_MAP.get(dst_port, 'authentication')} service"),
        ],
        
        "Web Attack": [
            # SQL Injection: large payloads + web ports
            (lambda: is_high("Fwd Packet Length Max") and is_high("Fwd Packets Length Total") and dst_port in [80, 443],
             "SQL Injection pattern - complex queries with large payloads targeting database"),
            # XSS: moderate payloads + many packets
            (lambda: is_high("Total Fwd Packets") and dst_port in [80, 443] and not is_high("Fwd Packet Length Max"),
             "Cross-Site Scripting (XSS) pattern - multiple requests with script injection attempts"),
            # Web brute force / fuzzing
            (lambda: is_high("Total Fwd Packets") and is_low("Flow Duration") and dst_port in [80, 443],
             "Web application fuzzing - rapid enumeration or path traversal attack"),
            # Generic web exploit
            (lambda: is_high("Fwd Packets Length Total") and dst_port in [80, 443],
             "Web application exploit - abnormal HTTP request patterns"),
            (lambda: dst_port in [80, 443],
             "HTTP/HTTPS service targeted with suspicious traffic"),
        ],
        
        "DDoS": [
            # SYN flood
            (lambda: is_high("SYN Flag Count") and is_high("Total Fwd Packets"),
             "Distributed SYN flood - coordinated connection saturation from multiple sources"),
            # Burst flood
            (lambda: is_high("Total Fwd Packets") and is_low("Flow Duration"),
             "Amplification DDoS - massive burst traffic from distributed botnet"),
            # Sustained distributed attack
            (lambda: is_high("Total Fwd Packets"),
             "Distributed volumetric attack - coordinated high-volume assault"),
        ],
        
        "Bot/Infiltration": [
            # C&C communication
            (lambda: dst_port > 8000 and is_high("Total Fwd Packets"),
             "Command & Control (C2) communication - botnet traffic to high port"),
            # Backdoor/persistence
            (lambda: is_high("Flow Duration") and dst_port not in [80, 443, 21, 22, 23, 25, 53],
             "Backdoor communication - persistent connection to unusual port"),
            # Data exfiltration
            (lambda: is_high("Fwd Packets Length Total") and dst_port not in [80, 443],
             "Potential data exfiltration - large data transfer to non-standard port"),
            (lambda: True,
             "Automated malicious behavior detected"),
        ],
        
        "Benign": [
            # Legitimate high-load (e.g., file downloads, streaming)
            (lambda: is_high("Flow Duration") and dst_port in [80, 443] and not is_high("SYN Flag Count"),
             "Legitimate high-bandwidth session - likely file download or media streaming"),
            # Interactive session (SSH, RDP)
            (lambda: is_high("Flow Duration") and dst_port in [22, 3389] and is_low("Total Fwd Packets"),
             "Interactive remote session - normal SSH/RDP administrative traffic"),
            # Normal DNS
            (lambda: dst_port == 53,
             "Normal DNS query traffic"),
            # Clean traffic
            (lambda: not any([is_high(f) for f in ["Flow Duration", "Total Fwd Packets", "Flow IAT Mean", "SYN Flag Count"]]),
             "Clean traffic - all metrics within normal parameters"),
            (lambda: True,
             "Traffic within expected baseline"),
        ]
    }
    
    # Get patterns for predicted class
    class_patterns = patterns.get(predicted_class, [])
    
    # Find first matching pattern
    for condition, description in class_patterns:
        try:
            if condition():
                return description
        except:
            continue
    
    # Default fallback
    return f"Detected as {predicted_class} based on traffic characteristics"

@app.route('/predict', methods=['POST'])
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
    """
    if not model:
        return jsonify({'error': 'Model not loaded'}), 500
    try:
        # The frontend sends the features dictionary directly
        data = request.json
        
        # Create DataFrame from input data
        # Ensure all features are present, fill missing with 0
        input_data = {feature: float(data.get(feature, 0)) for feature in feature_list}
        df = pd.DataFrame([input_data])
        
        # Create feature array in correct order
        features = np.array([input_data.get(feature, 0) for feature in feature_list]).reshape(1, -1)
        
        print("\n--- Received Features ---")
        for i, feature in enumerate(feature_list):
            print(f"{feature}: {features[0][i]}")
        
        # Scale features
        features_scaled = scaler.transform(features)
        
        # Predict
        prediction = model.predict(features_scaled)
        probs = model.predict_proba(features_scaled)[0]
        
        predicted_class = le.inverse_transform(prediction)[0]
        
        # Calculate Z-scores for insights
        # z = (x - mean) / scale
        z_scores = (features[0] - scaler.mean_) / scaler.scale_
        
        # Find top 3 features with highest absolute Z-scores
        top_indices = np.argsort(np.abs(z_scores))[::-1][:3]
        
        insights = []
        for idx in top_indices:
            feature_name = feature_list[idx]
            z_val = z_scores[idx]
            direction = "High" if z_val > 0 else "Low"
            
            # Calculate percentile (probability that a random variable is less than this value)
            percentile = norm.cdf(z_val) * 100
            
            # Use full display name
            display_name = FEATURE_DISPLAY_NAMES.get(feature_name, feature_name)
            
            insights.append({
                "feature": feature_name,
                "z_score": float(z_val),
                "percentile": float(percentile),
                "direction": direction,
                "description": f"{direction} {display_name} ({z_val:+.1f}σ, {percentile:.0f}th percentile)"
            })

        # Calculate confidence level based on top probability
        max_prob = float(np.max(probs))
        if max_prob > 0.95:
            confidence_level = "High"
        elif max_prob > 0.75:
            confidence_level = "Medium"
        else:
            confidence_level = "Low"

        # Enhanced Feature Sensitivity Analysis
        sensitivity_analysis = []
        
        # For attack predictions: find what would make it benign
        if predicted_class != "Benign":
            for idx in top_indices[:2]:  # Top 2 significant features
                feature_name = feature_list[idx]
                display_name = FEATURE_DISPLAY_NAMES.get(feature_name, feature_name)
                current_value = features[0][idx]
                
                if z_scores[idx] > 1.5:  # Only if significantly high
                    # Boundary detection: find tipping point
                    modification_found = False
                    for reduction_pct in [10, 20, 30, 40, 50, 60, 70, 80]:
                        modified_features = features.copy()
                        modified_features[0][idx] = current_value * (1 - reduction_pct/100)
                        modified_scaled = scaler.transform(modified_features)
                        new_pred_probs = model.predict_proba(modified_scaled)[0]
                        new_pred_class = le.inverse_transform([np.argmax(new_pred_probs)])[0]
                        new_max_prob = float(np.max(new_pred_probs))
                        
                        # Check if prediction changed
                        if new_pred_class != predicted_class:
                            sensitivity_analysis.append({
                                "feature": feature_name,
                                "type": "boundary",
                                "current_value": float(current_value),
                                "threshold_value": float(current_value * (1 - reduction_pct/100)),
                                "reduction_percent": reduction_pct,
                                "would_change_to": new_pred_class,
                                "description": f"Reducing {display_name} by {reduction_pct}% would change prediction to {new_pred_class}"
                            })
                            modification_found = True
                            break
                        # Check for significant confidence drop (even if class doesn't change)
                        elif max_prob - new_max_prob > 0.15 and not modification_found:
                            sensitivity_analysis.append({
                                "feature": feature_name,
                                "type": "confidence_impact",
                                "current_value": float(current_value),
                                "test_value": float(current_value * (1 - reduction_pct/100)),
                                "reduction_percent": reduction_pct,
                                "confidence_drop": f"{max_prob:.0%} → {new_max_prob:.0%}",
                                "description": f"Reducing {display_name} by {reduction_pct}% significantly lowers confidence from {max_prob:.0%} to {new_max_prob:.0%}"
                            })
                            modification_found = True
                            break
        
        # For benign predictions: find what would trigger an alert
        else:
            suspicious_features = ["SYN Flag Count", "Total Fwd Packets", "Flow Duration", "RST Flag Count"]
            for feature_name in suspicious_features:
                try:
                    idx = feature_list.index(feature_name)
                    display_name = FEATURE_DISPLAY_NAMES.get(feature_name, feature_name)
                    current_value = features[0][idx]
                    
                    # Test increasing suspicious features
                    for increase_factor in [2, 3, 5, 10, 20]:
                        modified_features = features.copy()
                        modified_features[0][idx] = current_value * increase_factor
                        modified_scaled = scaler.transform(modified_features)
                        new_pred_probs = model.predict_proba(modified_scaled)[0]
                        new_pred_class = le.inverse_transform([np.argmax(new_pred_probs)])[0]
                        
                        if new_pred_class != "Benign":
                            sensitivity_analysis.append({
                                "feature": feature_name,
                                "type": "benign_to_malicious",
                                "current_value": float(current_value),
                                "trigger_value": float(current_value * increase_factor),
                                "increase_factor": increase_factor,
                                "would_trigger": new_pred_class,
                                "description": f"Increasing {display_name} by {increase_factor}x would trigger {new_pred_class} detection"
                            })
                            break
                except (ValueError, IndexError):
                    continue
            
            # Limit to top 2 most sensitive for benign
            sensitivity_analysis = sensitivity_analysis[:2]

        # Get current timestamp
        timestamp = datetime.now().isoformat()

        # Detect attack pattern based on feature combinations
        pattern_description = detect_attack_pattern(
            predicted_class, 
            input_data, 
            z_scores, 
            feature_list
        )

        # Log input with port mapping
        dst_port = int(input_data.get('Dst Port', 0))
        port_str = PORT_MAP.get(dst_port, str(dst_port))
        print(f"Input Features (first 5): {df.iloc[0].head().to_dict()}")
        print(f"Dst Port: {port_str}")
        
        # Format results
        result = []
        for i, class_name in enumerate(le.classes_):
            result.append({
                "class": class_name,
                "probability": float(probs[i])
            })
        
        # Sort by probability descending
        sorted_result = sorted(result, key=lambda x: x['probability'], reverse=True)
        
        print("\n--- Prediction Probabilities ---")
        for item in sorted_result:
            print(f"{item['class']}: {item['probability']:.4f}")
        print("--------------------------------\n")
        
        return jsonify({
            "prediction": predicted_class,
            "confidence_level": confidence_level,
            "timestamp": timestamp,
            "probabilities": sorted_result,
            "insights": insights,
            "pattern_description": pattern_description,
            "sensitivity_analysis": sensitivity_analysis
        })

    except Exception as e:
        print(f"Error during prediction: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
