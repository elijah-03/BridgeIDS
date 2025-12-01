"""
IDS Control Panel - Configuration Constants
Centralizes magic numbers and configuration values for easier maintenance
"""

from typing import Dict

# ==================== ML MODEL PATHS ====================
MODEL_PATH = 'xgb_model.joblib'
SCALER_PATH = 'scaler.joblib'
LE_PATH = 'label_encoder.joblib'
FEATURE_LIST_PATH = 'feature_list.joblib'

# ==================== BASE FEATURES ====================
BASE_FEATURES = [
    'Dst Port', 'Protocol', 'Hour', 'Total Fwd Packets',
    'Fwd Packets Length Total', 'Flow Duration', 'Flow IAT Mean',
    'Fwd Packet Length Max', 'FIN Flag Count', 'SYN Flag Count',
    'RST Flag Count', 'Init Fwd Win Bytes'
]

# ==================== PORT MAPPING ====================
PORT_MAP: Dict[int, str] = {
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

# ==================== FEATURE DISPLAY NAMES ====================
FEATURE_DISPLAY_NAMES: Dict[str, str] = {
    "Dst Port": "Destination Port",
    "Protocol": "Protocol Type",
    "Hour": "Time of Day",
    "Total Fwd Packets": "Total Packets Sent",
    "Fwd Packets Length Total": "Total Bytes Sent",
    "Flow Duration": "Connection Duration",
    "Flow IAT Mean": "Avg Time Between Packets",
    "Fwd Packet Length Max": "Max Packet Size",
    "FIN Flag Count": "FIN Flags",
    "SYN Flag Count": "SYN Flags",
    "RST Flag Count": "RST Flags",
    "Init Fwd Win Bytes": "TCP Window Size",
    # Derived features
    "Avg Fwd Packet Size": "Average Packet Size",
    "Packet Rate": "Packet Rate",
    "Byte Rate": "Byte Rate",
    "Duration Seconds": "Connection Duration",
    "IAT_To_Duration_Ratio": "Inter-Arrival Time Ratio",
    "Flag_Density": "Flag Density",
    "SYN_Ratio": "SYN Flag Ratio",
    "RST_Ratio": "RST Flag Ratio",
    "Is_Common_Port": "Common Port",
    "Port_Category": "Port Category"
}

# ==================== Z-SCORE THRESHOLDS ====================
class ZScoreThresholds:
    """Thresholds for categorizing Z-scores"""
    VERY_HIGH = 2.5  # abs(z) > 2.5: Very high/low
    HIGH = 1.5       # abs(z) > 1.5: High/low
    SIGNIFICANT = 1.0  # abs(z) > 1.0: Significant enough to display
    
# ==================== CONFIDENCE THRESHOLDS ====================
class ConfidenceThresholds:
    """Thresholds for confidence level categorization"""
    HIGH = 0.75     # > 75%: High confidence
    MEDIUM = 0.50   # 50-75%: Medium confidence
    # < 50%: Low confidence

# ==================== SHAP THRESHOLDS ====================
class ShapThresholds:
    """Thresholds for SHAP contribution significance"""
    HIGH_CONTRIBUTION = 0.5   # abs(shap) > 0.5: High contribution  
    MEDIUM_CONTRIBUTION = 0.1 # abs(shap) > 0.1: Medium contribution
    MIN_DISPLAY = 0.01        # abs(shap) > 0.01: Minimum to display
    
    # Number of features to show in local rules
    TOP_FEATURES_COUNT = 5
    MAX_RULE_CONDITIONS = 4

# ==================== ANALYSIS PARAMETERS ====================
class AnalysisParams:
    """Parameters for feature analysis"""
    PDP_STEPS = 20  # Number of points for partial dependence plots
    MAX_PORT_VALUE = 65535
    MAX_HOUR = 23
    
    # Common ports to include in PDP analysis
    COMMON_PORTS = [21, 22, 23, 53, 80, 443, 3389, 8080]
    
    # Protocol values
    PROTOCOLS = {
        'TCP': 6,
        'UDP': 17,
        'ICMP': 1
    }

# ==================== ATTACK PATTERN THRESHOLDS ====================
class AttackPatternThresholds:
    """Thresholds for detecting specific attack patterns"""
    # DDoS Detection
    DDOS_HIGH_PACKET_COUNT = 10000
    DDOS_VERY_HIGH_PACKET_COUNT = 50000
    DDOS_SHORT_DURATION = 10000000  # ~10 seconds
    
    # DoS Detection
    DOS_LONG_DURATION = 100000000  # ~100 seconds
    DOS_LOW_IAT_MULTIPLIER = 100  # Duration should be > IAT * this value
    
    # Brute Force Detection
    BRUTE_FORCE_PACKET_RANGE = (5, 100)
    BRUTE_FORCE_BYTE_RANGE = (100, 100000)
    
    # Web Attack Detection
    WEB_ATTACK_MIN_PACKETS = 50
    WEB_ATTACK_PORT = 80
    
    # Bot Detection
    BOT_UNUSUAL_PORT_THRESHOLD = 1024
    
# ==================== ERROR MESSAGES ====================
class ErrorMessages:
    """Centralized error messages"""
    MODEL_NOT_LOADED = "Model not loaded"
    MISSING_FEATURES = "Missing required feature values"
    INVALID_FEATURE = "Unknown feature: {}"
    PREDICTION_FAILED = "Failed to generate prediction"
    ANALYSIS_FAILED = "Failed to analyze feature"
    SHAP_FAILED = "Failed to compute SHAP values"

# ==================== API CONFIGURATION ====================
class APIConfig:
    """API configuration"""
    DEBUG_MODE = True
    PORT = 5000
    HOST = '0.0.0.0'
    
    # CORS settings (if needed in future)
    CORS_ORIGINS = ['http://localhost:5000', 'http://127.0.0.1:5000']
