# How to Improve Web Attack Detection

## Current Problem

**Web Attack Detection: 0% Recall** (all 48 test samples misclassified as Benign)

## Root Cause Analysis

### 1. **Extremely Sparse Data**
From the full dataset analysis:
- **Total Web Attack samples in entire dataset: 438**
- Breakdown:
  - Web Attack - Brute Force: 131 samples
  - Web Attack - Brute Force - Attempted: 137 samples  
  - Web Attack - XSS: 113 samples
  - Web Attack - SQL: 39 samples
  - Web Attack - SQL - Attempted: 14 samples
  - Web Attack - XSS - Attempted: 4 samples

With 15% sampling:
- Actual Web Attack samples: ~65 total
- After "Attempted" → "Benign" relabeling: **~153 samples**
- Test set (20%): **~48 samples**
- Training set after split: **~123 samples**
- After SMOTE (boosted to 10K): **10,000 synthetic samples**

**The problem**: 99.2% of Web Attack training data is synthetic!

### 2. **Documentation Insights**

According to the dataset documentation:

**Web Attack - SQL Injection:**
- Many flows labeled as SQL Injection have **no actual SQL injection payload**
- They're just navigation to the attack page
- Actual malicious flows: only those with `Total Length of Fwd Packets > 0` AND `Total Length of Bwd Packets > 0`

**Web Attack - XSS:**
- Similar issue: initial flows are page loading, not attacks
- Flows with no malicious payload are labeled "Attempted"
- Very short duration flows (~5s) have no malicious payload

**Web Attack - Brute Force:**
- Pattern: Small flow with single login → Large flow with multiple logins
- Flows with `Total Fwd Packets > 20` are actual attacks
- Flows with `≤ 20 packets` are labeled "Attempted" (can't distinguish from benign single login)

### 3. **Why Current Approach Fails**

1. **Too few real samples** (138 becomes 48 after cleaning and splitting)
2. **SMOTE creates unrealistic patterns** when 99% of data is synthetic
3. **Feature overlap with Benign** - web traffic characteristics are similar
4. **Class imbalance** - Benign has 5.7M samples, Web Attack has 153

## Solutions (Ranked by Effectiveness)

### Solution 1: **Use Original Granular Labels** (Recommended)

Instead of merging all Web Attacks into one class, keep them separate:

**Current**:
```python
'Web Attack - SQL': 'Web Attack',
'Web Attack - XSS': 'Web Attack',
'Web Attack - Brute Force': 'Web Attack'
```

**Proposed**:
```python
'Web Attack - SQL': 'Web Attack - SQL',
'Web Attack - XSS': 'Web Attack - XSS',  
'Web Attack - Brute Force': 'Web Attack - Brute Force'
```

**Why this helps**:
- Reduces feature space confusion - each type has distinct patterns
- SQL: Large packets with database queries
- XSS: JavaScript injection patterns  
- Brute Force: Repeated login attempts (already works at 100% when separate!)

**Implementation**:
```python
# In preprocess.py
label_mapping = {
    'BENIGN': 'Benign',
    # Keep Web Attacks separate
    'Web Attack - SQL': 'Web Attack - SQL',
    'Web Attack - XSS': 'Web Attack - XSS',
    'Web Attack - Brute Force': 'Brute Force',  # Already part of Brute Force class
    # ... rest
}
```

**Expected Improvement**: 60-80% F1-score for Web Attack - SQL and XSS

### Solution 2: **Don't Relabel "Attempted" as Benign for Web Attacks** (Medium Effort)

**Current**: All "Attempted" flows → "Benign"
```python
if str(label).endswith(' - Attempted'):
    return 'Benign'
```

**Proposed**: Keep Web Attack Attempted flows
```python
def clean_label(label):
    if str(label).endswith(' - Attempted'):
        # Check if it's a Web Attack
        if 'Web Attack' in str(label):
            return label.replace(' - Attempted', '')  # Merge with main class
        return 'Benign'  # Others still go to Benign
    return label_mapping.get(label, 'Benign')
```

**Why this helps**:
- Adds 155 more Web Attack samples (137 Brute Force + 14 SQL + 4 XSS)
- Total becomes: 438 instead of 268
- 63% increase in training data

**Expected Improvement**: 20-40% F1-score

### Solution 3: **Add Targeted Feature Engineering for Web Traffic** (High Effort)

**Problem**: Current features don't capture HTTP-specific patterns

**New Features to Add**:
```python
# HTTP-specific features
'Is_HTTP_Port': Dst Port in [80, 8080, 443]
'Packet_Size_Variance': Variance of packet sizes (attacks have repeating patterns)
'Bidirectional_Ratio': Bwd Packets / Fwd Packets (web attacks are asymmetric)
'Flow_Duration_Per_Packet': Flow Duration / Total Packets (attacks are faster)
```

**Implementation**:
```python
# In preprocess.py engineer_features()
X['Is_HTTP_Port'] = X['Dst Port'].isin([80, 8080, 443]).astype(np.float32)
X['Bidirectional_Ratio'] = X['Total Bwd Packets'] / (X['Total Fwd Packets'] + 1)

# If we have packet length data
X['Avg_Fwd_Packet_Length'] = X['Fwd Packets Length Total'] / (X['Total Fwd Packets'] + 1)
```

**Expected Improvement**: 10-30% F1-score

### Solution 4: **Two-Stage Classifier** (High Complexity)

**Architecture**:
```
Stage 1: Binary Classifier (Benign vs Attack) 
    ↓
Stage 2a: Attack Type Classifier (DDoS, DoS, Bot, Brute Force)
Stage 2b: Web Attack Subtype Classifier (SQL, XSS, Brute Force)
```

**Why this helps**:
- Stage 1 separates Benign (5.7M) from all attacks (300K)
- Stage 2b only trains on Web Attack data (balanced)
- Reduces class imbalance impact

**Expected Improvement**: 50-70% F1-score

### Solution 5: **Augment with External Dataset** (Medium Effort)

**Options**:
1. **CICIDS2017** - Has Web Attack data
2. **HTTP DATASET CSIC 2010** - 36K normal + 25K web attack requests
3. **Syn HTTP requests** - Web attack focused dataset

**How to combine**:
```python
# Load external Web Attack data
external_web = pd.read_csv('http_csic_2010.csv')

# Keep only matching features
common_features = set(X.columns) & set(external_web.columns)
external_web = external_web[common_features]

# Concatenate before training
X_combined = pd.concat([X, external_web], ignore_index=True)
```

**Expected Improvement**: 40-60% F1-score (if dataset is compatible)

### Solution 6: **Anomaly Detection for Web Attacks** (Alternative Approach)

Instead of classification, use anomaly detection:

```python
from sklearn.ensemble import IsolationForest

# Train only on Benign HTTP traffic
benign_http = X[(y == 0) & (X['Dst Port'].isin([80, 443, 8080]))]

# Flag anomalies as potential Web Attacks
iso_forest = IsolationForest(contamination=0.001)
iso_forest.fit(benign_http)

# Predict: -1 = anomaly (potential Web Attack), 1 = normal
```

**Expected Improvement**: 30-50% recall (but higher false positives)

## Recommended Implementation Plan

### Phase 1: Quick Wins (1-2 hours)
1. ✅ **Keep granular Web Attack labels** (Solution 1)
2. ✅ **Don't relabel "Attempted" as Benign** (Solution 2)
3. ✅ **Add HTTP-specific features** (Solution 3)

### Phase 2: Medium Effort (4-6 hours)
4. Test with external dataset (Solution 5)
5. Fine-tune SMOTE strategy specifically for Web Attacks

### Phase 3: Advanced (if needed)
6. Implement two-stage classifier (Solution 4)
7. Add anomaly detection fallback (Solution 6)

## Expected Final Results

**Conservative Estimate** (Solutions 1-3):
- Web Attack - SQL: 50-60% F1
- Web Attack - XSS: 40-50% F1  
- Web Attack - Br ute Force: Already 100% (when separate from other Brute Force)
- **Overall Web Attack**: 40-60% F1 (vs. current 0%)

**Optimistic Estimate** (Solutions 1-5):
- Web Attack - SQL: 70-80% F1
- Web Attack - XSS: 60-70% F1
- Web Attack - Brute Force: 100% F1
- **Overall Web Attack**: 70-80% F1

## Code Changes Required

### 1. Modify `preprocess.py`:
```python
# Line ~50: Update label_mapping
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
    'Web Attack - Brute Force': 'Brute Force',  # Keep with Brute Force
    'Web Attack - SQL': 'Web Attack - SQL',      # NEW: Separate
    'Web Attack - XSS': 'Web Attack - XSS',      # NEW: Separate
    'Botnet Ares': 'Bot/Infiltration',
    'Infiltration - Communication Victim Attacker': 'Bot/Infiltration',
    'Infiltration - NMAP Portscan': 'Bot/Infiltration',
    'Infiltration - Dropbox Download': 'Bot/Infiltration'
}

# Line ~74: Update clean_label function
def clean_label(label):
    # Don't relabel Web Attack Attempted as Benign
    if str(label).endswith(' - Attempted'):
        if 'Web Attack' in str(label):
            base_label = label.replace(' - Attempted', '')
            return label_mapping.get(base_label, 'Benign')
        return 'Benign'
    return label_mapping.get(label, 'Benign')
```

### 2. Add HTTP features in `engineer_features()`:
```python
# Add to engineer_features() function
X['Is_HTTP_Port'] = X['Dst Port'].isin([80, 8080, 443, 8000]).astype(np.float32)
X['Avg_Fwd_Packet_Size'] = X['Fwd Packets Length Total'] / (X['Total Fwd Packets'] + 1)
```

### 3. Update `train_model.py` SMOTE strategy:
```python
# Line ~85: Update sampling strategy
if cls_name == 'Web Attack - SQL':
    sampling_strategy[cls_idx] = max(current_count, 5000)
elif cls_name == 'Web Attack - XSS':
    sampling_strategy[cls_idx] = max(current_count, 5000)
```

## Limitations & Caveats

1. **Still sparse**: Even with improvements, Web Attack data is limited
2. **False positives**: Aggressive detection will flag some benign HTTP as attacks
3. **Dataset bias**: Only 2 days of Web Attack data in original dataset
4. **Real-world gap**: Lab data may not reflect production web attacks

## Alternative: Accept the Limitation

**Pragmatic approach**: Document that model cannot detect Web Attacks and recommend:
1. Use a **Web Application Firewall (WAF)** for Web Attack detection
2. Deploy **ModSecurity** or similar rule-based system
3. Use **signature-based detection** (e.g., OWASP Core Rule Set)
4. This ML model focuses on network-level attacks (DoS, DDoS, Brute Force, Bot)

**Advantage**: Honest about limitations, clear deployment strategy

Would you like me to implement Solutions 1-3 (the quick wins)?
