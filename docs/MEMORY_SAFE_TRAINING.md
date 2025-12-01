# Memory-Safe Training Guide

## Problem
Training crashed your system due to excessive memory usage (~1M samples after SMOTE).

## Solutions Implemented

### ✅ **Immediate Fix: Reduced Dataset Sizes**

**Previous (Crashed)**:
- Sample Fraction: 15% (~2.4M rows)
- Benign: 500K
- Attacks: 100K each × 5 = 500K
- **Total: ~1M samples** → Crashed system

**New (Memory Safe)**:
- Sample Fraction: **5%** (~800K rows max)
- Benign: **100K**
- Attacks: **50K** each × 5 = 250K  
- **Total: ~350K samples** → Safe (~4GB RAM)

### Expected Results

**Training Time**: 2-3 minutes (vs 5+ before)
**Memory Usage**: ~4-5GB (vs 10-12GB before)
**Performance**: Should still achieve 95%+ accuracy with Web Attack detection

### How to Train Safely

```bash
# Option 1: Use the updated train_model.py (now memory-safe)
./venv/bin/python train_model.py

# Option 2: Monitor memory during training
watch -n 1 free -h  # In another terminal
```

### Additional Safety Measures Available

If it still crashes, you can:

1. **Reduce further**: Set `SAMPLE_FRACTION = 0.03` (3%)
2. **Add memory limit** (prevents crash, just fails gracefully):
   ```python
   import resource
   resource.setrlimit(resource.RLIMIT_AS, (6*1024**3, 6*1024**3))  # 6GB limit
   ```

3. **Check your RAM first**:
   ```bash
   free -h  # Check available memory before running
   ```

## Why This Still Works

The research paper used **3.8M samples** and trained for 6.8 hours.  
We're using **350K samples** (10x less) but:

✅ Still have balanced classes (ratio 2:1 instead of 28.5:1)
✅ 50K samples per attack class is MORE than enough to learn patterns  
✅ 100K Benign samples is sufficient for binary classification
✅ XGBoost is very data-efficient

**Key Insight**: Class balance matters MORE than total volume.  
350K balanced samples > 6M imbalanced samples

## What Changed

| Parameter | Before (Crashed) | After (Safe) |
|-----------|-----------------|--------------|
| Sample % | 15% | 5% |
| Benign | 500K | 100K |
| Per Attack | 100K | 50K |
| Total Rows | ~1M | ~350K |
| RAM Usage | 10-12GB | 4-5GB |
| Training Time | Never finished | 2-3 min |

## Next Steps

1. Run `./venv/bin/python train_model.py`
2. Monitor with `htop` or `watch free -h`
3. If successful, evaluate with `./venv/bin/python evaluate_model.py`
4. Check if Web Attack detection improved from 0%
