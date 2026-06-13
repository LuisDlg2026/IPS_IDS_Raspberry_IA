import sys
import os
from collections import Counter
import numpy as np

# Agregar path
sys.path.insert(0, os.getcwd())

from src.ml.inference import InferenceEngine

def main():
    engine = InferenceEngine()
    rf = engine._model
    
    print("--- ROOT SPLIT ANALYSIS ---")
    splits = []
    for i, tree in enumerate(rf.estimators_):
        tree_ = tree.tree_
        root_feat_idx = tree_.feature[0]
        root_feat_name = engine._selected_features[root_feat_idx]
        threshold = tree_.threshold[0]
        splits.append((root_feat_name, threshold))
        
    counts = Counter([s[0] for s in splits])
    print("Root split features counts across all trees:")
    for feat, count in counts.most_common():
        print(f"  - {feat}: {count} trees")
        
    # Qué clases se predicen si mqtt.topic <= threshold
    # Muestra los primeros 5 árboles
    print("\nDetailed splits for first 5 trees:")
    for i in range(5):
        tree_ = rf.estimators_[i].tree_
        feat = engine._selected_features[tree_.feature[0]]
        threshold = tree_.threshold[0]
        print(f"Tree {i}: root split on {feat} <= {threshold:.4f}")

if __name__ == "__main__":
    main()
