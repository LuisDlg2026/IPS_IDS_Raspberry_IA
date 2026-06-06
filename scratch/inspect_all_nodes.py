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
    
    print("--- ALL NODE SPLIT ANALYSIS ---")
    
    feature_splits = []
    
    for i, tree in enumerate(rf.estimators_):
        tree_ = tree.tree_
        # Recorrer todos los nodos que no sean hojas (feature != -2)
        for node in range(tree_.node_count):
            feat_idx = tree_.feature[node]
            if feat_idx != -2: # -2 en scikit-learn significa hoja (no-split)
                feat_name = engine._selected_features[feat_idx]
                feature_splits.append(feat_name)
                
    counts = Counter(feature_splits)
    print("Features split counts across all trees and all nodes:")
    for feat, count in counts.most_common():
        print(f"  - {feat}: {count} splits")

if __name__ == "__main__":
    main()
