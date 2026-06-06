import sys
import os
import numpy as np
import pandas as pd

# Agregar path
sys.path.insert(0, os.getcwd())

from src.ml.inference import InferenceEngine

def main():
    engine = InferenceEngine()
    
    print("--- DEBUG ML SCALING ---")
    print("Selected Features:", engine._selected_features)
    print("Is tcp.connection.syn in scaler features?", "tcp.connection.syn" in engine._scaler_features)
    
    idx_syn_scaler = engine._scaler_features.index("tcp.connection.syn")
    idx_syn_selected = engine._selected_features.index("tcp.connection.syn")
    print(f"Index in scaler: {idx_syn_scaler}, Index in selected: {idx_syn_selected}")
    
    # Test syn = 0
    feats_0 = {f: 0.0 for f in engine._selected_features}
    feats_0['tcp.dstport'] = 80.0
    feats_0['tcp.flags'] = 2.0
    
    # Test syn = 1000
    feats_1000 = feats_0.copy()
    feats_1000['tcp.connection.syn'] = 1000.0
    
    for label, feats in [("syn=0", feats_0), ("syn=1000", feats_1000)]:
        print(f"\nEvaluating: {label}")
        # Build 52 vector
        vector_52 = np.zeros(len(engine._scaler_features))
        for i, name in enumerate(engine._scaler_features):
            if name in feats:
                vector_52[i] = feats[name]
        
        print("Vector 52 syn value:", vector_52[idx_syn_scaler])
        
        # Scale
        X_df_52 = pd.DataFrame([vector_52], columns=engine._scaler_features)
        X_scaled_52 = engine._scaler.transform(X_df_52)
        print("Scaled 52 syn value:", X_scaled_52[0, idx_syn_scaler])
        
        # Build 36 vector
        X_array = np.zeros((1, len(engine._selected_features)))
        for i, idx in enumerate(engine._feature_indices):
            X_array[0, i] = X_scaled_52[0, idx]
        print("Selected 36 syn value:", X_array[0, idx_syn_selected])
        
        # Predict directly with model
        y_pred = engine._model.predict(X_array)[0]
        pred_label = engine._label_encoder.inverse_transform([y_pred])[0]
        
        # Probabilities
        if hasattr(engine._model, 'predict_proba'):
            proba = engine._model.predict_proba(X_array)[0]
            max_prob = np.max(proba)
            probs_dict = {cls: float(p) for cls, p in zip(engine._classes, proba)}
            print(f"Model predict: {pred_label} (prob={max_prob:.4f})")
            print(f"Top 3 probabilities:")
            sorted_probs = sorted(probs_dict.items(), key=lambda x: x[1], reverse=True)
            for cls, p in sorted_probs[:3]:
                print(f"  - {cls}: {p:.4f}")
        else:
            print(f"Model predict: {pred_label}")

if __name__ == "__main__":
    main()
