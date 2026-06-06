import sys
import os
import numpy as np
from collections import Counter

# Agregar path
sys.path.insert(0, os.getcwd())

from src.ml.inference import InferenceEngine

def main():
    engine = InferenceEngine()
    
    # El flujo real capturado del usuario:
    user_feats = {f: 0.0 for f in engine.feature_names}
    user_feats['tcp.dstport'] = 80.0
    user_feats['tcp.srcport'] = 1896.0
    user_feats['tcp.checksum'] = 3935.0
    user_feats['tcp.seq'] = 2057845967.0
    user_feats['tcp.ack'] = 1730409467.0
    user_feats['tcp.ack_raw'] = 1730409467.0
    user_feats['tcp.flags'] = 2.0
    user_feats['tcp.connection.syn'] = 50.0
    
    print("--- FOREST VOTES FOR HPING3 -K FLOW ---")
    
    # 1. Escalar usando el pipeline del engine
    # Replicamos el procesado para obtener el array que se pasa al modelo
    import pandas as pd
    vector_52 = np.zeros(len(engine._scaler_features))
    for i, name in enumerate(engine._scaler_features):
        if name in user_feats:
            vector_52[i] = user_feats[name]
            
    X_df_52 = pd.DataFrame([vector_52], columns=engine._scaler_features)
    X_scaled_52 = engine._scaler.transform(X_df_52)
    
    X_array = np.zeros((1, len(engine._selected_features)))
    for i, idx in enumerate(engine._feature_indices):
        X_array[0, i] = X_scaled_52[0, idx]
        
    # 2. Obtener votos de cada árbol individual
    rf = engine._model
    votes = []
    
    for i, tree in enumerate(rf.estimators_):
        pred_idx = tree.predict(X_array)[0]
        pred_class = engine._classes[int(pred_idx)]
        votes.append(pred_class)
        
    vote_counts = Counter(votes)
    print("\nResultados de la votación del bosque:")
    for cls, count in vote_counts.most_common():
        print(f"  - {cls}: {count} votos ({count/len(rf.estimators_):.1%})")
        
    # 3. ¿Qué pasa si aumentamos el número de paquetes syn a 5000 y ponemos valores realistas?
    # Probamos syn=5000, tcp.len=0, etc.
    user_feats['tcp.connection.syn'] = 5000.0
    
    # Re-escalar y re-votar
    vector_52 = np.zeros(len(engine._scaler_features))
    for i, name in enumerate(engine._scaler_features):
        if name in user_feats:
            vector_52[i] = user_feats[name]
    X_df_52 = pd.DataFrame([vector_52], columns=engine._scaler_features)
    X_scaled_52 = engine._scaler.transform(X_df_52)
    for i, idx in enumerate(engine._feature_indices):
        X_array[0, i] = X_scaled_52[0, idx]
        
    votes_5000 = []
    for tree in rf.estimators_:
        pred_idx = tree.predict(X_array)[0]
        pred_class = engine._classes[int(pred_idx)]
        votes_5000.append(pred_class)
        
    vote_counts_5000 = Counter(votes_5000)
    print("\nResultados con syn=5000:")
    for cls, count in vote_counts_5000.most_common():
        print(f"  - {cls}: {count} votos ({count/len(rf.estimators_):.1%})")

if __name__ == "__main__":
    main()
