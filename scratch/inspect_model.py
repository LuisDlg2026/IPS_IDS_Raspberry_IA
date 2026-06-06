import sys
import os
import numpy as np
import joblib

# Agregar path
sys.path.insert(0, os.getcwd())

from src.ml.inference import InferenceEngine

def main():
    engine = InferenceEngine()
    rf = engine._model
    
    print("--- MODEL INSPECTION ---")
    print("Class names in LabelEncoder:", engine._classes)
    
    # Obtener el índice de clases de ataque
    class_indices = {cls: i for i, cls in enumerate(engine._classes)}
    print("Class indices:", class_indices)
    
    # Inspeccionar los estimadores de la Random Forest (árboles de decisión)
    # Buscamos las reglas que clasifican a clases que no sean 'Normal'
    normal_idx = class_indices.get("Normal", 0)
    
    # Vamos a recorrer algunos árboles de decisión para extraer reglas que lleven a ataques
    n_trees_to_inspect = min(5, len(rf.estimators_))
    rules_found = []
    
    for tree_idx in range(n_trees_to_inspect):
        tree = rf.estimators_[tree_idx]
        tree_ = tree.tree_
        
        # Encontrar hojas que tengan una clase de ataque (que no sea Normal)
        # tree_.value contiene la distribución de clases en cada nodo
        # Para cada hoja (donde left_child == -1 y right_child == -1), vemos la clase predicha
        def recurse(node, path_rules):
            if tree_.children_left[node] == -1: # Es una hoja
                # Obtener la clase predicha
                class_counts = tree_.value[node][0]
                pred_class_idx = np.argmax(class_counts)
                if pred_class_idx != normal_idx:
                    pred_class_name = engine._classes[pred_class_idx]
                    rules_found.append({
                        "tree": tree_idx,
                        "class": pred_class_name,
                        "rules": list(path_rules)
                    })
                return
            
            # Nodo interno, obtener la característica e intentar seguir las ramas
            feat_idx = tree_.feature[node]
            feat_name = engine._selected_features[feat_idx]
            threshold = tree_.threshold[node]
            
            # Ir a la izquierda (menor o igual al umbral)
            path_rules.append(f"{feat_name} <= {threshold:.4f}")
            recurse(tree_.children_left[node], path_rules)
            path_rules.pop()
            
            # Ir a la derecha (mayor que el umbral)
            path_rules.append(f"{feat_name} > {threshold:.4f}")
            recurse(tree_.children_right[node], path_rules)
            path_rules.pop()
            
        recurse(0, [])
        if len(rules_found) >= 15:
            break
            
    print(f"\nSe encontraron {len(rules_found)} reglas que clasifican como ataque:")
    for i, r in enumerate(rules_found[:15]):
        print(f"\nRegla {i+1} para el ataque '{r['class']}':")
        for rule in r['rules'][:8]: # Mostrar las primeras 8 condiciones de la rama
            print(f"  - {rule}")
        if len(r['rules']) > 8:
            print("  - ...")

if __name__ == "__main__":
    main()
