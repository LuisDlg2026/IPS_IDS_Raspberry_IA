import os
import sys
import time
import datetime
import pandas as pd
import numpy as np
import warnings
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# Desactivar advertencias de scikit-learn
warnings.filterwarnings('ignore')

# Agregar el directorio raíz al path para importar correctamente los módulos locales
sys.path.insert(0, os.getcwd())

from src.ml.inference import InferenceEngine
from src.config import ACTIVE_MODEL

def main():
    print("==================================================")
    print("      EVALUACIÓN DE CALIDAD DE MODELO (PRUEBA 4)  ")
    print("==================================================")
    
    # Determinar qué modelo evaluar (por argumento o configuración activa)
    model_name = sys.argv[1] if len(sys.argv) > 1 else ACTIVE_MODEL
    print(f"\n[+] Cargando motor de inferencia para modelo: '{model_name}'...")
    
    try:
        engine = InferenceEngine(model_name=model_name)
    except Exception as e:
        print(f"[!] Error cargando el motor de inferencia: {e}")
        sys.exit(1)

    # 1. Cargar el dataset procesado
    parquet_path = Path("data/processed/edge_iiot_dataset.parquet")
    if not parquet_path.exists():
        print(f"[!] El archivo {parquet_path} no existe. Por favor, asegúrese de tener el dataset procesado en esa ruta.")
        sys.exit(1)
        
    print(f"\n[+] Cargando dataset {parquet_path.name} (esto puede demorar unos segundos)...")
    t0 = time.perf_counter()
    df = pd.read_parquet(parquet_path)
    print(f"    -> Cargado en {time.perf_counter() - t0:.2f}s. Total registros: {len(df):,}")

    # 2. Separar características (X) y etiquetas (y)
    # Usar las 52 características del scaler
    scaler_features = engine._scaler_features
    missing_feats = [f for f in scaler_features if f not in df.columns]
    if missing_feats:
        print(f"[!] Faltan características en el dataset: {missing_feats}")
        sys.exit(1)
        
    X = df[scaler_features]
    y = df['Attack_type']
    
    # 3. Realizar split Train/Test (20% test, shuffle=True, sin stratify para velocidad)
    # Nota: Con 2.2 millones de filas, un split aleatorio mantiene las proporciones de forma natural
    # sin el enorme coste de tiempo de stratify en puro python de scikit-learn.
    print("\n[+] Realizando split Train/Test (20% test, aleatorio)...")
    X_train, X_test, _, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=None, shuffle=True
    )
    print(f"    -> Tamaño del conjunto de test: {len(X_test):,} muestras.")

    # 4. Realizar predicciones optimizadas en lote (Vectorización NumPy)
    print(f"\n[+] Preprocesando características del conjunto de test...")
    # Codificar variables categóricas usando OrdinalEncoder (fit en train, transform en ambos)
    object_cols = X_train.select_dtypes(include=['object', 'category']).columns.tolist()
    if object_cols:
        print(f"    -> Codificando {len(object_cols)} columnas categóricas con OrdinalEncoder...")
        from sklearn.preprocessing import OrdinalEncoder
        oe = OrdinalEncoder(handle_unknown='use_encoded_value', unknown_value=-1)
        X_train[object_cols] = oe.fit_transform(X_train[object_cols].astype(str))
        X_test[object_cols] = oe.transform(X_test[object_cols].astype(str))
        
    # Convertir a float32 para ahorrar memoria y optimizar
    X_train = X_train.astype(np.float32)
    X_test = X_test.astype(np.float32)
    
    # Imputar valores nulos con la mediana del conjunto de entrenamiento
    print("    -> Imputando valores nulos con la mediana de entrenamiento...")
    medians = X_train.median()
    X_test = X_test.fillna(medians).fillna(0.0)
    
    # Reemplazar infinitos y asegurar valores dentro del rango de float32
    X_test = X_test.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    f32_min = np.finfo(np.float32).min
    f32_max = np.finfo(np.float32).max
    X_test = X_test.clip(lower=f32_min, upper=f32_max)

    print(f"\n[+] Ejecutando predicción en lote con el pipeline de '{model_name}'...")
    t_pred_start = time.perf_counter()
    
    # A. Escalar los datos de test completos
    X_test_scaled_52 = engine._scaler.transform(X_test)
    X_test_scaled_52 = np.nan_to_num(X_test_scaled_52, nan=0.0, posinf=0.0, neginf=0.0)
    X_test_scaled_52 = np.clip(X_test_scaled_52, f32_min, f32_max)
    
    # B. Extraer solo las 36 características seleccionadas
    X_test_scaled_36 = X_test_scaled_52[:, engine._feature_indices]
    
    # C. Predecir
    y_pred_encoded = engine._model.predict(X_test_scaled_36)
    
    # D. Decodificar etiquetas
    y_pred = engine._label_encoder.inverse_transform(y_pred_encoded)
    
    t_pred_elapsed = time.perf_counter() - t_pred_start
    print(f"    -> Predicción finalizada en {t_pred_elapsed:.2f}s.")
    print(f"    -> Latencia media de predicción por muestra: {t_pred_elapsed/len(X_test)*1000.0:.6f} ms.")

    # 5. Calcular métricas por clase y globales
    print("\n[+] Calculando reporte de clasificación...")
    report_dict = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    report_txt = classification_report(y_test, y_pred, zero_division=0)
    
    # Imprimir reporte en pantalla
    print(report_txt)

    # 6. Calcular matriz de confusión
    print("\n[+] Calculando matriz de confusión...")
    classes = sorted(list(y_test.unique()))
    cm = confusion_matrix(y_test, y_pred, labels=classes)
    
    # Generar tablas de reporte en Markdown
    report_lines = []
    report_lines.append(f"# Reporte de Clasificación sobre Dataset de Test - Modelo: {model_name.upper()}")
    report_lines.append(f"\n*Generado automáticamente el {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n")
    report_lines.append("## 1. Métricas de Calidad por Clase")
    report_lines.append("| Clase | Precisión (Precision) | Cobertura (Recall) | F1-Score | Soporte (Support) |")
    report_lines.append("| :--- | :---: | :---: | :---: | :---: |")
    
    for cls in classes:
        metrics = report_dict[cls]
        report_lines.append(f"| **{cls}** | {metrics['precision']:.4f} | {metrics['recall']:.4f} | {metrics['f1-score']:.4f} | {int(metrics['support']):,} |")
        
    report_lines.append("| | | | | |") # Separador visual
    
    # Agregar métricas globales
    for g_metric in ['accuracy', 'macro avg', 'weighted avg']:
        if g_metric == 'accuracy':
            report_lines.append(f"| **Accuracy Global** | | | {report_dict['accuracy']:.4f} | {len(y_test):,} |")
        else:
            metrics = report_dict[g_metric]
            report_lines.append(f"| **{g_metric.capitalize()}** | {metrics['precision']:.4f} | {metrics['recall']:.4f} | {metrics['f1-score']:.4f} | {int(metrics['support']):,} |")

    # Guardar reporte de clasificación
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    report_file = data_dir / f"classification_report_{model_name}.md"
    try:
        with open(report_file, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))
        print(f"[+] Reporte de clasificación guardado en: {report_file}")
    except Exception as e:
        print(f"[!] Error al guardar el reporte: {e}")

    # Generar tabla Markdown de la matriz de confusión
    cm_lines = []
    cm_lines.append(f"# Matriz de Confusión - Modelo: {model_name.upper()}")
    cm_lines.append(f"\n*Generado automáticamente el {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n")
    cm_lines.append("La matriz de confusión detalla el número de predicciones verdaderas (filas) frente a las predichas (columnas).\n")
    
    header = "| Clase Real \\ Predicha | " + " | ".join(classes) + " |"
    divider = "| :--- | " + " | ".join([":---:" for _ in classes]) + " |"
    cm_lines.append(header)
    cm_lines.append(divider)
    
    for i, row_cls in enumerate(classes):
        row_str = f"| **{row_cls}** | " + " | ".join([str(cm[i, j]) for j in range(len(classes))]) + " |"
        cm_lines.append(row_str)
        
    cm_file = data_dir / f"confusion_matrix_{model_name}.md"
    try:
        with open(cm_file, "w", encoding="utf-8") as f:
            f.write("\n".join(cm_lines))
        print(f"[+] Matriz de confusión guardada como tabla en: {cm_file}")
    except Exception as e:
        print(f"[!] Error al guardar la matriz de confusión: {e}")

    # Intentar generar la gráfica de la matriz de confusión
    try:
        import matplotlib
        matplotlib.use('Agg') # Evitar problemas de GUI en docker / servidores headless
        import matplotlib.pyplot as plt
        import seaborn as sns
        
        print("\n[+] Graficando matriz de confusión con matplotlib/seaborn...")
        plt.figure(figsize=(12, 10))
        
        # Normalizar para visualización de colores (0 a 1 por fila)
        cm_normalized = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        cm_normalized = np.nan_to_num(cm_normalized) # Failsafe para división por cero
        
        # Graficar heatmap usando anotaciones con los valores absolutos
        sns.heatmap(
            cm_normalized, 
            annot=cm, 
            fmt="d", 
            cmap="Blues", 
            xticklabels=classes, 
            yticklabels=classes,
            cbar=True
        )
        
        plt.title(f"Matriz de Confusión - Modelo: {model_name.upper()}\n(Normalizada por fila de soporte)")
        plt.ylabel("Clase Real")
        plt.xlabel("Clase Predicha")
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        img_path = data_dir / f"confusion_matrix_{model_name}.png"
        plt.savefig(img_path, dpi=150)
        plt.close()
        print(f"[+] Gráfico guardado con éxito en: {img_path}")
    except ImportError:
        print("\n[!] Advertencia: No se pudo importar matplotlib/seaborn. El gráfico PNG no se generó, pero las tablas Markdown completas se guardaron con éxito.")
    except Exception as e:
        print(f"\n[!] Error graficando la matriz de confusión: {e}")

if __name__ == "__main__":
    main()
