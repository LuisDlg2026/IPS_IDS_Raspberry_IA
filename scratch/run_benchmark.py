import os
import sys
import time
import numpy as np
import pandas as pd

# Agregar path
sys.path.insert(0, os.getcwd())

from src.ml.inference import InferenceEngine

def run_benchmark_for_model(model_name, n_samples, repeats=5):
    try:
        engine = InferenceEngine(model_name=model_name)
    except Exception as e:
        print(f"Error cargando el modelo {model_name}: {e}")
        return None

    # Crear datos ficticios
    dummy_feats = {f: 0.0 for f in engine.feature_names}
    dummy_feats['tcp.dstport'] = 80.0
    dummy_feats['tcp.flags'] = 2.0
    
    # Lista para almacenar tiempos de cada repetición
    inference_times_per_sample = [] # en ms/muestra
    throughputs = [] # en muestras/s

    for r in range(repeats):
        # Medir tiempo del lote completo
        t0 = time.perf_counter()
        
        # Realizamos N inferencias individuales para simular inferencia real en tiempo real
        for _ in range(n_samples):
            engine.predict(dummy_feats)
            
        elapsed_s = time.perf_counter() - t0
        
        ms_per_sample = (elapsed_s / n_samples) * 1000.0
        samples_per_s = n_samples / elapsed_s
        
        inference_times_per_sample.append(ms_per_sample)
        throughputs.append(samples_per_s)
        
    mean_ms = np.mean(inference_times_per_sample)
    std_ms = np.std(inference_times_per_sample)
    mean_throughput = np.mean(throughputs)
    
    return {
        "mean_ms": mean_ms,
        "std_ms": std_ms,
        "samples_s": mean_throughput
    }

def main():
    print("==================================================")
    # Título en español
    print("         INICIANDO BENCHMARK DE MODELOS")
    print("==================================================")
    
    models = ["random_forest", "lightgbm", "xgboost", "decision_tree", "mlp"]
    sample_sizes = [100, 1000, 10000]
    
    results = {}
    
    for model in models:
        results[model] = {}
        for size in sample_sizes:
            print(f"\n[+] Evaluando {model} con {size} muestras (5 repeticiones)...")
            res = run_benchmark_for_model(model, size, repeats=5)
            if res:
                results[model][size] = res
                print(f"    -> Media: {res['mean_ms']:.4f} ms/muestra ± {res['std_ms']:.4f}")
                print(f"    -> Throughput: {res['samples_s']:.1f} muestras/s")
            else:
                results[model][size] = None

    # Imprimir tablas resumen en formato Markdown
    for size in sample_sizes:
        print(f"\n### Tabla de Resultados: {size} muestras")
        print("| Modelo | Inferencia media (ms/muestra) | Desv. estándar | Muestras/s |")
        print("| --- | --- | --- | --- |")
        for model in models:
            res = results[model].get(size)
            if res:
                print(f"| {model} | {res['mean_ms']:.4f} | {res['std_ms']:.4f} | {res['samples_s']:.1f} |")
            else:
                print(f"| {model} | N/A | N/A | N/A |")

if __name__ == "__main__":
    main()
