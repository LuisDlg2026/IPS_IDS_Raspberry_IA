import os
import sys
import time
import platform
import datetime
from pathlib import Path
import numpy as np
import pandas as pd
import logging
import warnings

# Configurar logs para evitar spam durante el benchmark
logging.basicConfig(level=logging.ERROR)
logging.getLogger("src.ml.inference").setLevel(logging.ERROR)
logging.getLogger("src.config").setLevel(logging.ERROR)
warnings.filterwarnings('ignore')

# Agregar el directorio raíz al path para importar correctamente los módulos locales
sys.path.insert(0, os.getcwd())

from src.ml.inference import InferenceEngine

def get_system_info():
    """Obtiene información básica del sistema para documentar el entorno de ejecución."""
    info = {
        "Fecha/Hora": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Sistema Operativo": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "Procesador/Arquitectura": platform.processor() or "Desconocido",
        "Versión de Python": platform.python_version()
    }
    if platform.system() == "Linux":
        try:
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if "Model" in line or "model name" in line:
                        info["Hardware"] = line.split(":", 1)[1].strip()
                        break
        except Exception:
            pass
    return info

def run_benchmark_for_engine(engine, dummy_feats, n_samples, repeats=5):
    """Ejecuta el benchmark para un motor de inferencia ya cargado y un tamaño de muestra específicos."""
    inference_times_per_sample = []
    throughputs = []

    # Calentamiento (Warm-up)
    for _ in range(5):
        engine.predict(dummy_feats)

    for r in range(repeats):
        t0 = time.perf_counter()
        
        # Inferencia individual por muestra para simular detección flujo a flujo
        for i in range(n_samples):
            engine.predict(dummy_feats)
            
            # Mostrar progreso periódico para que el usuario sepa que sigue corriendo
            if (i + 1) % max(1, n_samples // 10) == 0 or i == n_samples - 1:
                pct = int(((r * n_samples + i + 1) / (repeats * n_samples)) * 100)
                sys.stdout.write(f"\r     -> Progreso: {pct}% | Repetición {r+1}/{repeats} | Muestras: {i+1}/{n_samples}")
                sys.stdout.flush()
            
        elapsed_s = time.perf_counter() - t0
        
        ms_per_sample = (elapsed_s / n_samples) * 1000.0
        samples_per_s = n_samples / elapsed_s
        
        inference_times_per_sample.append(ms_per_sample)
        throughputs.append(samples_per_s)
        
    print()  # Salto de línea después del bucle de progreso
    
    mean_ms = np.mean(inference_times_per_sample)
    std_ms = np.std(inference_times_per_sample) if len(inference_times_per_sample) > 1 else 0.0
    mean_throughput = np.mean(throughputs)
    
    return {
        "mean_ms": mean_ms,
        "std_ms": std_ms,
        "samples_s": mean_throughput
    }

def main():
    print("==================================================")
    print("      EJECUTANDO PERFORMANCE BENCHMARK (RNF-01)   ")
    print("==================================================")
    
    sys_info = get_system_info()
    print("\n[+] Información del Sistema:")
    for k, v in sys_info.items():
        print(f"    - {k}: {v}")
        
    models = ["random_forest", "lightgbm", "xgboost", "decision_tree", "mlp"]
    sample_sizes = [100, 1000, 10000]
    
    results = {}
    
    for model in models:
        results[model] = {}
        print(f"\n[+] Cargando modelo '{model}'...")
        t_load = time.perf_counter()
        try:
            # Desactivar warnings durante la carga
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                engine = InferenceEngine(model_name=model)
            print(f"    -> Modelo cargado en {time.perf_counter() - t_load:.2f}s")
        except Exception as e:
            print(f"    [!] Error al cargar el modelo '{model}': {e}")
            continue
        
        # Crear características de prueba
        dummy_feats = {f: 0.0 for f in engine.feature_names}
        dummy_feats['tcp.dstport'] = 80.0
        dummy_feats['tcp.srcport'] = 45123.0
        dummy_feats['tcp.flags'] = 2.0
        dummy_feats['tcp.seq'] = 123456789.0
        dummy_feats['tcp.ack'] = 987654321.0
        
        # Muestreo rápido de 10 ejecuciones para estimar latencia por muestra
        t_est = time.perf_counter()
        for _ in range(10):
            engine.predict(dummy_feats)
        lat_est_ms = ((time.perf_counter() - t_est) / 10.0) * 1000.0

        for size in sample_sizes:
            # Estimar el tiempo total para 5 repeticiones de este tamaño
            est_time_s = (lat_est_ms * size * 5) / 1000.0
            
            actual_repeats = 5
            skip_size = False
            
            # Limitar repeticiones o saltar tamaño si va a demorar demasiado en hardware limitado
            if est_time_s > 60.0:  # Si toma más de 1 minuto
                actual_repeats = 2
                est_time_s = (lat_est_ms * size * actual_repeats) / 1000.0
                if est_time_s > 60.0:
                    actual_repeats = 1
                    est_time_s = (lat_est_ms * size * actual_repeats) / 1000.0
                    if est_time_s > 90.0:  # Si incluso 1 repetición tarda más de 90s, lo omitimos y proyectamos
                        skip_size = True
            
            if skip_size:
                print(f"    [!] Omitiendo {size} muestras para '{model}' (Tiempo estimado excesivo: {est_time_s:.1f}s). Proyectando datos.")
                # Proyección basada en el tamaño de muestra anterior
                prev_size = 1000 if size == 10000 else 100
                prev_res = results[model].get(prev_size)
                if prev_res:
                    results[model][size] = {
                        "mean_ms": prev_res["mean_ms"],
                        "std_ms": 0.0,
                        "samples_s": prev_res["samples_s"],
                        "projected": True
                    }
                else:
                    results[model][size] = None
                continue

            print(f"    [+] Evaluando con {size} muestras ({actual_repeats} repeticiones)...")
            res = run_benchmark_for_engine(engine, dummy_feats, size, repeats=actual_repeats)
            if res:
                res["projected"] = False
                results[model][size] = res
                print(f"        -> Media: {res['mean_ms']:.4f} ms/muestra ± {res['std_ms']:.4f}")
                print(f"        -> Rendimiento: {res['samples_s']:.1f} muestras/s")
            else:
                results[model][size] = None

    # Generar Reporte Markdown
    report_lines = []
    report_lines.append("# Reporte de Rendimiento y Latencia de Modelos ML")
    report_lines.append(f"\n*Generado automáticamente el {sys_info['Fecha/Hora']}*\n")
    
    report_lines.append("## 1. Información del Entorno de Ejecución")
    for k, v in sys_info.items():
        report_lines.append(f"- **{k}**: {v}")
    
    report_lines.append("\n## 2. Resultados de Inferencia")
    report_lines.append("Los modelos se evaluaron realizando inferencia individual iterativa para emular la detección en tiempo real flujo por flujo.")
    report_lines.append("\n> **Nota**: En hardware de recursos limitados (como Raspberry Pi), algunas combinaciones pesadas con muestras grandes se omiten dinámicamente y se proyectan para evitar demoras extremas en el test.")
    
    for size in sample_sizes:
        report_lines.append(f"\n### Evaluación con {size:,} Muestras")
        report_lines.append("| Modelo | Inferencia Media (ms/muestra) | Desviación Estándar (ms) | Rendimiento (muestras/s) | Nota |")
        report_lines.append("| :--- | :---: | :---: | :---: | :---: |")
        for model in models:
            res = results[model].get(size)
            if res:
                nota = "Proyectado" if res.get("projected") else "Medido"
                report_lines.append(f"| **{model.upper()}** | {res['mean_ms']:.4f} ms | {res['std_ms']:.4f} ms | {res['samples_s']:.2f} | {nota} |")
            else:
                report_lines.append(f"| **{model.upper()}** | N/A | N/A | N/A | Error de carga |")

    report_lines.append("\n## 3. Evaluación de Requisitos No Funcionales (RNF-01)")
    report_lines.append("El criterio de éxito para **RNF-01** exige una latencia menor a 5 segundos (5000 ms) por flujo.")
    report_lines.append("\n| Modelo | Latencia Máxima Registrada / Proyectada (ms) | RNF-01 Cumplido |")
    report_lines.append("| :--- | :---: | :---: |")
    
    for model in models:
        max_ms = -1.0
        for size in sample_sizes:
            res = results[model].get(size)
            if res and res['mean_ms'] > max_ms:
                max_ms = res['mean_ms']
        
        if max_ms > 0:
            status = "✅ SÍ" if max_ms < 5000.0 else "❌ NO"
            report_lines.append(f"| **{model.upper()}** | {max_ms:.4f} ms | {status} |")
        else:
            report_lines.append(f"| **{model.upper()}** | N/A | N/A |")

    # Guardar en archivo local
    output_dir = Path("data")
    output_dir.mkdir(exist_ok=True)
    report_path = output_dir / "benchmark_results.md"
    
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))
        print(f"\n[+] ¡Reporte escrito con éxito en {report_path}!")
    except Exception as e:
        print(f"\n[!] Error al escribir el reporte: {e}")

    # Mostrar tablas también por consola
    print("\n\n==================================================")
    print("               RESUMEN DE RESULTADOS")
    print("==================================================")
    for size in sample_sizes:
        print(f"\n### Resultados para {size} muestras:")
        print(f"{'Modelo':<20} | {'Inferencia media':<22} | {'Desv. Estándar':<15} | {'Muestras/s':<12} | {'Nota':<10}")
        print("-" * 89)
        for model in models:
            res = results[model].get(size)
            if res:
                nota = "Proyectado" if res.get("projected") else "Medido"
                print(f"{model:<20} | {res['mean_ms']:>17.4f} ms | {res['std_ms']:>13.4f} | {res['samples_s']:>10.1f} | {nota:<10}")
            else:
                print(f"{model:<20} | {'N/A':>20} | {'N/A':>13} | {'N/A':>10} | {'Error':<10}")

if __name__ == "__main__":
    main()
