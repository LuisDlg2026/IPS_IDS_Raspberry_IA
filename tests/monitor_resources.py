import os
import sys
import time
import platform
import datetime
import numpy as np
import psutil

# Agregar el directorio raíz al path para importar correctamente
sys.path.insert(0, os.getcwd())

def get_system_info():
    """Obtiene información básica de hardware del sistema."""
    info = {
        "Fecha/Hora": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Sistema Operativo": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "Procesador": platform.processor() or "Desconocido",
        "RAM Total (MB)": f"{psutil.virtual_memory().total / (1024 * 1024):.1f} MB"
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

def run_monitoring_phase(phase_name, duration_sec):
    """Ejecuta el monitoreo en bucle durante la duración especificada."""
    print(f"\n>>> Iniciando Fase: {phase_name} ({duration_sec} segundos de muestreo)...")
    
    cpu_samples = []
    mem_samples = []
    
    # Calentamiento rápido de psutil
    psutil.cpu_percent(interval=None)
    time.sleep(0.1)

    for sec in range(1, duration_sec + 1):
        # Mide el uso de CPU (bloquea por 1 segundo)
        cpu = psutil.cpu_percent(interval=1.0)
        # Calcula RAM usada como Total - Disponible (para alinearse con el comando free)
        mem_info = psutil.virtual_memory()
        mem_used_mb = (mem_info.total - mem_info.available) / (1024 * 1024)
        
        cpu_samples.append(cpu)
        mem_samples.append(mem_used_mb)
        
        # Barra de progreso ASCII en la consola
        pct_done = int((sec / duration_sec) * 100)
        bar_len = 20
        filled_len = int(bar_len * sec // duration_sec)
        bar = "#" * filled_len + "-" * (bar_len - filled_len)
        
        sys.stdout.write(f"\r    [{bar}] {pct_done}% | CPU actual: {cpu:>5.1f}% | RAM actual: {mem_used_mb:>7.1f} MB")
        sys.stdout.flush()
        
    print()  # Salto de línea al terminar la barra
    
    mean_cpu = np.mean(cpu_samples)
    peak_cpu = np.max(cpu_samples)
    mean_mem = np.mean(mem_samples)
    
    print(f"    -> Resultados de Fase:")
    print(f"       * CPU Media: {mean_cpu:.2f}%")
    print(f"       * CPU Pico:  {peak_cpu:.2f}%")
    print(f"       * RAM Media: {mean_mem:.1f} MB")
    
    return {
        "mean_cpu": mean_cpu,
        "peak_cpu": peak_cpu,
        "mean_mem": mean_mem
    }

def main():
    print("==================================================")
    print("    MONITOREO DE CONSUMO DE RECURSOS (PRUEBA 2)   ")
    print("==================================================")
    
    sys_info = get_system_info()
    print("\n[+] Información de Hardware de la Raspberry Pi:")
    for k, v in sys_info.items():
        print(f"    - {k}: {v}")
        
    # Solicitar duración de muestreo
    duration_input = input("\n[?] Ingrese la duración de monitoreo por estado (en segundos) [Por defecto: 60]: ")
    try:
        duration = int(duration_input) if duration_input.strip() else 60
    except ValueError:
        duration = 60
    print(f"[+] Se muestrearán {duration} segundos para cada uno de los 3 estados.")

    results = {}

    # ------------------------------------------------------------
    # FASE 1: Reposo
    # ------------------------------------------------------------
    print("\n" + "="*50)
    print("ESTADO 1: SISTEMA EN REPOSO (IDLE)")
    print("="*50)
    print("Instrucciones: Asegúrese de que el contenedor docker 'edge_ids_ips' está corriendo,")
    print("pero no realice navegación web activa ni ejecute simulaciones de ataque.")
    input("\n[Presione ENTER para comenzar el muestreo en Reposo...]")
    results["reposo"] = run_monitoring_phase("Reposo", duration)

    # ------------------------------------------------------------
    # FASE 2: Tráfico Normal
    # ------------------------------------------------------------
    print("\n" + "="*50)
    print("ESTADO 2: SISTEMA CON TRÁFICO NORMAL")
    print("="*50)
    print("Instrucciones: Comience a generar tráfico web legítimo desde algún dispositivo LAN.")
    print("Por ejemplo, abra páginas web, reproduzca un video en streaming o ejecute tests benignos.")
    input("\n[Presione ENTER cuando el tráfico normal esté fluyendo para comenzar el muestreo...]")
    results["trafico_normal"] = run_monitoring_phase("Tráfico Normal", duration)

    # ------------------------------------------------------------
    # FASE 3: Tráfico de Ataque
    # ------------------------------------------------------------
    print("\n" + "="*50)
    print("ESTADO 3: SISTEMA BAJO TRÁFICO DE ATAQUE SIMULADO")
    print("="*50)
    print("Instrucciones: Inicie el ataque simulado.")
    print("Ejemplos:")
    print("  a) Desde Kali ejecutando un flood: hping3 -k -d 120 -S -p 80 --flood <IP_RASPBERRY>")
    print("  b) Ejecutando localmente: python tests/test_attack_simulation.py")
    input("\n[Presione ENTER cuando el ataque haya comenzado para iniciar el muestreo...]")
    results["trafico_ataque"] = run_monitoring_phase("Tráfico de Ataque", duration)

    # ------------------------------------------------------------
    # Procesamiento y Reporte
    # ------------------------------------------------------------
    print("\n\n==================================================")
    print("              RESULTADOS DE LA PRUEBA 2")
    print("==================================================")
    
    print(f"\n{'Estado':<20} | {'CPU Media (%)':<15} | {'CPU Pico (%)':<15} | {'RAM Usada (MB)':<15}")
    print("-" * 71)
    
    states = [
        ("Reposo", "reposo"),
        ("Tráfico normal", "trafico_normal"),
        ("Tráfico ataque", "trafico_ataque")
    ]
    
    for label, key in states:
        r = results[key]
        print(f"{label:<20} | {r['mean_cpu']:>13.2f}% | {r['peak_cpu']:>13.2f}% | {r['mean_mem']:>13.1f} MB")

    # Evaluar criterios de éxito (RNF-02: CPU < 70%, RNF-03: RAM < 2GB/2048MB)
    cpu_limit = 70.0
    ram_limit_mb = 2048.0 # 2 GB
    
    # Obtener valores máximos registrados bajo ataque para evaluar cumplimiento
    attack_mean_cpu = results["trafico_ataque"]["mean_cpu"]
    attack_peak_cpu = results["trafico_ataque"]["peak_cpu"]
    attack_mean_ram = results["trafico_ataque"]["mean_mem"]
    
    rnf02_status = "✅ CUMPLIDO" if attack_mean_cpu < cpu_limit else "❌ NO CUMPLIDO"
    rnf03_status = "✅ CUMPLIDO" if attack_mean_ram < ram_limit_mb else "❌ NO CUMPLIDO"

    print("\n[+] Evaluación de Requisitos No Funcionales:")
    print(f"    * RNF-02 (CPU Media < {cpu_limit}%): {rnf02_status} (Media ataque: {attack_mean_cpu:.2f}%, Pico: {attack_peak_cpu:.2f}%)")
    print(f"    * RNF-03 (RAM Media < {ram_limit_mb:.0f} MB): {rnf03_status} (RAM ataque: {attack_mean_ram:.1f} MB)")

    # Escribir reporte Markdown
    report_lines = [
        "# Reporte de Consumo de Recursos en Raspberry Pi (Prueba 2)",
        f"\n*Generado automáticamente el {sys_info['Fecha/Hora']}*\n",
        "## 1. Información del Sistema de Monitoreo",
        f"- **Fecha y Hora**: {sys_info['Fecha/Hora']}",
        f"- **Sistema Operativo**: {sys_info['Sistema Operativo']}",
        f"- **Procesador**: {sys_info['Procesador']}",
        f"- **RAM Total**: {sys_info['RAM Total (MB)']}",
    ]
    if "Hardware" in sys_info:
        report_lines.append(f"- **Hardware detectado**: {sys_info['Hardware']}")
        
    report_lines.extend([
        "\n## 2. Consumo de Recursos por Estado",
        "Mediciones en vivo del sistema completo en los tres escenarios operativos requeridos:",
        "\n| Estado | CPU Media (%) | CPU Pico (%) | RAM Usada Media (MB) |",
        "| :--- | :---: | :---: | :---: |"
    ])
    
    for label, key in states:
        r = results[key]
        report_lines.append(f"| {label} | {r['mean_cpu']:.2f}% | {r['peak_cpu']:.2f}% | {r['mean_mem']:.1f} MB |")
        
    report_lines.extend([
        "\n## 3. Criterios de Éxito y Cumplimiento",
        f"- **Requisito RNF-02**: El uso medio de la CPU del sistema debe mantenerse por debajo del **{cpu_limit}%**.",
        f"  * **Estado**: **{rnf02_status}** (CPU Media durante ataque: **{attack_mean_cpu:.2f}%**)",
        f"- **Requisito RNF-03**: La memoria RAM usada por el sistema debe mantenerse por debajo de **2 GB ({ram_limit_mb:.0f} MB)**.",
        f"  * **Estado**: **{rnf03_status}** (RAM Media durante ataque: **{attack_mean_ram:.1f} MB**)",
        "\n## 4. Notas de la Prueba",
        f"El muestreo se realizó con intervalos de 1 segundo durante un total de **{duration} segundos** por cada estado.",
        "El consumo registrado incluye el sistema operativo host de la Raspberry Pi y todos sus contenedores Docker activos en operación real."
    ])
    
    output_dir = os.path.dirname("data/resource_consumption_results.md")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        with open("data/resource_consumption_results.md", "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))
        print(f"\n[+] Reporte escrito exitosamente en 'data/resource_consumption_results.md'")
    except Exception as e:
        print(f"\n[!] Error guardando el reporte: {e}")

if __name__ == "__main__":
    main()
