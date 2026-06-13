"""
Script para poblar la base de datos con datos de demostración.
Permite probar el dashboard localmente sin la Raspberry Pi.

Uso: python scripts/seed_demo_data.py
"""

import sys
from pathlib import Path

# Asegurar que src está en el path
sys.path.insert(0, str(Path(__file__).parent.parent))

import random
from datetime import datetime, timedelta
from src.utils.storage import Database
from src.config import ATTACK_SEVERITY

def seed():
    db = Database()

    print("=== Seed Demo Data ===")
    print(f"DB: {db._db_path}")

    # ── 1. Dispositivos de ejemplo ──────────────────────────────
    devices = [
        {"ip": "192.168.1.1",   "mac": "AA:BB:CC:00:01:01", "hostname": "Router-Gateway",   "vendor": "TP-Link",    "os_guess": "Linux",   "risk_level": "low"},
        {"ip": "192.168.1.10",  "mac": "AA:BB:CC:00:01:10", "hostname": "Sensor-Temp-01",   "vendor": "ESP32",      "os_guess": "FreeRTOS","risk_level": "low"},
        {"ip": "192.168.1.11",  "mac": "AA:BB:CC:00:01:11", "hostname": "Sensor-Humedad",   "vendor": "ESP8266",    "os_guess": "FreeRTOS","risk_level": "low"},
        {"ip": "192.168.1.20",  "mac": "AA:BB:CC:00:01:20", "hostname": "Camara-IP-01",     "vendor": "Hikvision",  "os_guess": "Linux",   "risk_level": "medium"},
        {"ip": "192.168.1.30",  "mac": "AA:BB:CC:00:01:30", "hostname": "PLC-Industrial",   "vendor": "Siemens",    "os_guess": "VxWorks", "risk_level": "high"},
        {"ip": "192.168.1.100", "mac": "AA:BB:CC:00:01:64", "hostname": "PC-Operador",      "vendor": "Dell",       "os_guess": "Windows", "risk_level": "low"},
        {"ip": "192.168.1.200", "mac": "AA:BB:CC:00:01:C8", "hostname": "Raspberry-IDS",    "vendor": "Raspberry Pi","os_guess": "Linux",  "risk_level": "low"},
    ]
    for d in devices:
        db.save_device(d)
    print(f"  [+] {len(devices)} dispositivos creados")

    # ── 2. Alertas de las últimas 24 horas ──────────────────────
    attack_types = list(ATTACK_SEVERITY.keys())
    attack_types.remove("Normal")  # No generar alertas "Normal"
    now = datetime.now()

    alerts_created = 0
    for i in range(80):
        ts = now - timedelta(minutes=random.randint(1, 1440))  # últimas 24h
        attack = random.choice(attack_types)
        severity = ATTACK_SEVERITY[attack]
        confidence = round(random.uniform(0.55, 0.99), 3)
        inference_ms = round(random.uniform(1.5, 25.0), 2)

        alert = {
            "id": f"DEMO-{i:04d}",
            "timestamp": ts.isoformat(),
            "attack_type": attack,
            "confidence": confidence,
            "severity": severity,
            "src_ip": f"192.168.1.{random.randint(2, 254)}",
            "dst_ip": f"192.168.1.{random.choice([1, 10, 11, 20, 30, 100, 200])}",
            "n_packets": random.randint(10, 5000),
            "inference_ms": inference_ms,
        }
        db.save_alert(alert)
        alerts_created += 1

    # Agregar algunas alertas criticas en los ultimos 15 min para activar el semaforo
    for i in range(5):
        ts = now - timedelta(minutes=random.randint(1, 14))
        alert = {
            "id": f"DEMO-CRIT-{i:04d}",
            "timestamp": ts.isoformat(),
            "attack_type": random.choice(["DDoS_TCP", "Ransomware", "Backdoor", "DDoS_HTTP"]),
            "confidence": round(random.uniform(0.85, 0.99), 3),
            "severity": "critical",
            "src_ip": f"10.0.0.{random.randint(50, 200)}",
            "dst_ip": "192.168.1.30",
            "n_packets": random.randint(500, 10000),
            "inference_ms": round(random.uniform(3.0, 15.0), 2),
        }
        db.save_alert(alert)
        alerts_created += 1

    print(f"  [+] {alerts_created} alertas creadas (incluyendo 5 criticas recientes)")

    # ── 3. Metricas de red (ultimas 2 horas, cada 2 min) ────────
    stats_created = 0
    for i in range(60):
        ts = now - timedelta(minutes=i * 2)
        db.save_network_stats({
            "bytes_sent": random.randint(100000, 5000000),
            "bytes_recv": random.randint(200000, 8000000),
            "packets_sent": random.randint(500, 5000),
            "packets_recv": random.randint(800, 8000),
            "active_connections": random.randint(5, 40),
            "cpu_percent": round(random.uniform(15.0, 75.0), 1),
            "memory_percent": round(random.uniform(30.0, 70.0), 1),
            "latency_ms": round(random.uniform(2.0, 50.0), 1),
            "bandwidth_mbps": round(random.uniform(5.0, 95.0), 2),
        })
        stats_created += 1
    print(f"  [+] {stats_created} registros de metricas de red creados")

    # ── 4. Eventos del sistema ──────────────────────────────────
    events = [
        ("system_start",  "info",    "Sistema IDS/IPS iniciado correctamente"),
        ("model_loaded",  "info",    "Modelo Random Forest cargado (accuracy: 97.3%)"),
        ("scan_complete", "info",    "Escaneo ARP completado: 7 dispositivos detectados"),
        ("alert_burst",   "warning", "Rafaga de alertas detectada: 12 alertas en 5 minutos"),
        ("mitm_blocked",  "critical","Ataque MITM bloqueado desde 10.0.0.77"),
    ]
    for etype, sev, msg in events:
        db.log_event(etype, msg, severity=sev)
    print(f"  [+] {len(events)} eventos del sistema creados")

    print("\n=== Datos de demo insertados correctamente ===")
    print("Ejecuta el dashboard con:")
    print("  streamlit run src/dashboard/app.py")


if __name__ == "__main__":
    seed()
