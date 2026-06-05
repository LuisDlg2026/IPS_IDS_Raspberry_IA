"""
Generador de datos de demostración para el dashboard.
Permite poblar la base de datos con datos simulados realistas
para probar el dashboard sin la Raspberry Pi en producción.
"""

import random
import logging
from datetime import datetime, timedelta
from src.utils.storage import Database
from src.config import ATTACK_SEVERITY

logger = logging.getLogger(__name__)

# Clave usada en la tabla `settings` para persistir el modo
DEMO_MODE_KEY = "demo_mode_enabled"


def is_demo_mode(db: Database) -> bool:
    """Devuelve True si el modo demostración está activo."""
    return db.get_setting(DEMO_MODE_KEY) == "1"


def set_demo_mode(db: Database, enabled: bool):
    """Activa o desactiva el modo demostración."""
    db.set_setting(DEMO_MODE_KEY, "1" if enabled else "0")


def clear_demo_data(db: Database):
    """Elimina todos los datos de demostración (prefijo DEMO- en alertas)
    y limpia las tablas auxiliares que se poblaron con datos simulados."""
    import sqlite3
    conn = db._get_conn()
    try:
        # Eliminar alertas con prefijo DEMO-
        conn.execute("DELETE FROM alerts WHERE id LIKE 'DEMO-%'")
        # Eliminar dispositivos de demo (MACs que empiezan con AA:BB:CC:00)
        conn.execute("DELETE FROM devices WHERE mac LIKE 'AA:BB:CC:00%'")
        # Eliminar métricas de red simuladas (todas, ya que no tienen
        # prefijo; en producción solo habrá datos reales)
        # NO borramos network_stats ni events para no perder datos reales
        # Solo borramos eventos de demo
        conn.execute("DELETE FROM events WHERE message LIKE '%demo%' OR event_type = 'demo_seed'")
        conn.commit()
        logger.info("Datos de demostración eliminados")
    finally:
        conn.close()


def generate_demo_data(db: Database):
    """Genera un conjunto completo de datos simulados realistas."""

    # Primero limpiar datos de demo previos
    clear_demo_data(db)

    now = datetime.now()

    # ── 1. Dispositivos IoT de ejemplo ──────────────────────────
    devices = [
        {"ip": "192.168.1.1",   "mac": "AA:BB:CC:00:01:01", "hostname": "Router-Gateway",
         "vendor": "TP-Link",     "os_guess": "Linux",    "risk_level": "low"},
        {"ip": "192.168.1.10",  "mac": "AA:BB:CC:00:01:10", "hostname": "Sensor-Temp-01",
         "vendor": "ESP32",       "os_guess": "FreeRTOS", "risk_level": "low"},
        {"ip": "192.168.1.11",  "mac": "AA:BB:CC:00:01:11", "hostname": "Sensor-Humedad",
         "vendor": "ESP8266",     "os_guess": "FreeRTOS", "risk_level": "low"},
        {"ip": "192.168.1.20",  "mac": "AA:BB:CC:00:01:20", "hostname": "Camara-IP-01",
         "vendor": "Hikvision",   "os_guess": "Linux",    "risk_level": "medium"},
        {"ip": "192.168.1.30",  "mac": "AA:BB:CC:00:01:30", "hostname": "PLC-Industrial",
         "vendor": "Siemens",     "os_guess": "VxWorks",  "risk_level": "high"},
        {"ip": "192.168.1.100", "mac": "AA:BB:CC:00:01:64", "hostname": "PC-Operador",
         "vendor": "Dell",        "os_guess": "Windows",  "risk_level": "low"},
        {"ip": "192.168.1.200", "mac": "AA:BB:CC:00:01:C8", "hostname": "Raspberry-IDS",
         "vendor": "Raspberry Pi", "os_guess": "Linux",   "risk_level": "low"},
    ]
    for d in devices:
        db.save_device(d)

    # ── 2. Alertas distribuidas en las últimas 24 horas ─────────
    attack_types = [k for k in ATTACK_SEVERITY.keys() if k != "Normal"]

    for i in range(80):
        ts = now - timedelta(minutes=random.randint(1, 1440))
        attack = random.choice(attack_types)
        severity = ATTACK_SEVERITY[attack]

        db.save_alert({
            "id": f"DEMO-{i:04d}",
            "timestamp": ts.isoformat(),
            "attack_type": attack,
            "confidence": round(random.uniform(0.55, 0.99), 3),
            "severity": severity,
            "src_ip": f"192.168.1.{random.randint(2, 254)}",
            "dst_ip": f"192.168.1.{random.choice([1, 10, 11, 20, 30, 100, 200])}",
            "n_packets": random.randint(10, 5000),
            "inference_ms": round(random.uniform(1.5, 25.0), 2),
        })

    # Alertas críticas recientes (últimos 15 min) para activar el semáforo
    for i in range(5):
        ts = now - timedelta(minutes=random.randint(1, 14))
        db.save_alert({
            "id": f"DEMO-CRIT-{i:04d}",
            "timestamp": ts.isoformat(),
            "attack_type": random.choice(["DDoS_TCP", "Ransomware", "Backdoor", "DDoS_HTTP"]),
            "confidence": round(random.uniform(0.85, 0.99), 3),
            "severity": "critical",
            "src_ip": f"10.0.0.{random.randint(50, 200)}",
            "dst_ip": "192.168.1.30",
            "n_packets": random.randint(500, 10000),
            "inference_ms": round(random.uniform(3.0, 15.0), 2),
        })

    # ── 3. Métricas de red (últimas 2 horas, cada 2 min) ────────
    for i in range(60):
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

    # ── 4. Eventos del sistema ──────────────────────────────────
    demo_events = [
        ("system_start",  "info",     "Sistema IDS/IPS iniciado correctamente"),
        ("model_loaded",  "info",     "Modelo Random Forest cargado (accuracy: 97.3%)"),
        ("scan_complete", "info",     "Escaneo ARP completado: 7 dispositivos detectados"),
        ("alert_burst",   "warning",  "Ráfaga de alertas detectada: 12 alertas en 5 minutos"),
        ("mitm_blocked",  "critical", "Ataque MITM bloqueado desde 10.0.0.77"),
        ("demo_seed",     "info",     "Datos de demostración generados correctamente"),
    ]
    for etype, sev, msg in demo_events:
        db.log_event(etype, msg, severity=sev)

    # ── 5. Tráfico web simulado ─────────────────────────────────
    domains = [
        "google.com", "github.com", "stackoverflow.com", "aws.amazon.com",
        "malware-c2.evil.com", "phishing-login.ru", "update.microsoft.com",
        "cdn.cloudflare.com", "api.openai.com", "suspicious-download.xyz",
    ]
    for i in range(30):
        ts = now - timedelta(minutes=random.randint(1, 360))
        db.save_web_log({
            "src_ip": f"192.168.1.{random.choice([10, 11, 20, 30, 100])}",
            "dst_ip": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "protocol": random.choice(["HTTPS/TLS", "HTTP", "DNS"]),
            "domain_url": random.choice(domains),
            "details": {"method": "GET", "status": random.choice([200, 301, 403, 404])},
        })

    logger.info("Datos de demostración generados: 7 dispositivos, 85 alertas, 60 métricas, 30 registros web")
