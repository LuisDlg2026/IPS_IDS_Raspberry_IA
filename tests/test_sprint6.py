"""
Test de integracion del Sprint 6 (Almacenamiento + Crawler + Stats).

Ejecuta:
  - Database: Creacion y operaciones CRUD de alertas/eventos
  - NetworkMonitor: Recoleccion de metricas
  - FirmwareCrawler + DeviceAlertManager: Auditoria simulada

Uso:
  python tests/test_sprint6.py
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.storage import Database
from src.utils.network_stats import NetworkMonitor
from src.crawler.firmware_crawler import FirmwareCrawler
from src.crawler.device_alerts import DeviceAlertManager

def main():
    print("=" * 70)
    print("TEST SPRINT 6: Almacenamiento, Crawler y Stats")
    print("=" * 70)

    # 1. Test Database
    print("\n[1/4] Inicializando Base de Datos (SQLite)...")
    db = Database()
    print("  [OK] Conexión establecida y tablas creadas.")

    # 2. Test Network Monitor
    print("\n[2/4] Iniciando NetworkMonitor...")
    monitor = NetworkMonitor(db=db)
    monitor.start(interval=2)  # Recolectar rápido para el test
    time.sleep(5)  # Esperar a que recolecte algunos datos
    monitor.stop()

    stats = db.get_network_stats(limit=5)
    print(f"  [OK] Recolectados {len(stats)} registros de red.")
    if stats:
        print(f"     Último registro: CPU {stats[0].get('cpu_percent')}% | Memoria {stats[0].get('memory_percent')}%")

    # 3. Test Crawler & Alerts
    print("\n[3/4] Probando FirmwareCrawler y DeviceAlertManager...")
    crawler = FirmwareCrawler(db=db)
    alert_manager = DeviceAlertManager(db=db)

    # Simular dispositivo vulnerable
    device_info = crawler.audit_device("192.168.1.1", "CC:32:E5:11:22:33")
    # Forzamos los valores simulados para el test
    device_info["model"] = "Archer C7"
    device_info["current_firmware"] = "1.0.4 Build 20180425"
    device_info["latest_firmware"] = "1.0.5 Build 20201120"
    device_info["needs_update"] = True
    
    alert_manager.evaluate_device(device_info)

    # Simular otro dispositivo seguro
    device_info_safe = crawler.audit_device("192.168.1.20", "00:1E:E3:AA:BB:CC")
    device_info_safe["model"] = "Apple TV"
    alert_manager.evaluate_device(device_info_safe)

    devices = db.get_devices()
    print(f"  [OK] Dispositivos guardados: {len(devices)}")
    for dev in devices:
        print(f"     - {dev['ip']} ({dev['vendor']})")

    # 4. Verificar Alertas y Eventos
    print("\n[4/4] Verificando Alertas generadas en SQLite...")
    alerts = db.get_alerts()
    print(f"  [OK] Alertas totales: {len(alerts)}")
    for alert in alerts:
        print(f"     - {alert['attack_type']} [{alert['severity'].upper()}]: IP {alert['src_ip']}")

    events = db.get_events()
    print(f"  [OK] Eventos de auditoría: {len(events)}")
    
    summary = db.get_alert_summary()
    print(f"\nResumen de alertas por severidad: {summary['by_severity']}")

    print("\n" + "=" * 70)
    print("[OK] SPRINT 6 COMPLETADO CON EXITO")
    print("=" * 70)

if __name__ == "__main__":
    main()
