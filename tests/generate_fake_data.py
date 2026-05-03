import sys
import time
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.storage import Database

def generate_fake_data():
    print("Conectando a base de datos...")
    db = Database()
    
    # 1. Generar Dispositivos Falsos
    devices = [
        {"mac": "00:1E:E3:11:22:33", "ip": "192.168.1.10", "vendor": "Apple", "os_guess": "iOS", "risk_level": "low", "is_online": 1},
        {"mac": "B8:27:EB:AA:BB:CC", "ip": "192.168.1.5", "vendor": "Raspberry Pi", "os_guess": "Linux", "risk_level": "low", "is_online": 1},
        {"mac": "CC:32:E5:99:88:77", "ip": "192.168.1.1", "vendor": "TP-Link", "os_guess": "VxWorks", "risk_level": "medium", "is_online": 1},
        {"mac": "00:14:BF:DE:AD:BE", "ip": "192.168.1.100", "vendor": "Linksys", "os_guess": "Linux", "risk_level": "high", "is_online": 0},
        {"mac": "C0:25:E9:12:34:56", "ip": "192.168.1.150", "vendor": "TP-Link", "os_guess": "Unknown", "risk_level": "critical", "is_online": 1},
    ]
    
    print("Guardando dispositivos falsos...")
    for dev in devices:
        db.save_device(dev)

    # 2. Generar Estadísticas de Red Falsas (Tendencia)
    print("Guardando estadísticas de red falsas...")
    base_time = datetime.now().timestamp()
    
    # Simularemos las últimas 2 horas, 1 muestra por minuto (120 muestras)
    for i in range(120, 0, -1):
        fake_time = base_time - (i * 60)
        
        # Simular ancho de banda (un poco de ruido)
        bw = 10.0 + (i % 5) + (time.time() % 3)
        if i % 15 == 0: bw += 25.0 # Picos ocasionales
        
        stats = {
            "bytes_sent": int(bw * 1000 * 1000 / 8),
            "bytes_recv": int(bw * 2000 * 1000 / 8),
            "bandwidth_mbps": bw,
            "cpu_percent": 30.0 + (i % 20),
            "memory_percent": 45.0 + (i % 5),
            "latency_ms": 15.0 + (i % 10),
            "active_connections": 150 + (i % 50)
        }
        
        # Inyectar directamente con sqlite para forzar el timestamp
        conn = db._get_conn()
        conn.execute("""
            INSERT INTO network_stats 
            (timestamp, bytes_sent, bytes_recv, bandwidth_mbps, cpu_percent, memory_percent, latency_ms, active_connections)
            VALUES (datetime(?, 'unixepoch', 'localtime'), ?, ?, ?, ?, ?, ?, ?)
        """, (fake_time, stats['bytes_sent'], stats['bytes_recv'], stats['bandwidth_mbps'], 
              stats['cpu_percent'], stats['memory_percent'], stats['latency_ms'], stats['active_connections']))
        conn.commit()
        conn.close()

    # 3. Generar Alertas Falsas
    print("Guardando alertas falsas...")
    alerts = [
        {"attack_type": "DDoS_TCP", "confidence": 0.98, "severity": "critical", "src_ip": "114.114.114.114", "dst_ip": "192.168.1.5"},
        {"attack_type": "Port_Scanning", "confidence": 0.85, "severity": "low", "src_ip": "192.168.1.100", "dst_ip": "192.168.1.1"},
        {"attack_type": "Vulnerability_scanner", "confidence": 0.95, "severity": "medium", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.1", "details": {"reason": "Firmware antiguo"}},
        {"attack_type": "MITM", "confidence": 0.76, "severity": "high", "src_ip": "192.168.1.150", "dst_ip": "192.168.1.10"},
        {"attack_type": "Password", "confidence": 0.91, "severity": "medium", "src_ip": "8.8.8.8", "dst_ip": "192.168.1.5"},
    ]
    
    for alert in alerts:
        db.save_alert(alert)

    print("✅ Datos falsos inyectados con éxito. Listo para probar el Dashboard.")

if __name__ == "__main__":
    generate_fake_data()
