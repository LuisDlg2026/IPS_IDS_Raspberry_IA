import subprocess
import threading
import time
import sys
import os
import logging
from scapy.all import ARP, Ether, srp, conf

from src.detection.detector import IDSDetector
from src.utils.storage import Database
from src.utils.network_stats import NetworkMonitor
from src.crawler.firmware_crawler import FirmwareCrawler
from src.crawler.device_alerts import DeviceAlertManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

def start_backend():
    logger.info("Iniciando motor de captura de red e inferencia ML en segundo plano...")
    try:
        # 1. Conectar a la base de datos
        db = Database()
        
        # 1.5. Limpiar base de datos de pruebas si existe la variable de entorno o por defecto al iniciar real
        logger.info("Limpiando dispositivos antiguos para descubrir red real...")
        db.cleanup(days=0) # Borramos lo antiguo o forzamos nueva vista
        
        # 2. Iniciar el monitor de estadísticas reales de la Raspberry Pi
        logger.info("Iniciando recolección de estadísticas reales (CPU, RAM, Ancho de banda)...")
        monitor = NetworkMonitor(db=db)
        monitor.start(interval=10) # Guarda estadísticas cada 10 segundos
        
        # 3. Callback para guardar alertas del modelo ML en la base de datos
        def on_alert_detected(alert):
            logger.warning(f"Guardando nueva alerta en DB: {alert.prediction}")
            db.save_alert(alert.to_dict())

        # 4. Hilo de descubrimiento activo de dispositivos en la red (ARP)
        def network_discovery_loop():
            crawler = FirmwareCrawler(db)
            alert_manager = DeviceAlertManager(db)
            
            # Detectar subred basada en gateway o forzar una tipica local
            target_ip = "192.168.1.0/24"
            logger.info(f"Iniciando escaneo de dispositivos (ARP) en la red {target_ip}...")
            
            while True:
                try:
                    # Usar scapy para enviar ARP requests (requiere root)
                    arp_request = ARP(pdst=target_ip)
                    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                    packet = ether/arp_request
                    
                    # srp envia y recibe en capa 2 (MAC)
                    result = srp(packet, timeout=3, verbose=0)[0]
                    
                    discovered = 0
                    for sent, received in result:
                        ip = received.psrc
                        mac = received.hwsrc
                        
                        # Auditar el dispositivo descubierto (Firmware Crawler)
                        device_info = crawler.audit_device(ip, mac)
                        device_info["is_online"] = 1
                        device_info["risk_level"] = "low" if not device_info.get("needs_update") else "medium"
                        
                        # Guardar y generar alertas si aplican
                        alert_manager.evaluate_device(device_info)
                        discovered += 1
                        
                    logger.info(f"Escaneo de red completado: {discovered} dispositivos activos encontrados.")
                    
                except Exception as e:
                    logger.error(f"Error en descubrimiento de red: {e}")
                
                # Repetir el escaneo cada 5 minutos
                time.sleep(300)

        discovery_thread = threading.Thread(target=network_discovery_loop, daemon=True)
        discovery_thread.start()

        # 5. Iniciar el detector pasándole el callback
        detector = IDSDetector(on_alert=on_alert_detected)
        detector.start()
        
    except Exception as e:
        logger.error(f"Error crítico en el backend: {e}")
        sys.exit(1)

def start_frontend():
    logger.info("Levantando servidor Streamlit Dashboard...")
    try:
        # Usamos subprocess para lanzar streamlit
        subprocess.run(
            [sys.executable, "-m", "streamlit", "run", "src/dashboard/app.py", "--server.port=8501", "--server.address=0.0.0.0"],
            check=True
        )
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error(f"Error al iniciar el frontend: {e}")

if __name__ == "__main__":
    print("==================================================")
    print("  Edge-IIoTset IPS/IDS - Arrancando Sistema")
    print("==================================================")
    
    # 1. Iniciar backend en un hilo
    backend_thread = threading.Thread(target=start_backend, daemon=True)
    backend_thread.start()
    
    # 2. Darle 3 segundos al backend para que inicialice interfaces y SQLite
    time.sleep(3)
    
    # 3. Iniciar Streamlit en el hilo principal (bloqueante)
    start_frontend()
