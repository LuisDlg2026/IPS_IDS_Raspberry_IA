import subprocess
import threading
import time
import sys
import os
import logging

from src.detection.detector import IDSDetector
from src.utils.storage import Database
from src.utils.network_stats import NetworkMonitor

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

def start_backend():
    logger.info("Iniciando motor de captura de red e inferencia ML en segundo plano...")
    try:
        # 1. Conectar a la base de datos
        db = Database()
        
        # 2. Iniciar el monitor de estadísticas reales de la Raspberry Pi
        logger.info("Iniciando recolección de estadísticas reales (CPU, RAM, Ancho de banda)...")
        monitor = NetworkMonitor(db=db)
        monitor.start(interval=10) # Guarda estadísticas cada 10 segundos
        
        # 3. Callback para guardar alertas del modelo ML en la base de datos
        def on_alert_detected(alert):
            logger.warning(f"Guardando nueva alerta en DB: {alert.prediction}")
            db.save_alert(alert.to_dict())

        # 4. Iniciar el detector pasándole el callback
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
