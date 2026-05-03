"""
Generador de alertas para dispositivos en la red.

Conecta el crawler de firmware con la base de datos de almacenamiento,
evaluando la informacion del dispositivo y generando alertas de seguridad
si detecta versiones de firmware obsoletas o vulnerabilidades.

Uso:
    from src.crawler.device_alerts import DeviceAlertManager
    manager = DeviceAlertManager(db)
    manager.evaluate_device(device_info)
"""

import logging
from typing import Dict
import time

logger = logging.getLogger(__name__)

class DeviceAlertManager:
    """
    Evalua el estado de los dispositivos y genera alertas en el storage.
    """

    def __init__(self, db):
        self._db = db
        logger.info("DeviceAlertManager inicializado")

    def evaluate_device(self, device_info: Dict):
        """
        Evalua un dispositivo y genera alertas si es necesario.
        Se apoya en la info extraida por FirmwareCrawler.
        """
        mac = device_info.get("mac", "unknown")
        ip = device_info.get("ip", "unknown")
        
        # 1. Guardar o actualizar el dispositivo en la BD
        self._db.save_device(device_info)

        # 2. Evaluar si necesita actualizacion de firmware
        if device_info.get("needs_update"):
            current = device_info.get("current_firmware", "Unknown")
            latest = device_info.get("latest_firmware", "Unknown")
            
            alert = {
                "id": f"VULN-{int(time.time()*1000)}-{mac.replace(':','')}",
                "attack_type": "Vulnerability_scanner",  # Lo clasificamos bajo esta etiqueta para el dashboard
                "confidence": 0.95,
                "severity": "medium",
                "src_ip": ip,
                "dst_ip": ip,
                "flow_key": "device_audit",
                "details": {
                    "reason": "Outdated firmware detected",
                    "current": current,
                    "latest": latest,
                    "vendor": device_info.get("vendor"),
                    "model": device_info.get("model")
                }
            }
            logger.warning(f"Generando alerta de firmware para {ip} ({mac})")
            self._db.save_alert(alert)

        # 3. Evaluar vulnerabilidades conocidas (CVEs) simuladas
        if device_info.get("cve_found"):
            for cve in device_info["cve_found"]:
                alert = {
                    "id": f"CVE-{int(time.time()*1000)}-{cve}",
                    "attack_type": "Vulnerability",
                    "confidence": 1.0,
                    "severity": "high",
                    "src_ip": ip,
                    "dst_ip": ip,
                    "flow_key": "device_audit",
                    "details": {
                        "reason": f"Known Vulnerability {cve} detected",
                        "vendor": device_info.get("vendor"),
                        "model": device_info.get("model")
                    }
                }
                logger.warning(f"Generando alerta CVE {cve} para {ip}")
                self._db.save_alert(alert)

        # 4. Registrar evento de auditoria completada
        self._db.log_event(
            event_type="device_audit",
            message=f"Auditoria completada para {ip} ({device_info.get('vendor')})",
            severity="info",
            details=device_info
        )
