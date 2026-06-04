"""
Motor de escaneo activo basado en Nmap.

Realiza escaneos profundos bajo demanda para detectar sistemas operativos
(OS Fingerprinting) y puertos abiertos en los dispositivos descubiertos.
"""

import nmap
import logging
import threading
from typing import Dict, Optional, List

logger = logging.getLogger(__name__)

class NmapScanner:
    """
    Controlador de Nmap para análisis de red.
    """
    def __init__(self, db=None):
        self._db = db
        try:
            self.nm = nmap.PortScanner()
            self._available = True
        except nmap.PortScannerError:
            logger.error("Nmap no está instalado en el sistema. Los escaneos profundos fallarán.")
            self._available = False
        except Exception as e:
            logger.error(f"Error inicializando python-nmap: {e}")
            self._available = False
            
    def scan_device(self, ip: str) -> Optional[Dict]:
        """
        Realiza un escaneo activo (OS y Puertos TCP) a un dispositivo.
        Es un proceso bloqueante (tarda 10-30s).
        """
        if not self._available:
            return None
            
        logger.info(f"Iniciando escaneo profundo Nmap para {ip}...")
        try:
            # -sV: Detección de versión de servicios
            # -O: Detección de Sistema Operativo (requiere Root)
            # -F: Escaneo rápido (top 100 puertos)
            # -T4: Velocidad rápida
            # -Pn: Ignorar el ping (imprescindible para móviles o Windows con Firewall cerrado)
            self.nm.scan(hosts=ip, arguments='-sV -O -F -T4 -Pn --host-timeout 30s')
            
            if ip not in self.nm.all_hosts():
                logger.warning(f"Nmap no encontró el host {ip} o no respondió.")
                return None
                
            host_data = self.nm[ip]
            
            # Extraer hostname de Nmap si está disponible (DHCP / DNS inverso)
            hostname = None
            if 'hostnames' in host_data and len(host_data['hostnames']) > 0:
                name = host_data['hostnames'][0].get('name')
                if name:
                    hostname = name

            # Extraer puertos abiertos
            open_ports = []
            if 'tcp' in host_data:
                for port in host_data['tcp']:
                    state = host_data['tcp'][port]['state']
                    if state == 'open':
                        name = host_data['tcp'][port].get('name', 'unknown')
                        open_ports.append(f"{port}/tcp ({name})")
                        
            # Extraer estimación de OS basada en los banners de servicios (sV)
            # Ocasionalmente nmap adivina el OS cuando usa -sV
            os_guess = None
            if 'osmatch' in host_data and len(host_data['osmatch']) > 0:
                os_guess = host_data['osmatch'][0].get('name')
            else:
                # Si no hay osmatch, buscamos en los servicios
                for port in host_data.get('tcp', {}):
                    cpe = host_data['tcp'][port].get('cpe', '')
                    if 'cpe:/o:linux' in cpe: os_guess = 'Linux'
                    elif 'cpe:/o:microsoft:windows' in cpe: os_guess = 'Windows'
                    elif 'cpe:/o:apple' in cpe: os_guess = 'Apple/iOS/macOS'
                
            result = {
                "ip": ip,
                "open_ports": open_ports,
                "os_guess": os_guess,
                "hostname": hostname
            }
            logger.info(f"Escaneo Nmap completado para {ip}: OS={os_guess}, Puertos={open_ports}, Hostname={hostname}")
            return result
            
        except Exception as e:
            logger.error(f"Error durante escaneo Nmap a {ip}: {e}")
            return None

    def scan_device_async(self, ip: str):
        """
        Inicia el escaneo en un hilo en background para no bloquear.
        Guarda los resultados en la BD automáticamente.
        """
        if not self._db:
            logger.error("No se proporcionó conexión a la DB para el escaneo asíncrono.")
            return
            
        def _task():
            data = self.scan_device(ip)
            if data and (data.get("os_guess") or data.get("open_ports")):
                self._db.save_device(data)
                
        thread = threading.Thread(target=_task, daemon=True)
        thread.start()
