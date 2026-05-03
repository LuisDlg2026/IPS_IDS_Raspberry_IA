"""
Crawler para auditoria de firmware de dispositivos IoT.

Identifica dispositivos en la red, intenta extraer su version de firmware
(via banners HTTP/SSH, o inferencias) y busca online (fabricantes o bases de datos)
si existen versiones mas recientes o vulnerabilidades conocidas.

Uso:
    from src.crawler.firmware_crawler import FirmwareCrawler
    crawler = FirmwareCrawler(db)
    crawler.audit_device("192.168.1.50")
"""

import logging
import requests
import socket
import re
from bs4 import BeautifulSoup
from typing import Dict, Optional, Tuple, List

logger = logging.getLogger(__name__)


class FirmwareCrawler:
    """
    Rastreador de versiones de firmware y vulnerabilidades.
    """

    def __init__(self, db=None):
        self._db = db
        # Mapeo de MAC OUI a fabricantes conocidos
        self._vendors = {
            "CC:32:E5": "TP-Link",
            "C0:25:E9": "TP-Link",
            "00:14:BF": "Linksys",
            "00:1E:E3": "Apple",
            "B8:27:EB": "Raspberry Pi Foundation",
            "DC:A6:32": "Raspberry Pi Foundation",
            "00:0C:29": "VMware",
        }
        logger.info("FirmwareCrawler inicializado")

    def audit_device(self, ip: str, mac: str = None) -> Dict:
        """
        Realiza la auditoria completa de un dispositivo.
        1. Identifica el fabricante y modelo
        2. Intenta extraer firmware actual
        3. Busca la ultima version disponible
        """
        logger.info(f"Auditando dispositivo {ip} (MAC: {mac})")

        vendor = self._guess_vendor(mac) if mac else "Unknown"
        device_info = {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "model": "Unknown",
            "current_firmware": "Unknown",
            "latest_firmware": "Unknown",
            "needs_update": False,
            "cve_found": []
        }

        # Intentar obtener info por HTTP (ej. panel de admin de router)
        banner, http_title = self._grab_http_banner(ip)
        if http_title:
            device_info["notes"] = f"HTTP Title: {http_title}"
            # Reglas simples para inferir modelo/firmware basado en title
            if "TP-Link" in http_title or "Tether" in http_title:
                device_info["vendor"] = "TP-Link"
                device_info["model"] = "Archer C7" # Ejemplo simulado
                device_info["current_firmware"] = "1.0.4 Build 20180425"

        # Simular una busqueda de la ultima version en base al modelo
        if device_info["model"] != "Unknown":
            latest_fw = self._check_latest_firmware(device_info["vendor"], device_info["model"])
            if latest_fw:
                device_info["latest_firmware"] = latest_fw
                if device_info["current_firmware"] != latest_fw:
                    device_info["needs_update"] = True

        return device_info

    def _guess_vendor(self, mac: str) -> str:
        """Estima el fabricante basado en el prefijo MAC."""
        if not mac:
            return "Unknown"
        oui = mac.upper()[:8]
        return self._vendors.get(oui, "Unknown")

    def _grab_http_banner(self, ip: str, port: int = 80, timeout: int = 2) -> Tuple[str, str]:
        """Obtiene el banner y titulo HTTP de un dispositivo."""
        try:
            url = f"http://{ip}:{port}/"
            resp = requests.get(url, timeout=timeout, verify=False)
            banner = resp.headers.get("Server", "")

            # Extraer title
            title = ""
            if resp.text:
                soup = BeautifulSoup(resp.text, "html.parser")
                if soup.title and soup.title.string:
                    title = soup.title.string.strip()

            return banner, title
        except requests.RequestException:
            return "", ""

    def _grab_ssh_banner(self, ip: str, port: int = 22, timeout: int = 2) -> str:
        """Obtiene el banner SSH."""
        try:
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((ip, port))
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            return banner
        except (socket.timeout, ConnectionRefusedError, OSError):
            return ""

    def _check_latest_firmware(self, vendor: str, model: str) -> Optional[str]:
        """
        Busca online la ultima version del firmware.
        (Version simulada para el proyecto - en prod consultaria scraping real o API)
        """
        logger.debug(f"Buscando firmware para {vendor} {model}...")

        # Simulacion de scraping de la web del fabricante
        simulated_database = {
            "TP-Link": {
                "Archer C7": "1.0.5 Build 20201120",
                "TL-WR841N": "3.16.9 Build 150310"
            },
            "Linksys": {
                "WRT54G": "4.30.7",
                "EA7500": "2.0.8.194281"
            }
        }

        return simulated_database.get(vendor, {}).get(model)

    def scan_network(self, network_prefix: str = "192.168.1", start: int = 1, end: int = 254) -> List[Dict]:
        """
        Escanea un rango de IPs para auditar dispositivos.
        Nota: Esto es intensivo, mejor usar en background o con nmap/arp.
        """
        logger.info(f"Iniciando escaneo en {network_prefix}.{start}-{end}")
        results = []
        # En una implementacion real se usaria un ping sweep o ARP request concurrentes
        # Para evitar bloquear, solo es un esqueleto o se usara arp -a
        pass
        return results

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    crawler = FirmwareCrawler()
    # Test simple a localhost
    res = crawler.audit_device("127.0.0.1", "00:00:00:00:00:00")
    print(res)
