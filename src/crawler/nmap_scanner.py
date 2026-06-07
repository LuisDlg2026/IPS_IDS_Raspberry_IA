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
            self._original_nmap_path = self.nm._nmap_path
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
            
        # Alternar dinámicamente privilegios (sudo) a nivel de SO si el setting está activo
        if self._db:
            use_sudo = self._db.get_config("nmap_use_sudo", False, "bool")
            import sys
            import os
            
            # Si ya somos root (por ejemplo, dentro de Docker), no necesitamos el wrapper con sudo
            is_root = False
            if hasattr(os, "geteuid"):
                is_root = (os.geteuid() == 0)
                
            if use_sudo and not sys.platform.startswith("win") and not is_root:
                from pathlib import Path
                wrapper_path = Path("/tmp/nmap_sudo_wrapper")
                if self.nm._nmap_path != str(wrapper_path):
                    try:
                        with open(wrapper_path, "w") as f:
                            f.write(f"#!/bin/sh\nexec sudo {self._original_nmap_path} \"$@\"\n")
                        os.chmod(wrapper_path, 0o755)
                        self.nm._nmap_path = str(wrapper_path)
                        logger.info(f"Nmap alternado dinámicamente a modo Sudo privilegiado: {wrapper_path}")
                    except Exception as e:
                        logger.error(f"Error al crear wrapper de sudo para Nmap: {e}")
            else:
                if self.nm._nmap_path != self._original_nmap_path:
                    self.nm._nmap_path = self._original_nmap_path
                    logger.info("Nmap alternado dinámicamente a modo estándar (ejecutando con los privilegios actuales del proceso)")

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
            
            # Si Nmap no detectó nada (os_guess es None o vacío), activamos la cascada
            if not result.get("os_guess"):
                netbios_res = self.query_netbios(ip)
                if netbios_res:
                    result["os_guess"] = netbios_res["os_guess"]
                    result["vendor"] = netbios_res["vendor"]
                    if netbios_res.get("hostname") and not result.get("hostname"):
                        result["hostname"] = netbios_res["hostname"]
                    logger.info(f"Cascada activa: S.O. detectado vía NetBIOS para {ip}: OS={result['os_guess']}, Vendor={result['vendor']}, Hostname={result.get('hostname')}")
                    
            if not result.get("os_guess"):
                mdns_res = self.query_mdns(ip)
                if mdns_res:
                    result["os_guess"] = mdns_res["os_guess"]
                    result["vendor"] = mdns_res["vendor"]
                    logger.info(f"Cascada activa: S.O. detectado vía mDNS para {ip}: OS={result['os_guess']}, Vendor={result['vendor']}")
                    
            if not result.get("os_guess"):
                ssdp_res = self.query_ssdp(ip)
                if ssdp_res:
                    result["os_guess"] = ssdp_res["os_guess"]
                    result["vendor"] = ssdp_res["vendor"]
                    logger.info(f"Cascada activa: S.O. detectado vía SSDP para {ip}: OS={result['os_guess']}, Vendor={result['vendor']}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error durante escaneo Nmap a {ip}: {e}")
            return None

    def query_netbios(self, ip: str) -> Optional[Dict[str, str]]:
        """
        Realiza una consulta NetBIOS (NBNS) al puerto 137 UDP usando Scapy con payload directo
        para verificar si es un host Windows/Samba y extraer su hostname.
        """
        from scapy.all import IP, UDP, Raw, sr1
        
        logger.info(f"Iniciando cascada: Consulta NetBIOS activa a {ip}...")
        try:
            # Payload de consulta wildcard '*' de tipo STATUS (solicitar nombres NetBIOS)
            nbns_payload = b"\xa2\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
            
            pkt = IP(dst=ip)/UDP(sport=137, dport=137)/Raw(load=nbns_payload)
            ans = sr1(pkt, timeout=1.5, verbose=0)
            if ans and ans.haslayer(UDP):
                # Si nos responde al puerto 137 UDP con cualquier payload, es Windows o Samba (Linux)
                logger.info(f"Respuesta NetBIOS detectada para {ip}!")
                
                # Intentar parsear el hostname del payload de respuesta para refinar
                try:
                    raw_data = bytes(ans[Raw].load)
                    if len(raw_data) > 58:
                        num_names = raw_data[56]
                        if num_names > 0:
                            # Primer nombre en la lista (generalmente el hostname del equipo)
                            name_bytes = raw_data[57:57+15]
                            hostname = name_bytes.decode("utf-8", errors="ignore").strip()
                            if hostname:
                                logger.info(f"Nombre de host NetBIOS extraído: {hostname}")
                                return {"os_guess": "Windows", "vendor": "Microsoft Device", "hostname": hostname}
                except Exception:
                    pass
                
                return {"os_guess": "Windows", "vendor": "Microsoft Device"}
        except Exception as e:
            logger.debug(f"Error en consulta NetBIOS a {ip}: {e}")
        return None

    def query_mdns(self, ip: str) -> Optional[Dict[str, str]]:
        """
        Realiza consultas mDNS unicast al puerto 5353 del host para obtener pistas de S.O.
        """
        from scapy.all import IP, UDP, DNS, DNSQR, sr1
        
        logger.info(f"Iniciando cascada: Consulta mDNS activa a {ip}...")
        try:
            # 1. Probar consulta PTR para dispositivos Apple
            pkt_apple = IP(dst=ip)/UDP(sport=5353, dport=5353)/DNS(rd=1, qd=DNSQR(qname="_apple-mobdev2._tcp.local", qtype="PTR"))
            ans_apple = sr1(pkt_apple, timeout=1.5, verbose=0)
            if ans_apple and ans_apple.haslayer(DNS):
                return {"os_guess": "Apple iOS / macOS Device", "vendor": "Apple Inc."}
                
            # 2. Probar consulta PTR para Google Cast / Chromecast
            pkt_cast = IP(dst=ip)/UDP(sport=5353, dport=5353)/DNS(rd=1, qd=DNSQR(qname="_googlecast._tcp.local", qtype="PTR"))
            ans_cast = sr1(pkt_cast, timeout=1.5, verbose=0)
            if ans_cast and ans_cast.haslayer(DNS):
                return {"os_guess": "Android (Google Cast Device)", "vendor": "Google LLC"}
                
            # 3. Probar consulta PTR genérica de info de dispositivo
            pkt_info = IP(dst=ip)/UDP(sport=5353, dport=5353)/DNS(rd=1, qd=DNSQR(qname="_device-info._tcp.local", qtype="PTR"))
            ans_info = sr1(pkt_info, timeout=1.5, verbose=0)
            if ans_info and ans_info.haslayer(DNS):
                dns_layer = ans_info[DNS]
                for i in range(dns_layer.ancount):
                    rr_data = str(dns_layer.an[i].rdata).lower()
                    if "apple" in rr_data:
                        return {"os_guess": "Apple iOS / macOS Device", "vendor": "Apple Inc."}
                    elif "android" in rr_data:
                        return {"os_guess": "Android Device", "vendor": "Google LLC"}
                        
        except Exception as e:
            logger.debug(f"Error en consulta mDNS a {ip}: {e}")
        return None

    def query_ssdp(self, ip: str) -> Optional[Dict[str, str]]:
        """
        Realiza una consulta SSDP unicast directa al puerto 1900 del host buscando descriptores XML.
        """
        import socket
        import requests
        import re
        
        logger.info(f"Iniciando cascada: Consulta SSDP/UPnP activa a {ip}...")
        try:
            msg = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "MX: 2\r\n"
                "ST: ssdp:all\r\n\r\n"
            )
            
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.0)
            s.sendto(msg.encode("utf-8"), (ip, 1900))
            
            try:
                data, addr = s.recvfrom(2048)
                resp = data.decode("utf-8", errors="ignore")
                
                location_match = re.search(r"(?i)LOCATION:\s*([^\r\n]+)", resp)
                if location_match:
                    xml_url = location_match.group(1).strip()
                    # Descargar XML
                    r = requests.get(xml_url, timeout=2.0)
                    if r.status_code == 200:
                        xml_content = r.text
                        
                        manufacturer = None
                        model_name = None
                        os_str = None
                        
                        m_match = re.search(r"<manufacturer>(.*?)</manufacturer>", xml_content)
                        if m_match: manufacturer = m_match.group(1)
                        
                        mn_match = re.search(r"<modelName>(.*?)</modelName>", xml_content)
                        if mn_match: model_name = mn_match.group(1)
                        
                        os_match = re.search(r"<operatingSystem>(.*?)</operatingSystem>", xml_content)
                        if os_match: os_str = os_match.group(1)
                        
                        # Deducir S.O.
                        os_guess = os_str or "Linux (Embedded)"
                        vendor = manufacturer or "IoT Device"
                        
                        if model_name:
                            os_guess = f"{os_guess} ({model_name})"
                            
                        return {"os_guess": os_guess, "vendor": vendor}
            except socket.timeout:
                pass
            finally:
                s.close()
        except Exception as e:
            logger.debug(f"Error en consulta SSDP a {ip}: {e}")
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
