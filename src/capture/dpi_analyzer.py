"""
Deep Packet Inspection (DPI) Analyzer.

Analiza la capa de aplicación (Capa 7) de los paquetes capturados para extraer
información de navegación web, DNS, FTP y correo electrónico.
"""

import logging
import re
from typing import Dict, Optional
from scapy.all import DNSQR, TCP, UDP, Raw, IP, DHCP, BOOTP

logger = logging.getLogger(__name__)

class DPIAnalyzer:
    """
    Inspector profundo de paquetes.
    """
    
    def __init__(self, on_web_traffic=None):
        self._on_web_traffic = on_web_traffic
        
    def analyze_packet(self, packet) -> Optional[Dict]:
        """
        Analiza un paquete buscando información de Capa 7.
        Si encuentra algo relevante, llama al callback.
        """
        if not packet.haslayer(IP):
            return None
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        log_entry = None

        # 1. Analizar DNS (Capa UDP/TCP 53)
        if packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            log_entry = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": "DNS",
                "domain_url": qname,
                "details": {"type": "Query"}
            }
            
        # 1.5 Analizar DHCP (Capa UDP 67/68) para extraer nombres de dispositivo
        # 1.5 Analizar DHCP (Capa UDP 67/68) para extraer nombres de dispositivo y datos de red
        elif packet.haslayer(DHCP):
            dhcp_details = self._parse_dhcp_details(packet[DHCP], packet)
            if dhcp_details:
                hostname = dhcp_details.get("hostname")
                vendor_class = dhcp_details.get("vendor_class")
                mac = dhcp_details.get("mac")
                assigned_ip = dhcp_details.get("assigned_ip")
                requested_ip = dhcp_details.get("requested_ip")
                
                # Determinar IP para asociar al log
                dev_ip = assigned_ip or requested_ip or src_ip
                if dev_ip == "0.0.0.0" and dst_ip != "255.255.255.255":
                    dev_ip = dst_ip
                
                log_entry = {
                    "src_ip": dev_ip,
                    "dst_ip": dst_ip,
                    "protocol": "DHCP",
                    "domain_url": hostname or vendor_class or "Unknown",
                    "details": {
                        "type": "Hostname Discovery",
                        "mac": mac,
                        "hostname": hostname,
                        "vendor_class": vendor_class,
                        "requested_ip": requested_ip,
                        "assigned_ip": assigned_ip
                    }
                }

        # 2. Analizar protocolos TCP (HTTP, HTTPS, FTP, SMTP)
        elif packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            # HTTP (Puerto 80)
            if dport == 80 or sport == 80:
                http_info = self._parse_http(payload)
                if http_info:
                    log_entry = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": "HTTP",
                        "domain_url": http_info["url"],
                        "details": http_info
                    }
                    
            # HTTPS / TLS SNI (Puerto 443)
            elif dport == 443:
                sni = self._parse_tls_sni(payload)
                if sni:
                    log_entry = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": "HTTPS",
                        "domain_url": sni,
                        "details": {"type": "TLS Client Hello"}
                    }
                    
            # FTP (Puerto 21)
            elif dport == 21 or sport == 21:
                ftp_info = self._parse_ftp(payload)
                if ftp_info:
                    log_entry = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": "FTP",
                        "domain_url": ftp_info["command"],
                        "details": ftp_info
                    }
                    
            # SMTP (Puerto 25, 587)
            elif dport in [25, 587] or sport in [25, 587]:
                smtp_info = self._parse_smtp(payload)
                if smtp_info:
                    log_entry = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": "SMTP",
                        "domain_url": smtp_info["command"],
                        "details": smtp_info
                    }

        # Guardar en base de datos si hemos extraído algo
        if log_entry and self._on_web_traffic:
            try:
                self._on_web_traffic(log_entry)
            except Exception as e:
                logger.error(f"Error guardando web log: {e}")
                
        return log_entry

    def _parse_http(self, payload: bytes) -> Optional[Dict]:
        """Extrae el Host y el Path de una petición HTTP en texto plano."""
        try:
            text = payload.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            if not lines:
                return None
                
            first_line = lines[0]
            # Solo procesamos peticiones (GET, POST, etc.)
            if any(first_line.startswith(m) for m in ["GET", "POST", "PUT", "DELETE", "HEAD"]):
                parts = first_line.split(' ')
                if len(parts) >= 2:
                    method = parts[0]
                    path = parts[1]
                    
                    # Buscar el header Host:
                    host = ""
                    for line in lines[1:]:
                        if line.lower().startswith("host:"):
                            host = line.split(":", 1)[1].strip()
                            break
                    
                    url = f"{host}{path}" if host else path
                    return {
                        "method": method,
                        "host": host,
                        "path": path,
                        "url": url
                    }
        except Exception:
            pass
        return None

    def _parse_dhcp_details(self, dhcp_layer, packet) -> Optional[dict]:
        """Extrae detalles del paquete DHCP y BOOTP (Option 12 Hostname, Option 60 Vendor, MAC)."""
        try:
            details = {
                "hostname": None,
                "vendor_class": None,
                "requested_ip": None,
                "assigned_ip": None,
                "mac": None
            }
            
            # 1. Parsear opciones de DHCP
            for opt in dhcp_layer.options:
                if isinstance(opt, tuple):
                    key = opt[0]
                    val = opt[1]
                    if key == "hostname":
                        details["hostname"] = val.decode('utf-8', errors='ignore') if isinstance(val, bytes) else str(val)
                    elif key == "vendor_class_id":
                        details["vendor_class"] = val.decode('utf-8', errors='ignore') if isinstance(val, bytes) else str(val)
                    elif key == "requested_addr":
                        details["requested_ip"] = str(val)
            
            # 2. Parsear BOOTP para MAC e IP asignada
            if packet.haslayer(BOOTP):
                bootp = packet[BOOTP]
                if bootp.chaddr:
                    # chaddr es un byte string de 16 bytes. El MAC de Ethernet son los primeros 6 bytes.
                    mac_bytes = bootp.chaddr[:6]
                    details["mac"] = ":".join(f"{b:02x}" for b in mac_bytes)
                if bootp.yiaddr and bootp.yiaddr != "0.0.0.0":
                    details["assigned_ip"] = bootp.yiaddr
                    
            if details["hostname"] or details["vendor_class"] or details["mac"]:
                return details
        except Exception as e:
            logger.debug(f"Error parseando DHCP: {e}")
        return None

    def _parse_tls_sni(self, payload: bytes) -> Optional[str]:
        """
        Intenta extraer el Server Name Indication (SNI) de un paquete TLS Client Hello.
        Esta función parsea manualmente los bytes sin requerir librerías criptográficas.
        """
        try:
            # TLS Record Header
            # Byte 0: Content Type (22 = Handshake)
            # Byte 1-2: Version
            # Byte 3-4: Length
            if len(payload) < 43 or payload[0] != 0x16:
                return None
                
            # Handshake Header
            # Byte 5: Handshake Type (1 = Client Hello)
            if payload[5] != 0x01:
                return None
                
            # Saltamos Session ID, Cipher Suites, Compression Methods...
            # Esta es una heurística básica buscando la extensión SNI (0x00 0x00)
            # En un IDS de producción se usa un parser robusto como dpkt
            
            # Buscar el patrón típico de SNI: 0x00 0x00 (tipo extensión) + 2 bytes longitud
            # seguido de 0x00 (tipo list_name: host_name)
            
            # Método crudo pero rápido: buscar dominios en texto plano dentro del payload
            # que parezcan URLs (la mayoría de SNIs están expuestos así)
            text = payload.decode('utf-8', errors='ignore')
            # Buscar secuencias de caracteres imprimibles que parezcan un dominio
            match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text[43:])
            if match:
                # Comprobar si el match parece realmente un dominio (ej. descartar falsos positivos cortos)
                domain = match.group(1)
                if "." in domain and len(domain) > 4 and not domain.startswith("-"):
                    return domain
                    
        except Exception:
            pass
        return None
        
    def _parse_ftp(self, payload: bytes) -> Optional[Dict]:
        """Extrae comandos FTP en texto plano."""
        try:
            text = payload.decode('utf-8', errors='ignore').strip()
            if text.startswith("USER ") or text.startswith("PASS ") or text.startswith("RETR ") or text.startswith("STOR "):
                parts = text.split(" ", 1)
                cmd = parts[0]
                arg = parts[1] if len(parts) > 1 else ""
                # Ocultar contraseñas
                if cmd == "PASS":
                    arg = "********"
                return {
                    "command": f"{cmd} {arg}",
                    "cmd_type": cmd,
                    "arg": arg
                }
        except Exception:
            pass
        return None

    def _parse_smtp(self, payload: bytes) -> Optional[Dict]:
        """Extrae comandos SMTP en texto plano."""
        try:
            text = payload.decode('utf-8', errors='ignore').strip()
            if text.upper().startswith("MAIL FROM:") or text.upper().startswith("RCPT TO:"):
                return {
                    "command": text,
                    "type": "SMTP Control"
                }
        except Exception:
            pass
        return None
