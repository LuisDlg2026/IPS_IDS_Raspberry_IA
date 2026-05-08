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
        elif packet.haslayer(DHCP):
            hostname = self._parse_dhcp_hostname(packet[DHCP])
            if hostname:
                # Modificamos log_entry como tipo "Device_Name" para que el orquestador
                # sepa que esto es info pasiva del dispositivo y no "navegación"
                log_entry = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": "DHCP",
                    "domain_url": hostname,
                    "details": {"type": "Hostname Discovery"}
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

    def _parse_dhcp_hostname(self, dhcp_layer) -> Optional[str]:
        """Extrae el Hostname de las opciones DHCP (Opción 12)."""
        try:
            for opt in dhcp_layer.options:
                if isinstance(opt, tuple) and opt[0] == "hostname":
                    return opt[1].decode('utf-8', errors='ignore')
        except Exception:
            pass
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
