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
from src.capture.arp_spoofer import ArpSpoofer

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

def get_default_gateway_ip() -> str:
    """Detecta dinámicamente la IP de la puerta de enlace (Router) usando Scapy."""
    try:
        from scapy.all import conf
        # conf.route.route("0.0.0.0") devuelve (interfaz, gateway, destino)
        gw = conf.route.route("0.0.0.0")[1]
        if gw and gw != "0.0.0.0":
            return gw
    except Exception as e:
        logger.warning(f"Error detectando gateway con Scapy: {e}")
        
    try:
        import struct
        import socket
        # Intentar leer desde /proc/net/route en sistemas Linux
        if os.path.exists('/proc/net/route'):
            with open('/proc/net/route', 'r') as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] == "00000000":
                        gw_hex = parts[2]
                        return socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
    except Exception as e:
        logger.warning(f"Error detectando gateway en /proc/net/route: {e}")
        
    return "192.168.1.1" # Fallback


def start_backend():
    logger.info("Iniciando motor de captura de red e inferencia ML en segundo plano...")
    try:
        # 1. Conectar a la base de datos
        db = Database()
        
        # 1.5. Preparar red para descubrimiento fresco (sin borrar histórico de seguridad)
        logger.info("Reseteando estado online de dispositivos para redescubrir red...")
        db.reset_devices_online_status()
        
        # Limpiar solo registros realmente antiguos (>30 días por defecto)
        db.cleanup()
        
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
            
            # 1. Obtener la interfaz de captura desde la base de datos (con fallback a la config/entorno)
            from src.config import CAPTURE_INTERFACE
            from scapy.arch import get_if_addr
            
            db_iface = db.get_config("capture_interface", None, "str")
            iface_name = db_iface if db_iface else (CAPTURE_INTERFACE if CAPTURE_INTERFACE else "eth0")
            
            # 2. Deducir automáticamente la subred asumiendo formato /24
            try:
                # Intenta obtener la IP actual de la Raspberry usando un socket (más fiable)
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80)) # IP Externa conocida de Google
                local_ip = s.getsockname()[0]
                s.close()
                default_target = ".".join(local_ip.split(".")[:3]) + ".0/24" 
            except Exception as e:
                logger.warning(f"No se pudo detectar IP fiable, usando red por defecto. Error: {e}")
                default_target = "192.168.1.0/24"
                
            target_ip = os.environ.get("IDS_TARGET_SUBNET", default_target)
            logger.info(f"Iniciando escaneo ARP en la red {target_ip} a través de la interfaz {iface_name}...")
            
            while True:
                try:
                    discovered_devices = {} # ip -> mac
                    
                    # 0. Añadir la(s) propia(s) IP(s) de la Raspberry Pi al mapa
                    try:
                        import socket
                        # Obtenemos el hostname local y su IP
                        host_name = socket.gethostname()
                        
                        s_local = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s_local.connect(("8.8.8.8", 80))
                        local_ip = s_local.getsockname()[0]
                        s_local.close()
                        
                        db.save_device({
                            "ip": local_ip,
                            "mac": "localhost",
                            "vendor": "Raspberry Pi (Host IDS)",
                            "is_online": 1,
                            "risk_level": "low"
                        })
                    except Exception as e:
                        pass
                        
                    # 1. Intentar recolección pasiva desde la caché ARP del sistema

                    if os.path.exists('/proc/net/arp'):
                        with open('/proc/net/arp', 'r') as f:
                            for line in f.readlines()[1:]:
                                parts = line.split()
                                if len(parts) >= 4:
                                    ip, hw_type, flags, mac = parts[:4]
                                    if mac != "00:00:00:00:00:00" and not ip.startswith("169.254"):
                                        discovered_devices[ip] = mac
                    
                    # 2. Usar scapy para enviar ARP requests (complementario)
                    arp_request = ARP(pdst=target_ip)
                    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                    packet = ether/arp_request
                    
                    # srp envia y recibe en capa 2 (MAC). Se envia desde la interfaz especificada
                    result = srp(packet, timeout=10, verbose=0, iface=iface_name)[0]
                    
                    for sent, received in result:
                        discovered_devices[received.psrc] = received.hwsrc

                    # 3. Usar nmap para hacer un Ping Sweep a toda la red (-sn)
                    # Esto es super útil para descubrir móviles en la Wi-Fi o aparatos dormidos
                    try:
                        import nmap
                        nm = nmap.PortScanner()
                        nm.scan(hosts=target_ip, arguments='-sn')
                        for host in nm.all_hosts():
                            if host not in discovered_devices:
                                # Si no tenemos su MAC, se la pedimos
                                if 'mac' in nm[host]['addresses']:
                                    discovered_devices[host] = nm[host]['addresses']['mac']
                                else:
                                    discovered_devices[host] = 'unknown'
                    except Exception as e:
                        logger.warning(f"Error en Nmap Ping Sweep: {e}")

                    # 4. Forzar despertar (ICMP Ping Sweep nativo) por si nmap falla
                    # Solo lo mandamos en background de forma rápida con ping
                    # Extraer base ip de target_ip (ej. 192.168.1.0/24 -> 192.168.1)
                    base_ip_parts = target_ip.split('/')[0].split('.')[:3]
                    base_ip_str = ".".join(base_ip_parts)
                    if base_ip_str:
                        # Lanzar comando de barrido rápido (ping a broadcast para sacudir la subred, o nmap)
                        # Muchos IoTs responden mejor a un ping dirigido a su broadcast o a toda la red con la herramienta fping o ping -b
                        # Para no bloquear, lo ejecutamos en un subproceso
                        try:
                            # Hacemos ping broadcast a la red para forzar tablas ARP
                            bcast_ip = f"{base_ip_str}.255"
                            subprocess.Popen(['ping', '-c', '2', '-b', bcast_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        except Exception:
                            pass
                        
                    # Procesar todos los dispositivos encontrados (Caché + Scapy)
                    discovered_count = 0
                    
                    # Inicializamos nmap scanner si no lo tenemos aún 
                    from src.crawler.nmap_scanner import NmapScanner
                    nmap_scanner = NmapScanner(db=db)
                    
                    for ip, mac in discovered_devices.items():
                        # Auditar el dispositivo descubierto (Firmware Crawler)
                        device_info = crawler.audit_device(ip, mac)
                        device_info["is_online"] = 1
                        device_info["risk_level"] = "low" if not device_info.get("needs_update") else "medium"
                        
                        # Escaneo profundo con Nmap (OS + puertos) de forma asíncrona o sincrona rápida
                        if db.get_config("nmap_active_scan_enabled", True, "bool"):
                            nmap_result = nmap_scanner.scan_device(ip)
                            if nmap_result:
                                if nmap_result.get("os_guess"):
                                    device_info["os_guess"] = nmap_result["os_guess"]
                                if nmap_result.get("vendor") and (not device_info.get("vendor") or device_info.get("vendor") in ("Unknown", "Unknown (Pasivo)", "Local / Random")):
                                    device_info["vendor"] = nmap_result["vendor"]
                                if nmap_result.get("open_ports"):
                                    device_info["open_ports"] = nmap_result["open_ports"]
                                if nmap_result.get("hostname") and not device_info.get("hostname"):
                                    device_info["hostname"] = nmap_result["hostname"]
                        
                        # Guardar y generar alertas si aplican
                        alert_manager.evaluate_device(device_info)
                        db.save_device(device_info)
                        discovered_count += 1
                        
                    logger.info(f"Escaneo de red completado: {discovered_count} dispositivos activos encontrados (Caché ARP + Scapy).")
                    
                except Exception as e:
                    logger.error(f"Error en descubrimiento de red: {e}")
                
                # Repetir el escaneo según la configuración (en minutos)
                arp_interval_min = db.get_config("arp_passive_scan_interval", 5, "int")
                time.sleep(arp_interval_min * 60)

        discovery_thread = threading.Thread(target=network_discovery_loop, daemon=True)
        discovery_thread.start()
        
        # 4.2 Bucle de Intercepción Activa (MITM)
        def spoofer_loop():
            from src.config import CAPTURE_INTERFACE
            db_iface = db.get_config("capture_interface", None, "str")
            spoofer_iface = db_iface if db_iface else os.environ.get("IDS_CAPTURE_IFACE", CAPTURE_INTERFACE or "eth0")
            spoofer = ArpSpoofer(interface=spoofer_iface)
            last_target = None
            last_gateway = None
            is_active = False
            
            while True:
                try:
                    # Leer de la DB el estado deseado
                    spoof_target = db.get_setting("mitm_target_ip")
                    spoof_enabled = db.get_setting("mitm_enabled") == "1"
                    
                    # Resolver dinámicamente la IP del router (gateway)
                    gateway_ip = db.get_setting("mitm_gateway_ip") or get_default_gateway_ip()
                    
                    if spoof_enabled and spoof_target:
                        if not is_active or spoof_target != last_target or gateway_ip != last_gateway:
                            if is_active:
                                spoofer.stop()
                            logger.info(f"Levantando Intercepción Activa (MITM) para {spoof_target} usando pasarela {gateway_ip}...")
                            spoofer.start(target_ip=spoof_target, gateway_ip=gateway_ip)
                            last_target = spoof_target
                            last_gateway = gateway_ip
                            is_active = True
                    else:
                        if is_active:
                            logger.info("Apagando Intercepción Activa...")
                            spoofer.stop()
                            is_active = False
                            last_target = None
                            last_gateway = None
                            
                except Exception as e:
                    logger.error(f"Error en hilo Spoofer: {e}")
                time.sleep(3) # Comprobar base de datos cada 3s

        spoofer_thread = threading.Thread(target=spoofer_loop, daemon=True)
        spoofer_thread.start()

        # 4.5 Callback de descubrimiento pasivo (Cualquier IP que envíe/reciba tráfico se añade)
        def on_flow_detected(src_ip, dst_ip):
            if src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("172."): # Solo IPs locales
                # Añadir a la base de datos de forma pasiva
                db.save_device({
                    "ip": src_ip,
                    "mac": "unknown", # MAC se resolverá por ARP en el próximo escaneo
                    "vendor": "Unknown (Pasivo)",
                    "is_online": 1,
                    "risk_level": "low"
                })
                # No encolamos Nmap aquí para no spamear por cada paquete, solo en el loop ARP
                
        # 4.6 Callback para registros web (DPI)
        def on_web_traffic_detected(log_entry):
            if log_entry.get("protocol") == "DHCP":
                # Es un evento de descubrimiento pasivo de Hostname
                details = log_entry.get("details", {})
                ip = log_entry.get("src_ip")
                mac = details.get("mac")
                hostname = details.get("hostname")
                vendor_class = details.get("vendor_class")
                
                if not ip or ip == "0.0.0.0":
                    return
                    
                os_guess = None
                vendor = "Unknown (Pasivo)"
                
                # Reglas heurísticas de coincidencia para móviles Android
                is_android = False
                if hostname and any(x in hostname.lower() for x in ["android", "galaxy", "pixel", "redmi", "xiaomi", "huawei", "oneplus"]):
                    is_android = True
                if vendor_class and "android" in vendor_class.lower():
                    is_android = True
                    
                if is_android:
                    os_guess = "Android"
                    vendor = "Android Device"
                # Reglas heurísticas para dispositivos iOS/Apple
                elif hostname and any(x in hostname.lower() for x in ["iphone", "ipad", "ipod", "apple"]):
                    os_guess = "iOS"
                    vendor = "Apple Device"
                elif hostname and "raspberry" in hostname.lower():
                    os_guess = "Linux (Raspberry Pi OS)"
                    vendor = "Raspberry Pi"
                elif hostname and (any(x in hostname.lower() for x in ["windows", "desktop-", "laptop-"]) or hostname.lower().endswith("-pc")):
                    os_guess = "Windows"
                    vendor = "Microsoft Device"
                    
                device_data = {
                    "ip": ip,
                    "mac": mac or "unknown",
                    "hostname": hostname,
                    "vendor": vendor,
                    "is_online": 1
                }
                if os_guess:
                    device_data["os_guess"] = os_guess
                    
                logger.info(f"Dispositivo interceptado vía DHCP: IP={ip}, MAC={mac}, Host={hostname}, OS={os_guess}")
                db.save_device(device_data)
            else:
                # Es tráfico real, lo guardamos en la tabla web
                db.save_web_log(log_entry)
                
                # Extraer S.O. y fabricante del User-Agent en peticiones HTTP
                if log_entry.get("protocol") == "HTTP":
                    details = log_entry.get("details", {})
                    user_agent = details.get("user_agent") if isinstance(details, dict) else None
                    if user_agent:
                        ua_lower = user_agent.lower()
                        os_guess = None
                        vendor = None
                        
                        if "android" in ua_lower:
                            os_guess = "Android"
                            vendor = "Android Device"
                        elif any(x in ua_lower for x in ["iphone", "ipad", "ipod"]):
                            os_guess = "iOS"
                            vendor = "Apple Device"
                        elif "macintosh" in ua_lower or "mac os x" in ua_lower:
                            os_guess = "macOS"
                            vendor = "Apple Device"
                        elif "windows" in ua_lower:
                            os_guess = "Windows"
                            vendor = "Microsoft Device"
                        elif "linux" in ua_lower:
                            os_guess = "Linux"
                            
                        if os_guess:
                            db.save_device({
                                "ip": log_entry.get("src_ip"),
                                "os_guess": os_guess,
                                "vendor": vendor,
                                "is_online": 1
                            })

        # 5. Iniciar el detector pasándole los callbacks
        detector = IDSDetector(on_alert=on_alert_detected, on_flow=on_flow_detected)
        detector.set_web_traffic_callback(on_web_traffic_detected)
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
