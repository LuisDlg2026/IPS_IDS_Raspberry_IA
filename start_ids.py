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
            
            # 1. Obtener la interfaz de captura desde la config (o usar fallback 'eth0')
            from src.config import CAPTURE_INTERFACE
            from scapy.arch import get_if_addr
            
            iface_name = CAPTURE_INTERFACE if CAPTURE_INTERFACE else "eth0"
            
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

                    # 3. Forzar despertar (ICMP Ping Sweep) nativamente desde la Pi para IoTs dormidos
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
                    for ip, mac in discovered_devices.items():
                        # Auditar el dispositivo descubierto (Firmware Crawler)
                        device_info = crawler.audit_device(ip, mac)
                        device_info["is_online"] = 1
                        device_info["risk_level"] = "low" if not device_info.get("needs_update") else "medium"
                        
                        # Guardar y generar alertas si aplican
                        alert_manager.evaluate_device(device_info)
                        discovered_count += 1
                        
                    logger.info(f"Escaneo de red completado: {discovered_count} dispositivos activos encontrados (Caché ARP + Scapy).")
                    
                except Exception as e:
                    logger.error(f"Error en descubrimiento de red: {e}")
                
                # Repetir el escaneo cada 5 minutos
                time.sleep(300)

        discovery_thread = threading.Thread(target=network_discovery_loop, daemon=True)
        discovery_thread.start()

        # 4.5 Callback de descubrimiento pasivo (Cualquier IP que envíe/reciba tráfico se añade)
        def on_flow_detected(src_ip, dst_ip):
            # FIX: Solo añadimos src_ip. Si alguien envía un paquete, sabemos que existe al 100%.
            # Si añadiéramos dst_ip, herramientas como Nmap, nuestro propio ARP o Ping Sweep 
            # inventarían 255 dispositivos fantasma (IPs escaneadas que no respondieron).
            if src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("172."): # Solo IPs locales
                # Añadir a la base de datos de forma pasiva
                db.save_device({
                    "ip": src_ip,
                    "mac": "unknown", # MAC se resolverá por ARP en el próximo escaneo
                    "vendor": "Unknown (Pasivo)",
                    "is_online": 1,
                    "risk_level": "low"
                })

        # 5. Iniciar el detector pasándole los callbacks
        detector = IDSDetector(on_alert=on_alert_detected, on_flow=on_flow_detected)
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
