"""
Módulo de captura de tráfico de red en tiempo real.

Usa scapy para sniffar paquetes en una interfaz de red y los envía
al FlowAggregator para extraer features.

Uso:
    from src.capture.capture import PacketCapture
    capture = PacketCapture(interface="eth0")
    capture.start()  # Inicia captura en background
    capture.stop()   # Detiene captura
"""

import logging
import threading
import time
from typing import Callable, Optional, List
from collections import deque

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Sniffer de paquetes de red con scapy.

    Captura paquetes en una interfaz de red y los entrega a un callback
    para procesamiento (típicamente el FlowAggregator).

    Características:
    - Ejecución en thread separado (no bloquea)
    - Control start/stop
    - Estadísticas de captura
    - Buffer circular de últimos N paquetes para debug
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        packet_callback: Optional[Callable] = None,
        bpf_filter: str = "",
        buffer_size: int = 1000,
    ):
        """
        Args:
            interface: Interfaz de red (None = auto-detectar)
            packet_callback: Función llamada para cada paquete capturado
            bpf_filter: Filtro BPF (ej: "tcp port 80")
            buffer_size: Tamaño del buffer circular de debug
        """
        from src.config import CAPTURE_INTERFACE

        self._interface = interface or CAPTURE_INTERFACE
        self._callback = packet_callback
        self._bpf_filter = bpf_filter
        self._buffer = deque(maxlen=buffer_size)

        # Estado
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Estadísticas
        self._stats = {
            "packets_captured": 0,
            "packets_processed": 0,
            "packets_dropped": 0,
            "start_time": None,
            "errors": 0,
        }

        # Auto-detectar interfaz si no se especificó
        if self._interface is None:
            self._interface = self._detect_interface()

        logger.info(f"PacketCapture inicializado: interface={self._interface}")

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def stats(self) -> dict:
        stats = self._stats.copy()
        if stats["start_time"]:
            stats["uptime_seconds"] = round(time.time() - stats["start_time"], 1)
            elapsed = stats["uptime_seconds"]
            if elapsed > 0:
                stats["packets_per_second"] = round(
                    stats["packets_captured"] / elapsed, 1
                )
        return stats

    def start(self):
        """Inicia la captura de paquetes en un thread separado."""
        if self._running:
            logger.warning("La captura ya está en ejecución")
            return

        self._stop_event.clear()
        self._running = True
        self._stats["start_time"] = time.time()

        self._thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="PacketCapture"
        )
        self._thread.start()
        logger.info(f"🟢 Captura iniciada en {self._interface}")

    def stop(self):
        """Detiene la captura de paquetes."""
        if not self._running:
            return

        logger.info("🔴 Deteniendo captura...")
        self._stop_event.set()
        self._running = False

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

        logger.info(f"Captura detenida. Stats: {self.stats}")

    def _capture_loop(self):
        """Loop principal de captura (ejecuta en thread)."""
        try:
            from scapy.all import sniff

            logger.info(
                f"Iniciando sniff en {self._interface} "
                f"(filtro: '{self._bpf_filter or 'ninguno'}')"
            )

            sniff(
                iface=self._interface,
                prn=self._process_packet,
                filter=self._bpf_filter,
                store=False,  # No almacenar en memoria (eficiente)
                stop_filter=lambda _: self._stop_event.is_set(),
                promisc=True  # Forzar modo promiscuo para esuchar a terceros
            )

        except PermissionError:
            logger.error(
                "❌ Sin permisos para capturar. "
                "Ejecutar como administrador/root o con cap_net_raw"
            )
            self._running = False
        except Exception as e:
            logger.error(f"❌ Error en captura: {e}")
            self._stats["errors"] += 1
            self._running = False

    def _process_packet(self, packet):
        """Callback interno para cada paquete capturado."""
        self._stats["packets_captured"] += 1
        self._buffer.append(packet)

        if self._callback:
            try:
                self._callback(packet)
                self._stats["packets_processed"] += 1
            except Exception as e:
                self._stats["packets_dropped"] += 1
                logger.debug(f"Error procesando paquete: {e}")

    def get_recent_packets(self, n: int = 10) -> list:
        """Retorna los últimos N paquetes capturados (para debug)."""
        return list(self._buffer)[-n:]

    def _detect_interface(self) -> str:
        """Auto-detecta la interfaz de red activa."""
        import platform

        system = platform.system().lower()

        try:
            from scapy.all import get_if_list, conf
            interfaces = get_if_list()

            # Filtrar interfaces comunes
            if system == "windows":
                # En Windows, scapy usa nombres largos
                # Intentar la interfaz por defecto de scapy
                default = conf.iface
                if default:
                    logger.info(f"Interfaz auto-detectada (Windows): {default}")
                    return str(default)
            else:
                # Linux/Mac: preferir eth0 > wlan0 > cualquiera
                for preferred in ["eth0", "ens33", "enp0s3", "wlan0", "en0"]:
                    if preferred in interfaces:
                        logger.info(f"Interfaz auto-detectada: {preferred}")
                        return preferred

            # Fallback: primera interfaz no-loopback
            for iface in interfaces:
                if iface not in ("lo", "lo0"):
                    logger.info(f"Interfaz fallback: {iface}")
                    return iface

        except Exception as e:
            logger.warning(f"Error detectando interfaz: {e}")

        # Último recurso
        default = "eth0" if system == "linux" else "Wi-Fi"
        logger.warning(f"Usando interfaz por defecto: {default}")
        return default


# ─── CLI para pruebas ───────────────────────────────────────────
if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    print("=" * 60)
    print("TEST: Captura de paquetes (10 segundos)")
    print("=" * 60)

    def on_packet(pkt):
        from scapy.all import IP
        if pkt.haslayer(IP):
            print(f"  {pkt[IP].src} -> {pkt[IP].dst} ({len(pkt)} bytes)")

    capture = PacketCapture(packet_callback=on_packet)
    print(f"Interfaz: {capture._interface}")

    capture.start()
    try:
        time.sleep(10)
    except KeyboardInterrupt:
        pass
    capture.stop()

    print(f"\nEstadísticas: {capture.stats}")
