"""
Monitor de estadisticas de red del sistema.

Recopila metricas de rendimiento de red usando psutil:
  - Ancho de banda (bytes enviados/recibidos)
  - Conexiones activas
  - Latencia (ping al gateway)
  - CPU/RAM del sistema

Ejecuta en background y guarda periodicamente en SQLite.

Uso:
    from src.utils.network_stats import NetworkMonitor
    monitor = NetworkMonitor(db)
    monitor.start(interval=30)
"""

import time
import logging
import threading
import platform
import subprocess
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class NetworkMonitor:
    """
    Monitor periodico de metricas de red y sistema.

    Recopila datos cada N segundos y los persiste en SQLite
    para el dashboard y analisis historico.
    """

    def __init__(self, db=None, gateway: str = None):
        """
        Args:
            db: Instancia de Database (storage.py). Si None, solo imprime.
            gateway: IP del gateway para medir latencia.
                     Si None, intenta auto-detectar.
        """
        self._db = db
        self._gateway = gateway or self._detect_gateway()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Estado previo para calcular deltas
        self._prev_bytes_sent = 0
        self._prev_bytes_recv = 0
        self._prev_time = time.time()

        logger.info(f"NetworkMonitor inicializado (gateway={self._gateway})")

    def start(self, interval: int = 30):
        """Inicia el monitor en background."""
        if self._running:
            return

        self._running = True
        self._stop_event.clear()

        # Capturar estado inicial
        self._init_counters()

        self._thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True,
            name="NetworkMonitor"
        )
        self._thread.start()
        logger.info(f"NetworkMonitor activo (cada {interval}s)")

    def stop(self):
        """Detiene el monitor."""
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("NetworkMonitor detenido")

    def get_current_stats(self) -> Dict:
        """Obtiene una instantanea de las metricas actuales."""
        try:
            import psutil
        except ImportError:
            return {"error": "psutil no instalado"}

        now = time.time()
        elapsed = now - self._prev_time if self._prev_time else 1

        # Metricas de red
        net = psutil.net_io_counters()
        bytes_sent_delta = net.bytes_sent - self._prev_bytes_sent
        bytes_recv_delta = net.bytes_recv - self._prev_bytes_recv

        # Bandwidth en Mbps
        bandwidth_up = (bytes_sent_delta * 8 / elapsed) / 1_000_000 if elapsed > 0 else 0
        bandwidth_down = (bytes_recv_delta * 8 / elapsed) / 1_000_000 if elapsed > 0 else 0

        # Conexiones activas
        try:
            connections = len(psutil.net_connections(kind='inet'))
        except (psutil.AccessDenied, PermissionError):
            connections = 0

        # Sistema
        cpu = psutil.cpu_percent(interval=0)
        memory = psutil.virtual_memory().percent

        # Latencia
        latency = self._measure_latency()

        # Actualizar estado previo
        self._prev_bytes_sent = net.bytes_sent
        self._prev_bytes_recv = net.bytes_recv
        self._prev_time = now

        return {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "bytes_sent_delta": bytes_sent_delta,
            "bytes_recv_delta": bytes_recv_delta,
            "bandwidth_up_mbps": round(bandwidth_up, 2),
            "bandwidth_down_mbps": round(bandwidth_down, 2),
            "bandwidth_mbps": round(bandwidth_up + bandwidth_down, 2),
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv,
            "active_connections": connections,
            "cpu_percent": cpu,
            "memory_percent": memory,
            "latency_ms": latency,
        }

    def _monitor_loop(self, interval: int):
        """Loop de monitoreo periodico."""
        while not self._stop_event.is_set():
            try:
                stats = self.get_current_stats()

                if self._db:
                    self._db.save_network_stats(stats)

                logger.debug(
                    f"Net: {stats.get('bandwidth_down_mbps',0):.1f}Mbps down, "
                    f"CPU: {stats.get('cpu_percent',0):.0f}%, "
                    f"Latencia: {stats.get('latency_ms','N/A')}ms"
                )

            except Exception as e:
                logger.error(f"Error en NetworkMonitor: {e}")

            self._stop_event.wait(timeout=interval)

    def _init_counters(self):
        """Inicializa contadores de red."""
        try:
            import psutil
            net = psutil.net_io_counters()
            self._prev_bytes_sent = net.bytes_sent
            self._prev_bytes_recv = net.bytes_recv
            self._prev_time = time.time()
        except ImportError:
            pass

    def _measure_latency(self) -> Optional[float]:
        """Mide latencia al gateway con ping."""
        if not self._gateway:
            return None
        try:
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", self._gateway]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", self._gateway]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=3
            )

            if result.returncode == 0:
                output = result.stdout
                # Parsear "time=Xms" o "tiempo=Xms"
                for token in output.split():
                    if "time=" in token.lower() or "tiempo=" in token.lower():
                        val = token.split("=")[1].replace("ms", "").replace("ms", "")
                        return round(float(val), 1)

                # Windows en espanol: "Respuesta desde X: bytes=32 tiempo=1ms TTL=64"
                if "tiempo=" in output:
                    idx = output.index("tiempo=")
                    val_str = output[idx+7:].split("m")[0]
                    return round(float(val_str), 1)
            return None
        except Exception:
            return None

    def _detect_gateway(self) -> str:
        """Auto-detecta el gateway por defecto."""
        try:
            system = platform.system().lower()
            if system == "windows":
                result = subprocess.run(
                    ["powershell", "-Command",
                     "(Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    gw = result.stdout.strip().split('\n')[0].strip()
                    if gw:
                        return gw
            else:
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    parts = result.stdout.split()
                    if "via" in parts:
                        return parts[parts.index("via") + 1]
        except Exception:
            pass

        return "8.8.8.8"  # Fallback: Google DNS
