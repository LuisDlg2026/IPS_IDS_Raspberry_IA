"""
Detector: orquestador principal del IDS/IPS.

Conecta los tres módulos del pipeline:
    Captura → Features → Inferencia → Alerta

Uso:
    from src.detection.detector import IDSDetector
    detector = IDSDetector()
    detector.start()    # Inicia captura + detección
    detector.stop()     # Detiene todo
    detector.get_alerts()  # Obtiene alertas recientes
"""

import logging
import time
import threading
from collections import deque
from typing import Dict, List, Optional, Callable
from datetime import datetime

logger = logging.getLogger(__name__)


class Alert:
    """Representa una alerta de seguridad generada por el IDS."""

    def __init__(self, prediction: str, confidence: float, severity: str,
                 flow_key: str, src_ip: str, dst_ip: str, details: dict):
        self.id = f"ALERT-{int(time.time()*1000)}"
        self.timestamp = datetime.now()
        self.prediction = prediction
        self.confidence = confidence
        self.severity = severity
        self.flow_key = flow_key
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.details = details
        self.acknowledged = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "attack_type": self.prediction,
            "confidence": self.confidence,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "flow_key": self.flow_key,
            "acknowledged": self.acknowledged,
        }

    def __repr__(self):
        return (f"Alert({self.prediction}, confidence={self.confidence:.2%}, "
                f"severity={self.severity}, {self.src_ip}->{self.dst_ip})")


class IDSDetector:
    """
    Orquestador del sistema IDS/IPS.

    Pipeline: Captura → Agregación por flujo → Extracción features →
              Inferencia ML → Generación de alertas

    Funciona en modo ventana temporal: cada N segundos, procesa todos
    los flujos acumulados, genera predicciones y crea alertas.
    """

    def __init__(
        self,
        model_name: str = None,
        interface: str = None,
        window_seconds: float = None,
        confidence_threshold: float = None,
        on_alert: Optional[Callable[[Alert], None]] = None,
    ):
        """
        Args:
            model_name: Modelo ML a usar (None = config default)
            interface: Interfaz de red (None = auto-detect)
            window_seconds: Ventana temporal para agrupar flujos
            confidence_threshold: Umbral mínimo de confianza para alertar
            on_alert: Callback cuando se genera una alerta
        """
        from src.config import FLOW_WINDOW_SECONDS, CONFIDENCE_THRESHOLD

        self._window_seconds = window_seconds or FLOW_WINDOW_SECONDS
        self._confidence_threshold = confidence_threshold or CONFIDENCE_THRESHOLD
        self._on_alert_callback = on_alert

        # Inicializar componentes del pipeline
        from src.ml.inference import InferenceEngine
        from src.capture.capture import PacketCapture
        from src.capture.features_adapter import FlowAggregator

        self._engine = InferenceEngine(model_name=model_name)
        self._aggregator = FlowAggregator()
        self._capture = PacketCapture(
            interface=interface,
            packet_callback=self._on_packet
        )

        # Alertas
        self._alerts: deque = deque(maxlen=10000)
        self._alert_counts: Dict[str, int] = {}

        # Estado
        self._running = False
        self._analysis_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Estadísticas
        self._stats = {
            "windows_processed": 0,
            "flows_analyzed": 0,
            "attacks_detected": 0,
            "normal_flows": 0,
            "start_time": None,
        }

        logger.info(
            f"IDSDetector inicializado: "
            f"modelo={self._engine.model_name}, "
            f"ventana={self._window_seconds}s, "
            f"umbral={self._confidence_threshold}"
        )

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def stats(self) -> dict:
        stats = {**self._stats, **self._engine.stats, **self._capture.stats}
        if stats.get("start_time"):
            stats["uptime_seconds"] = round(time.time() - stats["start_time"], 1)
        return stats

    def start(self):
        """Inicia el pipeline completo: captura + análisis periódico."""
        if self._running:
            logger.warning("El detector ya está en ejecución")
            return

        self._running = True
        self._stop_event.clear()
        self._stats["start_time"] = time.time()

        # Iniciar captura de paquetes
        self._capture.start()

        # Iniciar thread de análisis periódico
        self._analysis_thread = threading.Thread(
            target=self._analysis_loop,
            daemon=True,
            name="IDSAnalysis"
        )
        self._analysis_thread.start()

        logger.info(f"🟢 IDS/IPS activo — analizando cada {self._window_seconds}s")

    def stop(self):
        """Detiene todo el pipeline."""
        if not self._running:
            return

        logger.info("🔴 Deteniendo IDS/IPS...")
        self._running = False
        self._stop_event.set()

        self._capture.stop()

        if self._analysis_thread and self._analysis_thread.is_alive():
            self._analysis_thread.join(timeout=10)

        logger.info(f"IDS/IPS detenido. Stats: {self.stats}")

    def get_alerts(self, limit: int = 100, severity: str = None) -> List[dict]:
        """
        Obtiene las alertas más recientes.

        Args:
            limit: Número máximo de alertas a devolver
            severity: Filtrar por severidad ('low', 'medium', 'high', 'critical')
        """
        alerts = list(self._alerts)
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        return [a.to_dict() for a in alerts[-limit:]]

    def get_alert_summary(self) -> dict:
        """Resumen de alertas por tipo y severidad."""
        summary = {
            "total": len(self._alerts),
            "by_type": {},
            "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
        }
        for alert in self._alerts:
            summary["by_type"][alert.prediction] = \
                summary["by_type"].get(alert.prediction, 0) + 1
            if alert.severity in summary["by_severity"]:
                summary["by_severity"][alert.severity] += 1
        return summary

    def _on_packet(self, packet):
        """Callback para cada paquete capturado — lo añade al agregador."""
        self._aggregator.add_packet(packet)

    def _analysis_loop(self):
        """
        Loop de análisis periódico.

        Cada ventana temporal:
        1. Obtiene features de todos los flujos acumulados
        2. Hace predicción con el modelo ML
        3. Genera alertas si se detectan ataques
        4. Limpia el agregador
        """
        while not self._stop_event.is_set():
            # Esperar la ventana temporal
            self._stop_event.wait(timeout=self._window_seconds)
            if self._stop_event.is_set():
                break

            try:
                self._process_window()
            except Exception as e:
                logger.error(f"Error en análisis: {e}")

    def _process_window(self):
        """Procesa una ventana temporal de flujos."""
        flows = self._aggregator.get_all_flow_features()
        self._aggregator.clear()

        if not flows:
            return

        self._stats["windows_processed"] += 1
        self._stats["flows_analyzed"] += len(flows)

        for flow_data in flows:
            features = flow_data["features"]
            flow_key = flow_data["flow_key"]
            src_ip = flow_data["src_ip"]
            dst_ip = flow_data["dst_ip"]

            # Predicción
            result = self._engine.predict(features)

            if result["is_attack"] and result["confidence"] >= self._confidence_threshold:
                self._stats["attacks_detected"] += 1

                alert = Alert(
                    prediction=result["prediction"],
                    confidence=result["confidence"],
                    severity=result["severity"],
                    flow_key=flow_key,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    details={
                        "n_packets": flow_data["n_packets"],
                        "inference_ms": result["inference_ms"],
                        "probabilities": result.get("probabilities", {}),
                    }
                )
                self._alerts.append(alert)

                logger.warning(f"🚨 {alert}")

                # Callback externo
                if self._on_alert_callback:
                    try:
                        self._on_alert_callback(alert)
                    except Exception as e:
                        logger.error(f"Error en callback de alerta: {e}")
            else:
                self._stats["normal_flows"] += 1

        n_attacks = sum(1 for f in flows
                        if self._engine.predict(f["features"])["is_attack"])
        logger.info(
            f"Ventana procesada: {len(flows)} flujos, "
            f"{n_attacks} ataques detectados"
        )


# ─── CLI para pruebas ───────────────────────────────────────────
if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%H:%M:%S"
    )

    print("=" * 60)
    print("TEST: IDS/IPS Detector (30 segundos)")
    print("=" * 60)

    def on_alert(alert):
        print(f"\n  🚨 ALERTA: {alert.prediction} "
              f"({alert.confidence:.1%}) "
              f"{alert.src_ip} → {alert.dst_ip}")

    detector = IDSDetector(on_alert=on_alert)
    print(f"Modelo: {detector._engine.model_name}")
    print(f"Ventana: {detector._window_seconds}s")
    print(f"Interfaz: {detector._capture._interface}")

    detector.start()

    try:
        while True:
            time.sleep(10)
            stats = detector.stats
            print(f"\n📊 Paquetes: {stats.get('packets_captured', 0)}, "
                  f"Flujos: {stats.get('flows_analyzed', 0)}, "
                  f"Ataques: {stats.get('attacks_detected', 0)}")
    except KeyboardInterrupt:
        print("\nDeteniendo...")

    detector.stop()
    print(f"\nResumen final: {detector.get_alert_summary()}")
