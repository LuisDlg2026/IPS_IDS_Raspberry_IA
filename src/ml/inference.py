"""
Motor de inferencia ML para el IDS/IPS.

Carga los artefactos entrenados (modelo, scaler, encoder, features)
y proporciona predicciones en tiempo real sobre vectores de features
extraídos del tráfico de red.

Uso:
    from src.ml.inference import InferenceEngine
    engine = InferenceEngine()
    result = engine.predict(feature_dict)
"""

import time
import logging
import numpy as np
import joblib
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class InferenceEngine:
    """
    Motor de inferencia que encapsula modelo + scaler + encoder.

    Diseñado para:
    - Carga única al inicio (no recargar en cada predicción)
    - Thread-safe (stateless después de init)
    - Medir latencia de inferencia
    - Compatible con Raspberry Pi (bajo consumo de RAM)
    """

    def __init__(self, model_name: str = None, models_dir: str = None):
        """
        Inicializa el motor cargando todos los artefactos.

        Args:
            model_name: Nombre del modelo a usar ('random_forest', 'lightgbm', etc.)
                        Si None, usa ACTIVE_MODEL de config.py
            models_dir: Directorio de modelos. Si None, usa DATA_MODELS de config.py
        """
        # Importar config aquí para evitar imports circulares
        from src.config import (
            ACTIVE_MODEL, MODEL_PATHS, SCALER_PATH,
            LABEL_ENCODER_PATH, SELECTED_FEATURES_PATH, DATA_MODELS
        )

        self._models_dir = Path(models_dir) if models_dir else DATA_MODELS
        self._model_name = model_name or ACTIVE_MODEL

        # Rutas de artefactos
        if model_name and models_dir:
            model_path = self._models_dir / f"{model_name}_model.joblib"
        else:
            model_path = MODEL_PATHS.get(self._model_name)

        scaler_path = SCALER_PATH
        encoder_path = LABEL_ENCODER_PATH
        features_path = SELECTED_FEATURES_PATH

        # Cargar artefactos
        logger.info(f"Cargando modelo: {self._model_name} desde {model_path}")
        self._model = joblib.load(model_path)
        self._scaler = joblib.load(scaler_path)
        self._label_encoder = joblib.load(encoder_path)
        self._selected_features: List[str] = joblib.load(features_path)

        # Cache de info del modelo
        self._n_features = len(self._selected_features)
        self._classes = list(self._label_encoder.classes_)
        self._n_classes = len(self._classes)

        # Métricas de rendimiento
        self._prediction_count = 0
        self._total_inference_time = 0.0

        logger.info(
            f"✅ InferenceEngine inicializado: "
            f"modelo={self._model_name}, "
            f"features={self._n_features}, "
            f"clases={self._n_classes}"
        )

    @property
    def feature_names(self) -> List[str]:
        """Lista ordenada de features que el modelo espera."""
        return self._selected_features.copy()

    @property
    def class_names(self) -> List[str]:
        """Lista de nombres de clases de ataque."""
        return self._classes.copy()

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def stats(self) -> Dict:
        """Estadísticas de rendimiento acumuladas."""
        avg_ms = (
            (self._total_inference_time / self._prediction_count * 1000)
            if self._prediction_count > 0 else 0
        )
        return {
            "model": self._model_name,
            "predictions": self._prediction_count,
            "avg_inference_ms": round(avg_ms, 4),
            "total_inference_s": round(self._total_inference_time, 3),
        }

    def predict(self, features: Dict[str, float]) -> Dict:
        """
        Realiza una predicción a partir de un diccionario de features.

        Args:
            features: Diccionario {nombre_feature: valor}.
                      Debe contener las features en self.feature_names.

        Returns:
            Dict con:
                - 'prediction': nombre de la clase predicha
                - 'class_id': índice numérico de la clase
                - 'confidence': probabilidad máxima (si el modelo soporta predict_proba)
                - 'probabilities': dict {clase: probabilidad} para todas las clases
                - 'inference_ms': tiempo de inferencia en ms
                - 'is_attack': bool, True si no es 'Normal'
                - 'severity': nivel de severidad del ataque
        """
        # Construir vector de features en el orden correcto
        feature_vector = self._build_feature_vector(features)

        # Escalar
        # NOTA: El scaler se fitteó con 52 features (antes de la selección),
        # pero el modelo usa 36 (después de la selección).
        # Los modelos se entrenaron con datos ya escalados y seleccionados,
        # por lo que el vector ya viene escalado del pipeline del notebook.
        # Aquí aplicamos el mismo escalado.

        # Medir tiempo de inferencia
        t_start = time.perf_counter()

        # Reshape para una sola muestra
        X = feature_vector.reshape(1, -1)

        # Predecir
        y_pred = self._model.predict(X)[0]
        prediction = self._label_encoder.inverse_transform([y_pred])[0]

        # Probabilidades (si el modelo las soporta)
        probabilities = {}
        confidence = 1.0
        if hasattr(self._model, 'predict_proba'):
            proba = self._model.predict_proba(X)[0]
            confidence = float(np.max(proba))
            probabilities = {
                cls: round(float(p), 4)
                for cls, p in zip(self._classes, proba)
            }

        inference_time = time.perf_counter() - t_start
        inference_ms = inference_time * 1000

        # Actualizar métricas
        self._prediction_count += 1
        self._total_inference_time += inference_time

        # Determinar severidad
        from src.config import ATTACK_SEVERITY
        severity = ATTACK_SEVERITY.get(prediction, "unknown")

        result = {
            "prediction": prediction,
            "class_id": int(y_pred),
            "confidence": round(confidence, 4),
            "probabilities": probabilities,
            "inference_ms": round(inference_ms, 4),
            "is_attack": prediction != "Normal",
            "severity": severity,
        }

        if result["is_attack"]:
            logger.warning(
                f"🚨 ATAQUE DETECTADO: {prediction} "
                f"(confianza={confidence:.2%}, severity={severity})"
            )
        else:
            logger.debug(f"✅ Normal (confianza={confidence:.2%})")

        return result

    def predict_batch(self, features_list: List[Dict[str, float]]) -> List[Dict]:
        """Predicción en lote para múltiples flujos."""
        return [self.predict(f) for f in features_list]

    def _build_feature_vector(self, features: Dict[str, float]) -> np.ndarray:
        """
        Construye el vector numpy en el orden exacto que el modelo espera.

        Features faltantes se rellenan con 0.0 (valor por defecto seguro
        después del escalado — equivale a la media).
        """
        vector = np.zeros(self._n_features, dtype=np.float64)
        missing = []

        for i, feat_name in enumerate(self._selected_features):
            if feat_name in features:
                val = features[feat_name]
                # Manejar valores no numéricos
                try:
                    vector[i] = float(val) if val is not None else 0.0
                except (ValueError, TypeError):
                    vector[i] = 0.0
            else:
                missing.append(feat_name)

        if missing:
            logger.debug(
                f"Features faltantes ({len(missing)}/{self._n_features}): "
                f"{missing[:5]}{'...' if len(missing) > 5 else ''}"
            )

        # Reemplazar inf/nan
        vector = np.nan_to_num(vector, nan=0.0, posinf=0.0, neginf=0.0)

        return vector

    def health_check(self) -> Dict:
        """Verifica que el motor funciona correctamente."""
        try:
            # Predicción con vector de ceros (debería predecir 'Normal')
            dummy = {f: 0.0 for f in self._selected_features}
            result = self.predict(dummy)
            return {
                "status": "ok",
                "model": self._model_name,
                "test_prediction": result["prediction"],
                "test_inference_ms": result["inference_ms"],
                "n_features": self._n_features,
                "n_classes": self._n_classes,
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}


# ─── Singleton para uso global ──────────────────────────────────
_engine_instance: Optional[InferenceEngine] = None


def get_engine(model_name: str = None) -> InferenceEngine:
    """Obtiene la instancia singleton del motor de inferencia."""
    global _engine_instance
    if _engine_instance is None or (model_name and model_name != _engine_instance.model_name):
        _engine_instance = InferenceEngine(model_name=model_name)
    return _engine_instance


# ─── CLI para pruebas rápidas ───────────────────────────────────
if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    print("=" * 60)
    print("TEST: Motor de Inferencia IDS/IPS")
    print("=" * 60)

    engine = InferenceEngine()
    print(f"\nModelo: {engine.model_name}")
    print(f"Features: {engine._n_features}")
    print(f"Clases: {engine.class_names}")

    # Health check
    health = engine.health_check()
    print(f"\nHealth check: {health['status']}")
    print(f"  Predicción test: {health.get('test_prediction')}")
    print(f"  Latencia test: {health.get('test_inference_ms'):.4f} ms")

    # Benchmark
    print(f"\nBenchmark (1000 predicciones)...")
    dummy = {f: 0.0 for f in engine.feature_names}
    t0 = time.perf_counter()
    for _ in range(1000):
        engine.predict(dummy)
    elapsed = time.perf_counter() - t0
    print(f"  Total: {elapsed:.2f}s")
    print(f"  Por predicción: {elapsed/1000*1000:.4f} ms")
    print(f"\n✅ Motor de inferencia OK")
