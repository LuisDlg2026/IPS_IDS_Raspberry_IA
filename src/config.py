"""
Configuración central del proyecto IDS/IPS.
Todas las rutas, constantes y parámetros se definen aquí.
"""

import os
from pathlib import Path

# ─── Rutas principales ──────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent
SRC_DIR = Path(__file__).parent
DATA_DIR = PROJECT_ROOT / "data"
DATA_RAW = DATA_DIR / "raw"
DATA_PROCESSED = DATA_DIR / "processed"
DATA_MODELS = DATA_DIR / "models"
NOTEBOOKS_DIR = PROJECT_ROOT / "notebooks"
TESTS_DIR = PROJECT_ROOT / "tests"
LOG_DIR = PROJECT_ROOT / "logs"

# Crear directorios si no existen
for dir_path in [DATA_RAW, DATA_PROCESSED, DATA_MODELS, LOG_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# ─── Base de datos ──────────────────────────────────────────────
DB_PATH = DATA_DIR / "ids_ips.db"

# ─── Logging ────────────────────────────────────────────────────
LOG_FILE = LOG_DIR / "system.log"
LOG_LEVEL = os.environ.get("IDS_LOG_LEVEL", "INFO")

# ─── Captura de red ─────────────────────────────────────────────
# None = auto-detectar interfaz activa
CAPTURE_INTERFACE = os.environ.get("IDS_CAPTURE_IFACE", None)
FLOW_WINDOW_SECONDS = 10       # Ventana temporal para agrupar paquetes en flujos
PACKET_BUFFER_SIZE = 65535     # Tamaño del buffer de captura
MAX_PACKETS_PER_FLOW = 10000  # Límite de paquetes por flujo

# ─── Machine Learning ───────────────────────────────────────────
# Artefactos generados por el notebook de entrenamiento
MODEL_PATH = DATA_MODELS / "random_forest_model.joblib"
LIGHTGBM_MODEL_PATH = DATA_MODELS / "lightgbm_model.joblib"
SCALER_PATH = DATA_MODELS / "scaler.joblib"
LABEL_ENCODER_PATH = DATA_MODELS / "label_encoder.joblib"
SELECTED_FEATURES_PATH = DATA_MODELS / "selected_features.joblib"

# Modelo activo (cambiar para usar otro)
ACTIVE_MODEL = os.environ.get("IDS_MODEL", "random_forest")
MODEL_PATHS = {
    "random_forest": DATA_MODELS / "random_forest_model.joblib",
    "lightgbm": DATA_MODELS / "lightgbm_model.joblib",
    "xgboost": DATA_MODELS / "xgboost_model.joblib",
    "decision_tree": DATA_MODELS / "decision_tree_model.joblib",
    "mlp": DATA_MODELS / "mlp_model.joblib",
}

# Umbral de confianza mínimo para generar alerta
CONFIDENCE_THRESHOLD = 0.5

# ─── Dashboard ──────────────────────────────────────────────────
DASHBOARD_PORT = 8501
DASHBOARD_HOST = "0.0.0.0"

# ─── Severidad de ataques ───────────────────────────────────────
ATTACK_SEVERITY = {
    "Normal": "info",
    "Port_Scanning": "low",
    "Fingerprinting": "low",
    "Vulnerability_scanner": "medium",
    "MITM": "high",
    "DNS_Spoofing": "high",
    "Password": "medium",
    "Backdoor": "critical",
    "Ransomware": "critical",
    "SQL_injection": "high",
    "XSS": "high",
    "Uploading": "medium",
    "DDoS_TCP": "critical",
    "DDoS_UDP": "critical",
    "DDoS_ICMP": "high",
    "DDoS_HTTP": "critical",
}