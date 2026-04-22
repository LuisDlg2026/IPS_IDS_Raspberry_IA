@"
"""
Archivo de configuración del proyecto IDS/IPS.
Se usará en todos los módulos para acceder a rutas, constantes, etc.
"""

import os
from pathlib import Path

# Rutas principales
PROJECT_ROOT = Path(__file__).parent.parent
SRC_DIR = Path(__file__).parent
DATA_DIR = PROJECT_ROOT / "data"
DATA_RAW = DATA_DIR / "raw"
DATA_PROCESSED = DATA_DIR / "processed"
DATA_MODELS = DATA_DIR / "models"
NOTEBOOKS_DIR = PROJECT_ROOT / "notebooks"
TESTS_DIR = PROJECT_ROOT / "tests"

# Crear directorios si no existen
for dir_path in [DATA_RAW, DATA_PROCESSED, DATA_MODELS]:
    dir_path.mkdir(parents=True, exist_ok=True)

# Base de datos
DB_PATH = DATA_DIR / "ids_ips.db"

# Configuración de logging
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "system.log"

# Configuración de captura de red
CAPTURE_INTERFACE = None  # Se configurará según el SO
PACKET_BUFFER_SIZE = 65535
FLOW_TIMEOUT = 10  # segundos

# Configuración de ML
MODEL_PATH = DATA_MODELS / "model.pkl"
PREPROCESSOR_PATH = DATA_MODELS / "preprocessor.pkl"

# Configuración de Dashboard
DASHBOARD_PORT = 8501
DASHBOARD_HOST = "0.0.0.0"

print(f"✅ CONFIG LOADED - Project root: {PROJECT_ROOT}")
"@ | Out-File -Encoding UTF8 src/config.py