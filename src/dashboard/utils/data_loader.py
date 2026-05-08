"""
Módulo para cargar datos desde la base de datos SQLite hacia Pandas DataFrames.
Utilizado por el dashboard de Streamlit para renderizar las vistas.
"""

import pandas as pd
from typing import Dict, List, Optional
import sys
from pathlib import Path
import logging

# Añadir src al path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from src.utils.storage import Database

logger = logging.getLogger(__name__)

# Instancia global (singleton) para el dashboard
_db_instance = None

def get_db() -> Database:
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance

def load_alerts(limit: int = 100, severity: Optional[str] = None) -> pd.DataFrame:
    """Carga alertas y devuelve un DataFrame."""
    db = get_db()
    alerts = db.get_alerts(limit=limit, severity=severity)
    if not alerts:
        return pd.DataFrame(columns=["id", "timestamp", "attack_type", "confidence", "severity", "src_ip", "dst_ip", "n_packets", "acknowledged"])
    
    df = pd.DataFrame(alerts)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

def load_alert_summary() -> Dict:
    """Carga resumen de alertas."""
    db = get_db()
    return db.get_alert_summary()

def load_devices(online_only: bool = False) -> pd.DataFrame:
    """Carga el inventario de dispositivos como DataFrame."""
    db = get_db()
    devices = db.get_devices(online_only=online_only)
    if not devices:
        return pd.DataFrame(columns=["mac", "ip", "vendor", "os_guess", "risk_level", "is_online", "last_seen"])
    
    df = pd.DataFrame(devices)
    df["last_seen"] = pd.to_datetime(df["last_seen"])
    return df

def load_network_stats(limit: int = 100, hours: Optional[int] = None) -> pd.DataFrame:
    """Carga métricas de red como DataFrame."""
    db = get_db()
    stats = db.get_network_stats(limit=limit, hours=hours)
    if not stats:
        return pd.DataFrame(columns=["timestamp", "bandwidth_mbps", "cpu_percent", "memory_percent", "latency_ms", "active_connections"])
    
    df = pd.DataFrame(stats)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp")
    return df

def load_system_events(limit: int = 50) -> pd.DataFrame:
    """Carga eventos del sistema."""
    db = get_db()
    events = db.get_events(limit=limit)
    if not events:
        return pd.DataFrame(columns=["timestamp", "event_type", "severity", "message"])
    
    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

def load_web_traffic(limit: int = 500) -> pd.DataFrame:
    """Carga los últimos registros de navegación web (DPI) en un DataFrame."""
    db = get_db()
    try:
        logs = db.get_web_logs(limit=limit)
    except Exception:
        logs = []
        
    if not logs:
        return pd.DataFrame(columns=["timestamp", "src_ip", "dst_ip", "protocol", "domain_url", "details"])
    
    df = pd.DataFrame(logs)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df
