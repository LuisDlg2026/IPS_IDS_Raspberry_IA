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

def load_alerts(limit: int = 100, severity: Optional[str] = None,
                since: Optional[str] = None) -> pd.DataFrame:
    """Carga alertas y devuelve un DataFrame.
    
    Args:
        limit: Número máximo de alertas a devolver.
        severity: Filtrar por severidad (optional).
        since: Timestamp ISO para filtro temporal (optional).
    """
    db = get_db()
    alerts = db.get_alerts(limit=limit, severity=severity, since=since)
    if not alerts:
        return pd.DataFrame(columns=["id", "timestamp", "attack_type", "confidence",
                                     "severity", "src_ip", "dst_ip", "n_packets",
                                     "inference_ms", "acknowledged"])
    
    df = pd.DataFrame(alerts)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

def load_alert_summary() -> Dict:
    """Carga resumen de alertas."""
    db = get_db()
    return db.get_alert_summary()

def load_alerts_paged(limit: int = 50, offset: int = 0,
                      severities: Optional[List[str]] = None,
                      attack_type: Optional[str] = None,
                      src_ip: Optional[str] = None,
                      since: Optional[str] = None,
                      until: Optional[str] = None) -> pd.DataFrame:
    """Carga alertas paginadas y filtradas en un DataFrame."""
    db = get_db()
    alerts = db.get_alerts_paged(limit=limit, offset=offset, severities=severities,
                                 attack_type=attack_type, src_ip=src_ip,
                                 since=since, until=until)
    if not alerts:
        return pd.DataFrame(columns=["id", "timestamp", "attack_type", "confidence",
                                     "severity", "src_ip", "dst_ip", "flow_key",
                                     "n_packets", "inference_ms", "acknowledged"])
    
    df = pd.DataFrame(alerts)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

def load_alerts_summary_filtered(severities: Optional[List[str]] = None,
                                 attack_type: Optional[str] = None,
                                 src_ip: Optional[str] = None,
                                 since: Optional[str] = None,
                                 until: Optional[str] = None) -> Dict:
    """Carga el resumen de métricas para un conjunto de filtros activos."""
    db = get_db()
    return db.get_alerts_summary_filtered(severities=severities, attack_type=attack_type,
                                          src_ip=src_ip, since=since, until=until)

def load_alerts_filtered(severities: Optional[List[str]] = None,
                         attack_type: Optional[str] = None,
                         src_ip: Optional[str] = None,
                         since: Optional[str] = None,
                         until: Optional[str] = None) -> pd.DataFrame:
    """Carga todas las alertas filtradas sin paginación (para exportar a CSV)."""
    db = get_db()
    alerts = db.get_alerts_filtered(severities=severities, attack_type=attack_type,
                                     src_ip=src_ip, since=since, until=until)
    if not alerts:
        return pd.DataFrame(columns=["id", "timestamp", "attack_type", "confidence",
                                     "severity", "src_ip", "dst_ip", "flow_key",
                                     "n_packets", "inference_ms", "acknowledged"])
    
    df = pd.DataFrame(alerts)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

def load_devices(online_only: bool = False) -> pd.DataFrame:
    """Carga el inventario de dispositivos como DataFrame."""
    db = get_db()
    devices = db.get_devices(online_only=online_only)
    if not devices:
        return pd.DataFrame(columns=["mac", "ip", "vendor", "os_guess", "risk_level", "is_online", "last_seen"])
    
    df = pd.DataFrame(devices)
    df["last_seen"] = pd.to_datetime(df["last_seen"])
    
    # Limpiar nulos para evitar visualizaciones 'nan' o 'None' en el dashboard
    for col in ["hostname", "vendor", "os_guess", "notes"]:
        if col in df.columns:
            df[col] = df[col].apply(lambda x: None if pd.isna(x) or str(x).strip().lower() in ("nan", "none", "") else x)
            
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


def load_active_device_count() -> int:
    """Devuelve el número de dispositivos activos (online) en la red."""
    db = get_db()
    devices = db.get_devices(online_only=True)
    return len(devices)


def load_avg_inference_latency(hours: int = 24) -> float:
    """Calcula la latencia media de inferencia (ms) a partir de la tabla alerts.
    
    Usa el campo inference_ms de las alertas generadas en las últimas `hours` horas.
    Devuelve 0.0 si no hay datos.
    """
    from datetime import datetime, timedelta
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    df = load_alerts(limit=10000, since=since)
    if df.empty or "inference_ms" not in df.columns:
        return 0.0
    valid = df["inference_ms"].dropna()
    return float(valid.mean()) if len(valid) > 0 else 0.0

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

def load_web_traffic_filtered(protocol: str = None, hours: int = 24) -> pd.DataFrame:
    """Carga tramas de navegación web aplicando filtros de protocolo y ventana temporal."""
    db = get_db()
    with db._lock:
        conn = db._get_conn()
        try:
            query = "SELECT * FROM web_traffic WHERE 1=1"
            params = []
            if protocol:
                query += " AND protocol = ?"
                params.append(protocol)
            if hours:
                query += " AND timestamp >= datetime('now', '-' || ? || ' hours', 'localtime')"
                params.append(str(hours))
            query += " ORDER BY timestamp DESC"
            rows = conn.execute(query, params).fetchall()
            df = pd.DataFrame([dict(r) for r in rows])
            if df.empty:
                return pd.DataFrame(columns=["id", "timestamp", "src_ip", "dst_ip", "protocol", "domain_url", "details"])
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            return df
        finally:
            conn.close()

def load_dns_web_metrics() -> Dict:
    """Calcula y devuelve métricas avanzadas sobre el tráfico de capa de aplicación (DNS y HTTP)."""
    db = get_db()
    with db._lock:
        conn = db._get_conn()
        try:
            # 1. Consultas DNS únicas en las últimas 24h
            query_dns_unique = """
                SELECT COUNT(DISTINCT domain_url) 
                FROM web_traffic 
                WHERE protocol = 'DNS' AND timestamp >= datetime('now', '-24 hours', 'localtime')
            """
            dns_unique_24h = conn.execute(query_dns_unique).fetchone()[0] or 0

            # 2. Dominios nuevos en las últimas 24h (no vistos en los 7 días anteriores, i.e., 8 días atrás hasta hace 24h)
            query_dns_new = """
                SELECT COUNT(DISTINCT domain_url) 
                FROM web_traffic 
                WHERE protocol = 'DNS' AND timestamp >= datetime('now', '-24 hours', 'localtime')
                AND domain_url NOT IN (
                    SELECT DISTINCT domain_url 
                    FROM web_traffic 
                    WHERE protocol = 'DNS' 
                    AND timestamp >= datetime('now', '-192 hours', 'localtime') 
                    AND timestamp < datetime('now', '-24 hours', 'localtime')
                )
            """
            dns_new_7d = conn.execute(query_dns_new).fetchone()[0] or 0

            # 3. Conexiones HTTP no cifradas activas (en la última hora como proxy de activas/recientes)
            query_http_unencrypted = """
                SELECT COUNT(*) 
                FROM web_traffic 
                WHERE protocol = 'HTTP' AND timestamp >= datetime('now', '-1 hours', 'localtime')
            """
            http_unencrypted_1h = conn.execute(query_http_unencrypted).fetchone()[0] or 0

            return {
                "dns_unique_24h": dns_unique_24h,
                "dns_new_7d": dns_new_7d,
                "http_unencrypted_1h": http_unencrypted_1h
            }
        finally:
            conn.close()
