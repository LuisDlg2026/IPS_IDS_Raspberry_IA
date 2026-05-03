"""
Almacenamiento persistente en SQLite para el IDS/IPS.

Tablas:
  - alerts: Alertas de seguridad generadas por el ML
  - devices: Dispositivos descubiertos en la red
  - network_stats: Metricas de red periodicas
  - events: Log de eventos del sistema

Uso:
    from src.utils.storage import Database
    db = Database()
    db.save_alert(alert_dict)
    alerts = db.get_alerts(limit=50)
"""

import sqlite3
import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class Database:
    """
    Capa de persistencia SQLite para el IDS/IPS.

    Thread-safe: usa un lock para operaciones concurrentes.
    Ligero: SQLite no requiere servidor (ideal para Raspberry Pi).
    """

    def __init__(self, db_path: str = None):
        from src.config import DB_PATH
        self._db_path = Path(db_path) if db_path else DB_PATH
        self._lock = threading.Lock()
        self._init_db()
        logger.info(f"Database inicializada: {self._db_path}")

    def _get_conn(self) -> sqlite3.Connection:
        """Crea una conexion nueva (SQLite no es thread-safe con la misma)."""
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")   # Write-Ahead Logging
        conn.execute("PRAGMA synchronous=NORMAL")  # Balance rendimiento/seguridad
        return conn

    def _init_db(self):
        """Crea las tablas si no existen."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        attack_type TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        severity TEXT NOT NULL,
                        src_ip TEXT,
                        dst_ip TEXT,
                        flow_key TEXT,
                        n_packets INTEGER DEFAULT 0,
                        inference_ms REAL,
                        acknowledged INTEGER DEFAULT 0,
                        details TEXT,
                        created_at TEXT DEFAULT (datetime('now','localtime'))
                    );

                    CREATE TABLE IF NOT EXISTS devices (
                        ip TEXT PRIMARY KEY,
                        mac TEXT,
                        hostname TEXT,
                        vendor TEXT,
                        os_guess TEXT,
                        open_ports TEXT,
                        first_seen TEXT DEFAULT (datetime('now','localtime')),
                        last_seen TEXT DEFAULT (datetime('now','localtime')),
                        is_online INTEGER DEFAULT 1,
                        risk_level TEXT DEFAULT 'low',
                        notes TEXT
                    );

                    CREATE TABLE IF NOT EXISTS network_stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT DEFAULT (datetime('now','localtime')),
                        bytes_sent INTEGER DEFAULT 0,
                        bytes_recv INTEGER DEFAULT 0,
                        packets_sent INTEGER DEFAULT 0,
                        packets_recv INTEGER DEFAULT 0,
                        active_connections INTEGER DEFAULT 0,
                        cpu_percent REAL,
                        memory_percent REAL,
                        latency_ms REAL,
                        bandwidth_mbps REAL
                    );

                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT DEFAULT (datetime('now','localtime')),
                        event_type TEXT NOT NULL,
                        severity TEXT DEFAULT 'info',
                        message TEXT,
                        details TEXT
                    );

                    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
                    CREATE INDEX IF NOT EXISTS idx_alerts_attack ON alerts(attack_type);
                    CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
                    CREATE INDEX IF NOT EXISTS idx_stats_timestamp ON network_stats(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
                """)
                conn.commit()
                logger.info("Tablas SQLite creadas/verificadas")
            finally:
                conn.close()

    # ─── ALERTS ─────────────────────────────────────────────

    def save_alert(self, alert: Dict) -> str:
        """Guarda una alerta de seguridad."""
        with self._lock:
            conn = self._get_conn()
            try:
                alert_id = alert.get("id", f"ALERT-{int(datetime.now().timestamp()*1000)}")
                conn.execute("""
                    INSERT OR REPLACE INTO alerts
                    (id, timestamp, attack_type, confidence, severity,
                     src_ip, dst_ip, flow_key, n_packets, inference_ms,
                     acknowledged, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert_id,
                    alert.get("timestamp", datetime.now().isoformat()),
                    alert.get("attack_type", "Unknown"),
                    alert.get("confidence", 0),
                    alert.get("severity", "unknown"),
                    alert.get("src_ip"),
                    alert.get("dst_ip"),
                    alert.get("flow_key"),
                    alert.get("n_packets", 0),
                    alert.get("inference_ms", 0),
                    1 if alert.get("acknowledged") else 0,
                    json.dumps(alert.get("details", {})),
                ))
                conn.commit()
                return alert_id
            finally:
                conn.close()

    def get_alerts(self, limit: int = 100, severity: str = None,
                   attack_type: str = None, since: str = None) -> List[Dict]:
        """Obtiene alertas con filtros opcionales."""
        with self._lock:
            conn = self._get_conn()
            try:
                query = "SELECT * FROM alerts WHERE 1=1"
                params = []

                if severity:
                    query += " AND severity = ?"
                    params.append(severity)
                if attack_type:
                    query += " AND attack_type = ?"
                    params.append(attack_type)
                if since:
                    query += " AND timestamp >= ?"
                    params.append(since)

                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)

                rows = conn.execute(query, params).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_alert_summary(self) -> Dict:
        """Resumen de alertas agrupado por tipo y severidad."""
        with self._lock:
            conn = self._get_conn()
            try:
                total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                by_type = conn.execute(
                    "SELECT attack_type, COUNT(*) as cnt FROM alerts "
                    "GROUP BY attack_type ORDER BY cnt DESC"
                ).fetchall()
                by_severity = conn.execute(
                    "SELECT severity, COUNT(*) as cnt FROM alerts "
                    "GROUP BY severity ORDER BY cnt DESC"
                ).fetchall()
                return {
                    "total": total,
                    "by_type": {r["attack_type"]: r["cnt"] for r in by_type},
                    "by_severity": {r["severity"]: r["cnt"] for r in by_severity},
                }
            finally:
                conn.close()

    def acknowledge_alert(self, alert_id: str):
        """Marca una alerta como reconocida."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?",
                             (alert_id,))
                conn.commit()
            finally:
                conn.close()

    # ─── DEVICES ────────────────────────────────────────────

    def save_device(self, device: Dict) -> str:
        """Guarda o actualiza un dispositivo descubierto."""
        with self._lock:
            conn = self._get_conn()
            try:
                ip = device.get("ip")
                mac = device.get("mac", "unknown")
                if not ip: return mac
                
                # Si es un descubrimiento pasivo donde MAC es unknown, no podemos pisar la key si ya existia la IP
                cursor = conn.execute("SELECT mac FROM devices WHERE ip = ?", (ip,))
                row = cursor.fetchone()
                if row and row['mac'] != "unknown" and mac == "unknown":
                    mac = row['mac']
                
                conn.execute("""
                    INSERT INTO devices (ip, mac, hostname, vendor, os_guess,
                                        open_ports, risk_level, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        mac = COALESCE(NULLIF(excluded.mac, 'unknown'), devices.mac),
                        hostname = COALESCE(excluded.hostname, devices.hostname),
                        vendor = CASE WHEN excluded.vendor != 'Unknown (Pasivo)' THEN excluded.vendor ELSE devices.vendor END,
                        os_guess = COALESCE(excluded.os_guess, devices.os_guess),
                        open_ports = COALESCE(excluded.open_ports, devices.open_ports),
                        last_seen = datetime('now','localtime'),
                        is_online = 1
                """, (
                    ip,
                    mac,
                    device.get("hostname"),
                    device.get("vendor", "Unknown (Pasivo)"),
                    device.get("os_guess"),
                    json.dumps(device.get("open_ports", [])),
                    device.get("risk_level", "low"),
                    device.get("notes"),
                ))
                conn.commit()
                return ip
            finally:
                conn.close()

    def get_devices(self, online_only: bool = False) -> List[Dict]:
        """Obtiene la lista de dispositivos."""
        with self._lock:
            conn = self._get_conn()
            try:
                query = "SELECT * FROM devices"
                if online_only:
                    query += " WHERE is_online = 1"
                query += " ORDER BY last_seen DESC"
                rows = conn.execute(query).fetchall()
                results = []
                for r in rows:
                    d = dict(r)
                    if d.get("open_ports"):
                        try:
                            d["open_ports"] = json.loads(d["open_ports"])
                        except (json.JSONDecodeError, TypeError):
                            pass
                    results.append(d)
                return results
            finally:
                conn.close()

    def set_device_offline(self, mac: str):
        """Marca un dispositivo como offline."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("UPDATE devices SET is_online = 0 WHERE mac = ?",
                             (mac,))
                conn.commit()
            finally:
                conn.close()

    # ─── NETWORK STATS ──────────────────────────────────────

    def save_network_stats(self, stats: Dict):
        """Guarda una instantanea de metricas de red."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT INTO network_stats
                    (bytes_sent, bytes_recv, packets_sent, packets_recv,
                     active_connections, cpu_percent, memory_percent,
                     latency_ms, bandwidth_mbps)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    stats.get("bytes_sent", 0),
                    stats.get("bytes_recv", 0),
                    stats.get("packets_sent", 0),
                    stats.get("packets_recv", 0),
                    stats.get("active_connections", 0),
                    stats.get("cpu_percent"),
                    stats.get("memory_percent"),
                    stats.get("latency_ms"),
                    stats.get("bandwidth_mbps"),
                ))
                conn.commit()
            finally:
                conn.close()

    def get_network_stats(self, limit: int = 100, hours: int = None) -> List[Dict]:
        """Obtiene historico de metricas de red."""
        with self._lock:
            conn = self._get_conn()
            try:
                query = "SELECT * FROM network_stats"
                params = []
                if hours:
                    query += " WHERE timestamp >= datetime('now', '-' || ? || ' hours', 'localtime')"
                    params.append(str(hours))
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                rows = conn.execute(query, params).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # ─── EVENTS ─────────────────────────────────────────────

    def log_event(self, event_type: str, message: str,
                  severity: str = "info", details: dict = None):
        """Registra un evento del sistema."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT INTO events (event_type, severity, message, details)
                    VALUES (?, ?, ?, ?)
                """, (event_type, severity, message,
                      json.dumps(details) if details else None))
                conn.commit()
            finally:
                conn.close()

    def get_events(self, limit: int = 100, event_type: str = None) -> List[Dict]:
        """Obtiene eventos del sistema."""
        with self._lock:
            conn = self._get_conn()
            try:
                query = "SELECT * FROM events"
                params = []
                if event_type:
                    query += " WHERE event_type = ?"
                    params.append(event_type)
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                rows = conn.execute(query, params).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # ─── MANTENIMIENTO ──────────────────────────────────────

    def cleanup(self, days: int = 30):
        """Elimina registros antiguos."""
        with self._lock:
            conn = self._get_conn()
            try:
                cutoff = f"-{days} days"
                for table in ["alerts", "network_stats", "events"]:
                    conn.execute(
                        f"DELETE FROM {table} "
                        f"WHERE timestamp < datetime('now', ?, 'localtime')",
                        (cutoff,)
                    )
                conn.commit()
                conn.execute("VACUUM")
                logger.info(f"Limpieza: eliminados registros > {days} dias")
            finally:
                conn.close()

    def get_db_stats(self) -> Dict:
        """Estadisticas de la base de datos."""
        with self._lock:
            conn = self._get_conn()
            try:
                stats = {}
                for table in ["alerts", "devices", "network_stats", "events"]:
                    count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    stats[table] = count
                # Tamano del archivo
                stats["file_size_mb"] = round(self._db_path.stat().st_size / 1024 / 1024, 2)
                return stats
            finally:
                conn.close()
