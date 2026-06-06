import streamlit as st
import pandas as pd
import time
import json
import math
from collections import Counter
from datetime import datetime, timedelta
import plotly.express as px
from src.dashboard.utils.data_loader import (
    load_web_traffic_filtered, load_dns_web_metrics, load_devices, get_db
)
from src.dashboard.utils.demo_data import is_demo_mode
from src.dashboard.utils.styles import (
    inject_global_css, render_page_header, render_metric_card,
    render_section_divider, render_status_badge, render_footer, get_plotly_layout, COLORS
)
from src.config import DASHBOARD_REFRESH_RATE

st.set_page_config(page_title="Tráfico y DNS - IPS/IDS", page_icon="🌐", layout="wide")
inject_global_css()

# Toggle de Auto-Refresco
st.sidebar.markdown(f"⏱️ **Auto-Refresco:** `{DASHBOARD_REFRESH_RATE}s`")
auto_refresh = st.sidebar.toggle("Habilitar Auto-Refresco", value=True)

# ── Header ──────────────────────────────────────────────────────
render_page_header(
    icon="🌐",
    title="Análisis de Tráfico L7 (DPI) y DNS",
    subtitle="Auditoría de capa de aplicación: resolución de nombres DNS, heurística DGA y conexiones HTTP no cifradas.",
    gradient="linear-gradient(135deg, rgba(27, 38, 59, 0.8) 0%, rgba(13, 27, 42, 0.95) 100%)",
    accent="linear-gradient(90deg, var(--accent-blue), var(--accent-cyan))"
)

# ── 1. Métricas SOC (Capa de Aplicación) ───────────────────────────
metrics = load_dns_web_metrics()

col1, col2, col3 = st.columns(3)
with col1:
    render_metric_card(
        "🔎", 
        "Consultas DNS Únicas (24h)", 
        str(metrics["dns_unique_24h"]), 
        accent="blue"
    )
with col2:
    render_metric_card(
        "🆕", 
        "Dominios Nuevos (7d)", 
        str(metrics["dns_new_7d"]), 
        accent="cyan" if metrics["dns_new_7d"] > 0 else "blue",
        glow=(metrics["dns_new_7d"] > 0)
    )
with col3:
    render_metric_card(
        "🔓", 
        "HTTP Inseguro (Última Hora)", 
        str(metrics["http_unencrypted_1h"]), 
        accent="red" if metrics["http_unencrypted_1h"] > 0 else "green",
        glow=(metrics["http_unencrypted_1h"] > 0)
    )

# ── Heurística DGA y C2 ──
def calculate_shannon_entropy(domain: str) -> float:
    """Calcula la entropía de Shannon del nombre principal del dominio."""
    if not domain or not isinstance(domain, str):
        return 0.0
    # Extraer el dominio principal (ej: google de google.com)
    parts = domain.split(".")
    domain_name = parts[-2] if len(parts) >= 2 else domain
    if not domain_name:
        return 0.0
    length = len(domain_name)
    counts = Counter(domain_name)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def is_suspicious_domain(domain: str) -> bool:
    """Heurística local offline para detectar dominios tipo DGA o conocidos de C2."""
    if not domain or not isinstance(domain, str):
        return False
    domain_lower = domain.lower()
    
    # 1. Coincidencia de palabras clave C2
    c2_keywords = ["malware", "hack", "exploit", "c2", "c&c", "command-control", "exfil", "reverse-shell", "bad-actor"]
    if any(kw in domain_lower for kw in c2_keywords):
        return True
        
    # 2. Entropía de Shannon (Heurística DGA)
    parts = domain.split(".")
    domain_name = parts[-2] if len(parts) >= 2 else domain
    entropy = calculate_shannon_entropy(domain)
    # Nombre largo con entropía muy alta suele ser DGA (ej: xqruymwlzbx)
    if len(domain_name) >= 12 and entropy >= 3.65:
        return True
        
    return False

# ── 2. Distribución de Consultas DNS (Histograma Top 25) ──────────────
render_section_divider("Distribución de Consultas DNS y Detección DGA")

# Selector de ventana temporal para los gráficos
col_f1, col_f2 = st.columns([1, 2])
with col_f1:
    dns_window = st.selectbox(
        "Rango de datos:",
        ["Última hora", "Últimas 6 horas", "Últimas 24 horas"],
        index=2
    )

hours_map = {
    "Última hora": 1,
    "Últimas 6 horas": 6,
    "Últimas 24 horas": 24
}
hours = hours_map[dns_window]

# Cargar tramas DNS de la base de datos
dns_df = load_web_traffic_filtered(protocol="DNS", hours=hours)

if dns_df.empty:
    st.info("💡 No hay consultas DNS registradas en esta ventana temporal.")
else:
    # Agrupar y contar
    dns_counts = dns_df["domain_url"].value_counts().reset_index()
    dns_counts.columns = ["Dominio", "Consultas"]
    top_25 = dns_counts.head(25).copy()
    
    # Evaluar sospecha (C2 / DGA) para cada uno
    top_25["Sospechoso"] = top_25["Dominio"].apply(lambda d: "Sospechoso" if is_suspicious_domain(d) else "Normal")
    top_25["Entropía"] = top_25["Dominio"].apply(calculate_shannon_entropy)
    
    # Ordenar de menor a mayor consultas para el gráfico de barras horizontales
    top_25 = top_25.sort_values(by="Consultas", ascending=True)

    fig_dns = px.bar(
        top_25,
        x="Consultas",
        y="Dominio",
        orientation="h",
        color="Sospechoso",
        color_discrete_map={
            "Normal": COLORS["accent_cyan"],
            "Sospechoso": "#ef4444"
        },
        labels={"Consultas": "Consultas", "Dominio": "Dominio DNS"},
        hover_data={"Entropía": ":.2f", "Sospechoso": True}
    )
    
    layout = get_plotly_layout()
    layout["height"] = 550
    layout["margin"] = dict(l=0, r=0, t=10, b=0)
    fig_dns.update_layout(**layout)
    
    st.plotly_chart(fig_dns, use_container_width=True)
    
    if "Sospechoso" in top_25["Sospechoso"].values:
        st.warning("🚨 **Alerta de Seguridad:** Se detectaron dominios con alta entropía o patrones similares a DGA/C2 (resaltados en rojo). Revisa la auditoría del dispositivo implicado.")

# ── 3. Conexiones HTTP No Cifradas (Tabla de DPI) ───────────────────
render_section_divider("Auditoría de Conexiones HTTP Inseguras (Capa 7)")

# Cargar logs de HTTP
http_df = load_web_traffic_filtered(protocol="HTTP", hours=hours)

def parse_http_details(row):
    details_str = row.get("details", "")
    method = "GET"
    status_code = "200"
    res_size = 1500
    
    if details_str:
        if isinstance(details_str, dict):
            details = details_str
        else:
            try:
                details = json.loads(details_str)
            except:
                details = {}
        method = details.get("method", "GET")
        status_code = details.get("status", "200")
        res_size = details.get("payload_len", 1500)
    
    return method, str(status_code), res_size

# Determinar si mostrar simulación basada únicamente en el MODO DEMOSTRACIÓN
db = get_db()
demo_active = is_demo_mode(db)

if demo_active and http_df.empty:
    simulated_http = [
        ("192.168.1.10", "192.168.1.1", "ESP32-Temp-Sensor/api/post_stats", "POST", "200", 124),
        ("192.168.1.11", "192.168.1.1", "ESP8266-Humedad/config.json", "GET", "200", 256),
        ("192.168.1.20", "192.168.1.1", "Hikvision-Cam01/video_stream?quality=low", "GET", "200", 8900000),
        ("192.168.1.30", "192.168.1.1", "PLC-Siemens/modbus_bridge", "POST", "500", 64),
        ("192.168.1.100", "142.250.184.4", "google.com/search?q=TFMs+UCLM", "GET", "301", 14500),
        ("192.168.1.100", "185.112.145.12", "bad-actor-domain.ru/c2_payload.exe", "GET", "200", 5600000),
    ]
    
    sim_data = []
    for src, dst, url, method, code, size in simulated_http:
        sim_data.append({
            "timestamp": datetime.now() - timedelta(minutes=10),
            "src_ip": src,
            "dst_ip": dst,
            "method": method,
            "url": url,
            "status": code,
            "size": size
        })
    http_display_df = pd.DataFrame(sim_data)
else:
    if http_df.empty:
        http_display_df = pd.DataFrame(columns=["timestamp", "src_ip", "dst_ip", "method", "url", "status", "size"])
    else:
        # Formatear HTTP reales
        parsed_cols = http_df.apply(parse_http_details, axis=1)
        http_df["method"] = [p[0] for p in parsed_cols]
        http_df["status"] = [p[1] for p in parsed_cols]
        http_df["size"] = [p[2] for p in parsed_cols]
        
        http_display_df = http_df[["timestamp", "src_ip", "dst_ip", "method", "domain_url", "status", "size"]].copy()
        http_display_df.rename(columns={"domain_url": "url"}, inplace=True)

# Formatear tamaño de respuesta
def format_size(val):
    try:
        val_int = int(val)
        if val_int >= 1_000_000:
            return f"{val_int / 1_000_000:.2f} MB"
        elif val_int >= 1_000:
            return f"{val_int / 1_000:.1f} KB"
        else:
            return f"{val_int} B"
    except (ValueError, TypeError):
        return "0 B"

if http_display_df.empty:
    st.info("💡 No se han detectado conexiones HTTP no cifradas reales en esta ventana temporal.")
else:
    http_display_df["size_formatted"] = http_display_df["size"].apply(format_size)

    # Ordenar de más reciente a más antiguo
    http_display_df["timestamp"] = pd.to_datetime(http_display_df["timestamp"])
    http_display_df = http_display_df.sort_values(by="timestamp", ascending=False)

    # Mostrar tabla
    st.dataframe(
        http_display_df[["timestamp", "src_ip", "dst_ip", "method", "url", "status", "size_formatted"]],
        column_config={
            "timestamp": st.column_config.DatetimeColumn("Hora", format="DD/MM/YY - HH:mm:ss"),
            "src_ip": st.column_config.TextColumn("IP Origen"),
            "dst_ip": st.column_config.TextColumn("IP Destino"),
            "method": st.column_config.TextColumn("Método"),
            "url": st.column_config.TextColumn("URL Solicitada"),
            "status": st.column_config.TextColumn("Respuesta"),
            "size_formatted": st.column_config.TextColumn("Tamaño Respuesta"),
        },
        hide_index=True,
        use_container_width=True
    )

st.caption("ℹ️ El tráfico HTTP sin cifrar transmite contraseñas y payloads en claro, exponiendo a dispositivos vulnerables a inyecciones o escuchas pasivas.")

render_footer()

# Auto-Refresco
if auto_refresh:
    time.sleep(DASHBOARD_REFRESH_RATE)
    st.rerun()
