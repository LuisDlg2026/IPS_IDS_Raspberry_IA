import streamlit as st
import pandas as pd
import time
from src.dashboard.utils.data_loader import load_alerts, load_alert_summary
from src.dashboard.utils.styles import (
    inject_global_css, render_page_header, render_metric_card,
    render_section_divider, render_footer, COLORS, SEVERITY_COLORS, SEVERITY_BG
)
from src.config import DASHBOARD_REFRESH_RATE

st.set_page_config(page_title="Alertas - IPS/IDS", page_icon="🚨", layout="wide")
inject_global_css()

# Toggle de Auto-Refresco
st.sidebar.markdown(f"⏱️ **Auto-Refresco:** `{DASHBOARD_REFRESH_RATE}s`")
auto_refresh = st.sidebar.toggle("Habilitar Auto-Refresco", value=True)

# ── Header ──────────────────────────────────────────────────────
render_page_header(
    icon="🚨",
    title="Centro de Operaciones de Seguridad (SOC)",
    subtitle="Registro inmutable de ataques clasificados mediante Inteligencia Artificial y vulnerabilidades de firmware.",
    gradient="linear-gradient(135deg, rgba(239, 68, 68, 0.12) 0%, rgba(15, 23, 42, 0.95) 60%, rgba(10, 14, 26, 1) 100%)",
    accent="linear-gradient(90deg, var(--accent-red), var(--accent-amber))"
)

# ── Resumen rápido (KPIs) ──────────────────────────────────────
summary = load_alert_summary()
total = summary.get("total", 0)
by_sev = summary.get("by_severity", {})
critical_count = by_sev.get("critical", 0)
high_count = by_sev.get("high", 0)
medium_count = by_sev.get("medium", 0)
low_count = by_sev.get("low", 0)

col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    render_metric_card("📊", "Total Eventos", str(total), accent="blue")
with col2:
    render_metric_card("💀", "Críticas", str(critical_count), accent="red", glow=critical_count > 0)
with col3:
    render_metric_card("🔥", "Altas", str(high_count), accent="amber", glow=high_count > 0)
with col4:
    render_metric_card("⚠️", "Medias", str(medium_count), accent="amber")
with col5:
    render_metric_card("ℹ️", "Bajas / Info", str(low_count + by_sev.get("info", 0)), accent="cyan")

# ── Filtros ─────────────────────────────────────────────────────
render_section_divider("Motor de Búsqueda y Filtrado")

col1, col2, col3 = st.columns([1, 1, 2])
with col1:
    severity_filter = st.selectbox("Severidad de la Amenaza", ["Todas", "critical", "high", "medium", "low", "info"])
with col2:
    limit = st.select_slider("Ventana de eventos (Últimos N)", options=[50, 100, 250, 500, 1000], value=100)
with col3:
    st.write("")
    if st.button("🔄 Refrescar Logs Manualmente", use_container_width=True):
        st.rerun()

severity = None if severity_filter == "Todas" else severity_filter
alerts_df = load_alerts(limit=limit, severity=severity)

if alerts_df.empty:
    st.markdown("""
    <div style="
        text-align: center; padding: 60px 40px;
        background: rgba(6, 214, 160, 0.05);
        border: 1px solid rgba(6, 214, 160, 0.15);
        border-radius: 16px;
        margin-top: 20px;
    ">
        <div style="font-size: 3rem; margin-bottom: 12px;">✨</div>
        <div style="color: var(--accent-cyan); font-weight: 600; font-size: 1.1rem;">¡Enhorabuena!</div>
        <div style="color: var(--text-muted); font-size: 0.9rem; margin-top: 6px;">No hay intrusiones detectadas bajo los filtros actuales en el perímetro de la red</div>
    </div>
    """, unsafe_allow_html=True)
else:
    # Formateo visual con colores del sistema
    def color_severity(val):
        sev_styles = {
            'critical': f'background-color: {SEVERITY_BG["critical"]}; color: {SEVERITY_COLORS["critical"]}; border-left: 4px solid {SEVERITY_COLORS["critical"]}; font-weight: bold;',
            'high': f'background-color: {SEVERITY_BG["high"]}; color: {SEVERITY_COLORS["high"]}; border-left: 4px solid {SEVERITY_COLORS["high"]}; font-weight: bold;',
            'medium': f'background-color: {SEVERITY_BG["medium"]}; color: {SEVERITY_COLORS["medium"]}; border-left: 4px solid {SEVERITY_COLORS["medium"]}; font-weight: bold;',
            'low': f'background-color: {SEVERITY_BG["low"]}; color: {SEVERITY_COLORS["low"]}; border-left: 4px solid {SEVERITY_COLORS["low"]}; font-weight: bold;',
            'info': f'background-color: {SEVERITY_BG["info"]}; color: {SEVERITY_COLORS["info"]}; border-left: 4px solid {SEVERITY_COLORS["info"]}; font-weight: bold;',
        }
        return sev_styles.get(val, 'color: white;')

    styled_df = alerts_df.style.map(color_severity, subset=['severity'])

    st.dataframe(
        styled_df,
        column_config={
            "id": st.column_config.TextColumn("Hash de Alerta", width="medium"),
            "timestamp": st.column_config.DatetimeColumn("Marca de Tiempo", format="DD/MM/YY - HH:mm:ss"),
            "attack_type": st.column_config.TextColumn("Vector de Ataque (Etiqueta)"),
            "confidence": st.column_config.ProgressColumn("Certidumbre ML", min_value=0, max_value=1, format="%.2f"),
            "severity": st.column_config.TextColumn("Nivel de Gravedad"),
            "src_ip": st.column_config.TextColumn("Vector Origen (IP)"),
            "dst_ip": st.column_config.TextColumn("Víctima (IP)"),
            "n_packets": st.column_config.NumberColumn("Carga (Paquetes)"),
        },
        height=600,
        hide_index=True,
        use_container_width=True
    )

    st.caption("ℹ️ Puedes pasar por encima de las cabeceras de la tabla para buscar, ordenar o descargar los logs en formato `.CSV` para análisis forense.")

render_footer()

# ── Auto-Refresh ────────────────────────────────────────────────
if auto_refresh:
    time.sleep(DASHBOARD_REFRESH_RATE)
    st.rerun()
