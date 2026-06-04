import streamlit as st
import pandas as pd
import time
from src.dashboard.utils.data_loader import load_alerts
from src.config import DASHBOARD_REFRESH_RATE

st.set_page_config(page_title="Alertas - IPS/IDS", page_icon="🚨", layout="wide")

st.markdown("""
<style>
    .alert-header {
        background: linear-gradient(90deg, rgba(200,0,0,0.8) 0%, rgba(20,20,20,1) 100%);
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        border-left: 5px solid #ff4b4b;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# Toggle de Auto-Refresco
st.sidebar.markdown(f"⏱️ **Auto-Refresco:** `{DASHBOARD_REFRESH_RATE}s`")
auto_refresh = st.sidebar.toggle("Habilitar Auto-Refresco", value=True)

st.markdown('<div class="alert-header"><h1>🚨 Centro de Operaciones de Seguridad (SOC)</h1><p>Registro inmutable de ataques clasificados mediante Inteligencia Artificial y vulnerabilidades de firmware.</p></div>', unsafe_allow_html=True)

# Filtros
st.markdown("### 🔎 Motor de Búsqueda y Filtrado")
col1, col2, col3 = st.columns([1, 1, 2])
with col1:
    severity_filter = st.selectbox("Severidad de la Amenaza", ["Todas", "critical", "high", "medium", "low", "info"])
with col2:
    limit = st.select_slider("Ventana de eventos (Últimos N)", options=[50, 100, 250, 500, 1000], value=100)
with col3:
    st.write("<br>", unsafe_allow_html=True)
    if st.button("🔄 Refrescar Logs Manualmente", use_container_width=True):
        st.rerun()

severity = None if severity_filter == "Todas" else severity_filter
alerts_df = load_alerts(limit=limit, severity=severity)

if alerts_df.empty:
    st.success("✨ ¡Enhorabuena! No hay intrusiones detectadas bajo los filtros actuales en el perímetro de la red.")
else:
    # Formateo visual
    def color_severity(val):
        color = 'transparent'
        text_color = 'white'
        if val == 'critical': color, text_color = '#6b0000', '#ffb3b3'
        elif val == 'high': color, text_color = '#7a3b00', '#ffd699'
        elif val == 'medium': color, text_color = '#6b6600', '#ffff99'
        elif val == 'low': color, text_color = '#004d1a', '#99ffb3'
        elif val == 'info': color, text_color = '#003366', '#99ccff'
        return f'background-color: {color}; color: {text_color}; border-left: 4px solid {text_color}; font-weight: bold;'

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

# -- Auto-Refresh --
if auto_refresh:
    time.sleep(DASHBOARD_REFRESH_RATE)
    st.rerun()
