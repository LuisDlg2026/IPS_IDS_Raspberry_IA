import streamlit as st
import pandas as pd
import time
from src.dashboard.utils.data_loader import load_alerts
from src.config import DASHBOARD_REFRESH_RATE

st.set_page_config(page_title="Alertas - IPS/IDS", page_icon="🚨", layout="wide")

# Toggle de Auto-Refresco
st.sidebar.markdown(f"**Auto-Refresco: {DASHBOARD_REFRESH_RATE}s**")
auto_refresh = st.sidebar.toggle("Habilitar Auto-Refresco", value=True)

st.title("🚨 Historial de Alertas de Seguridad")
st.markdown("Registro de ataques detectados por el modelo ML y vulnerabilidades encontradas por la auditoría.")

# Filtros
col1, col2 = st.columns([1, 1])
with col1:
    severity_filter = st.selectbox("Filtrar por Severidad", ["Todas", "critical", "high", "medium", "low", "info"])
with col2:
    limit = st.slider("Límite de registros", 50, 500, 100)

severity = None if severity_filter == "Todas" else severity_filter
alerts_df = load_alerts(limit=limit, severity=severity)

if alerts_df.empty:
    st.success("No hay alertas registradas que coincidan con los filtros.")
else:
    # Formateo visual
    def color_severity(val):
        color = 'white'
        if val == 'critical': color = '#ff4b4b'
        elif val == 'high': color = '#ffa421'
        elif val == 'medium': color = '#ffe312'
        elif val == 'low': color = '#21c354'
        elif val == 'info': color = '#00a8e8'
        return f'background-color: {color}; color: black; font-weight: bold'

    styled_df = alerts_df.style.map(color_severity, subset=['severity'])
    
    st.dataframe(
        styled_df,
        column_config={
            "id": st.column_config.TextColumn("ID Alerta", width="medium"),
            "timestamp": st.column_config.DatetimeColumn("Fecha/Hora", format="DD/MM/YYYY HH:mm:ss"),
            "attack_type": st.column_config.TextColumn("Tipo de Amenaza"),
            "confidence": st.column_config.ProgressColumn("Confianza ML", min_value=0, max_value=1, format="%.2f"),
            "severity": st.column_config.TextColumn("Severidad"),
            "src_ip": st.column_config.TextColumn("IP Origen"),
            "dst_ip": st.column_config.TextColumn("IP Destino"),
            "n_packets": "Paquetes",
        },
        hide_index=True,
        use_container_width=True
    )

    st.info("Tip: Usa la opción 'Descargar como CSV' en la parte superior derecha de la tabla para exportar los datos.")

# -- Auto-Refresh --
if auto_refresh:
    time.sleep(DASHBOARD_REFRESH_RATE)
    st.rerun()
