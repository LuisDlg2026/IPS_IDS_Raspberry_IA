import streamlit as st
import plotly.express as px
from src.dashboard.utils.data_loader import load_alert_summary, load_network_stats
from src.config import DASHBOARD_REFRESH_RATE
import time

st.set_page_config(page_title="Home - IPS/IDS", page_icon="🏠", layout="wide")

# Toggle de Auto-Refresco en el sidebar (configurable desde config)
st.sidebar.markdown(f"**Auto-Refresco: {DASHBOARD_REFRESH_RATE}s**")
auto_refresh = st.sidebar.toggle("Habilitar Auto-Refresco", value=True)

col_title, col_btn = st.columns([4, 1])
with col_title:
    st.title("🏠 Estado General del Sistema")
with col_btn:
    st.write("") # Espaciado
    if st.button("🔄 Actualizar Datos"):
        st.rerun()

# Cargar datos
summary = load_alert_summary()
stats_df = load_network_stats(limit=30)  # Últimas 30 muestras

# 1. KPIs principales (Métricas)
st.subheader("Indicadores Principales")

# Determinar estado de salud
total_alerts = summary.get("total", 0)
high_alerts = summary.get("by_severity", {}).get("high", 0) + summary.get("by_severity", {}).get("critical", 0)

status_color = "🟢 Saludable"
if high_alerts > 0:
    status_color = "🔴 Crítico"
elif total_alerts > 0:
    status_color = "🟡 Advertencia"

col1, col2, col3, col4 = st.columns(4)

current_bandwidth = 0.0
current_latency = 0.0
if not stats_df.empty:
    current_bandwidth = stats_df.iloc[-1]["bandwidth_mbps"]
    current_latency = stats_df.iloc[-1]["latency_ms"]

col1.metric("Estado de la Red", status_color)
col2.metric("Alertas Activas", total_alerts, delta=f"{high_alerts} críticas", delta_color="inverse")
col3.metric("Ancho de Banda", f"{current_bandwidth:.2f} Mbps")
col4.metric("Latencia Media", f"{current_latency:.1f} ms")

st.divider()

# 2. Gráficos de tendencias
col_chart1, col_chart2 = st.columns(2)

with col_chart1:
    st.subheader("📈 Tendencia de Ancho de Banda")
    if not stats_df.empty:
        fig_bw = px.area(stats_df, x="timestamp", y="bandwidth_mbps", 
                         title="Ancho de Banda (Últimos periodos)",
                         labels={"timestamp": "Tiempo", "bandwidth_mbps": "Mbps"},
                         color_discrete_sequence=["#00b4d8"])
        st.plotly_chart(fig_bw, use_container_width=True)
    else:
        st.info("Esperando datos de red...")

with col_chart2:
    st.subheader("🚨 Tipos de Alerta")
    by_type = summary.get("by_type", {})
    if by_type:
        fig_types = px.pie(names=list(by_type.keys()), values=list(by_type.values()),
                           title="Distribución de Amenazas",
                           hole=0.4,
                           color_discrete_sequence=px.colors.sequential.RdBu)
        st.plotly_chart(fig_types, use_container_width=True)
    else:
        st.success("No hay amenazas registradas.")

# -- Auto-Refresh --
if auto_refresh:
    time.sleep(DASHBOARD_REFRESH_RATE)
    st.rerun()
