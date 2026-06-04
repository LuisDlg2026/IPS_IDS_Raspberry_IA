import streamlit as st
import plotly.express as px
from src.dashboard.utils.data_loader import load_alert_summary, load_network_stats
from src.config import DASHBOARD_REFRESH_RATE
import time

st.set_page_config(page_title="Home - IPS/IDS", page_icon="🏠", layout="wide")

# -- CSS Personalizado --
st.markdown("""
<style>
    .metric-container {
        background-color: #1E1E1E;
        border-radius: 10px;
        padding: 20px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        border-left: 5px solid #00b4d8;
    }
    .metric-container-red {
        border-left: 5px solid #ff4b4b;
    }
    .metric-container-yellow {
        border-left: 5px solid #ffa421;
    }
    .metric-container-green {
        border-left: 5px solid #21c354;
    }
    h1 {
        color: #f8f9fa;
        font-weight: 700;
        text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
    }
</style>
""", unsafe_allow_html=True)

# Toggle de Auto-Refresco en el sidebar (configurable desde config)
st.sidebar.markdown(f"⏱️ **Auto-Refresco:** `{DASHBOARD_REFRESH_RATE}s`")
auto_refresh = st.sidebar.toggle("Habilitar Auto-Refresco", value=True)

col_title, col_btn = st.columns([6, 1])
with col_title:
    st.title("🏠 Dashboard Principal")
    st.markdown("Visión panorámica del estado de la red y salud de la infraestructura.")
with col_btn:
    st.write("") # Espaciado lateral
    st.write("")
    if st.button("🔄 Refrescar", use_container_width=True):
        st.rerun()

st.divider()

# Cargar datos
summary = load_alert_summary()
stats_df = load_network_stats(limit=30)  # Últimas 30 muestras

# 1. KPIs principales (Métricas)
total_alerts = summary.get("total", 0)
high_alerts = summary.get("by_severity", {}).get("high", 0) + summary.get("by_severity", {}).get("critical", 0)

status_color = "🟢 Saludable"
css_class = "metric-container-green"
if high_alerts > 0:
    status_color = "🔴 Crítico"
    css_class = "metric-container-red"
elif total_alerts > 0:
    status_color = "🟡 Advertencia"
    css_class = "metric-container-yellow"

col1, col2, col3, col4 = st.columns(4)

current_bandwidth = 0.0
current_latency = 0.0
if not stats_df.empty:
    current_bandwidth = stats_df.iloc[-1]["bandwidth_mbps"]
    current_latency = stats_df.iloc[-1]["latency_ms"]

with col1:
    st.markdown(f'<div class="metric-container {css_class}">', unsafe_allow_html=True)
    st.metric("🛡️ Estado de la Red", status_color)
    st.markdown('</div>', unsafe_allow_html=True)

with col2:
    st.markdown(f'<div class="metric-container {"metric-container-red" if high_alerts > 0 else "metric-container-green"}">', unsafe_allow_html=True)
    st.metric("🚨 Alertas Activas", total_alerts, delta=f"{high_alerts} críticas", delta_color="inverse")
    st.markdown('</div>', unsafe_allow_html=True)

with col3:
    st.markdown('<div class="metric-container">', unsafe_allow_html=True)
    st.metric("📈 Ancho de Banda", f"{current_bandwidth:.2f} Mbps")
    st.markdown('</div>', unsafe_allow_html=True)

with col4:
    st.markdown('<div class="metric-container">', unsafe_allow_html=True)
    st.metric("⚡ Latencia Media", f"{current_latency:.1f} ms")
    st.markdown('</div>', unsafe_allow_html=True)

st.write("")
st.write("")

# 2. Gráficos de tendencias
col_chart1, col_chart2 = st.columns([3, 2])

with col_chart1:
    st.markdown("### 🌊 Tráfico de Red Reciente")
    if not stats_df.empty:
        fig_bw = px.area(stats_df, x="timestamp", y="bandwidth_mbps", 
                         labels={"timestamp": "Tiempo", "bandwidth_mbps": "Mbps"},
                         color_discrete_sequence=["#00b4d8"],
                         template="plotly_dark")
        fig_bw.update_layout(margin=dict(l=0, r=0, t=10, b=0), plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig_bw, use_container_width=True)
    else:
        st.info("Esperando datos de red recientes para generar gráfica...")

with col_chart2:
    st.markdown("### 🧬 Análisis de Amenazas")
    by_type = summary.get("by_type", {})
    if by_type:
        fig_types = px.pie(names=list(by_type.keys()), values=list(by_type.values()),
                           hole=0.5,
                           color_discrete_sequence=px.colors.sequential.Tealgrn,
                           template="plotly_dark")
        fig_types.update_layout(margin=dict(l=0, r=0, t=10, b=0), plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)")
        fig_types.update_traces(textposition='inside', textinfo='percent+label')
        st.plotly_chart(fig_types, use_container_width=True)
    else:
        st.success("🎉 No hay amenazas registradas en la base de datos.")

st.markdown("<br><hr><center><sub>Desarrollado para TFM Ciberseguridad UCLM • Luis Ignacio de Luna Gómez</sub></center>", unsafe_allow_html=True)

# -- Auto-Refresh --
if auto_refresh:
    time.sleep(DASHBOARD_REFRESH_RATE)
    st.rerun()
