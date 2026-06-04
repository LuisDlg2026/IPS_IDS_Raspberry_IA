import streamlit as st
import plotly.express as px
from src.dashboard.utils.data_loader import load_network_stats

st.set_page_config(page_title="Rendimiento de Red - IPS/IDS", page_icon="⚡", layout="wide")

st.markdown("""
<style>
    .speed-header {
        background: radial-gradient(circle at 10% 20%, #1e3c72 0%, #2a5298 90%);
        padding: 20px;
        border-radius: 12px;
        border-right: 5px solid #00b4d8;
        color: white;
    }
    .metric-speed {
        background: #111;
        padding: 15px;
        border-radius: 8px;
        box-shadow: 2px 2px 5px rgba(0,0,0,0.5);
        text-align: center;
        border-top: 3px solid #f39c12;
    }
</style>
""", unsafe_allow_html=True)

col_title, col_btn = st.columns([5, 1])
with col_title:
    st.markdown("""
    <div class="speed-header">
        <h1 style="margin-top:0;">⚡ Rendimiento y Telemetría</h1>
        <p style="margin-bottom:0; font-size: 1.1em; color: #ced4da;">Monitorización continua del tráfico RAW, ancho de banda saturado y estrés de la Raspberry Pi.</p>
    </div><br>
    """, unsafe_allow_html=True)
with col_btn:
    st.write("") # Espaciado
    if st.button("🔄 Refrescar Gráficos", use_container_width=True):
        st.rerun()

# Filtros
col_filtro, _ = st.columns([1, 3])
horas = col_filtro.selectbox("🔎 Ventana Temporal:", [1, 3, 6, 12, 24], index=1, format_func=lambda x: f"Últimas {x} horas de captura")

stats_df = load_network_stats(limit=1000, hours=horas)

if stats_df.empty:
    st.info("🕒 Esperando a que el Sniffer llene los bufferes... (Refresque en un minuto)")
else:
    # Métricas Top
    current = stats_df.iloc[-1]
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown('<div class="metric-speed">', unsafe_allow_html=True)
        st.metric("Tasa de Transferencia", f"{current['bandwidth_mbps']:.2f} Mbps")
        st.markdown('</div>', unsafe_allow_html=True)
    with col2:
        st.markdown('<div class="metric-speed" style="border-top: 3px solid #2980b9;">', unsafe_allow_html=True)
        st.metric("Latencia al Exterior", f"{current['latency_ms']:.1f} ms")
        st.markdown('</div>', unsafe_allow_html=True)
    with col3:
        st.markdown('<div class="metric-speed" style="border-top: 3px solid #e74c3c;">', unsafe_allow_html=True)
        st.metric("CPU (Raspberry Pi)", f"{current['cpu_percent']}%")
        st.markdown('</div>', unsafe_allow_html=True)
    with col4:
        st.markdown('<div class="metric-speed" style="border-top: 3px solid #27ae60;">', unsafe_allow_html=True)
        st.metric("Sockets TCP/UDP", current['active_connections'])
        st.markdown('</div>', unsafe_allow_html=True)
    
    st.divider()

    # Gráficos de Área con Plotly
    st.markdown("### 🌊 Histograma de Ancho de Banda")
    
    fig_bw = px.area(stats_df, x="timestamp", y="bandwidth_mbps", 
                    labels={"timestamp": "Escala Temporal", "bandwidth_mbps": "Ancho de Banda (Mbps)"},
                    color_discrete_sequence=["#8e44ad"],
                    template="plotly_dark")
    fig_bw.update_layout(margin=dict(l=0, r=0, t=10, b=0), plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)")
    
    st.plotly_chart(fig_bw, use_container_width=True)
    
    st.markdown("### 💻 Esfuerzo de Hardware Host")
    col_chart1, col_chart2 = st.columns(2)
    
    with col_chart1:
        fig_cpu = px.line(stats_df, x="timestamp", y="cpu_percent", 
                        title="Consumo de CPU (%)",
                        color_discrete_sequence=["#e67e22"],
                        template="plotly_dark")
        fig_cpu.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig_cpu, use_container_width=True)
        
    with col_chart2:
        fig_mem = px.line(stats_df, x="timestamp", y="memory_percent", 
                        title="Consumo de Memoria RAM (%)",
                        color_discrete_sequence=["#27ae60"],
                        template="plotly_dark")
        fig_mem.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig_mem, use_container_width=True)
