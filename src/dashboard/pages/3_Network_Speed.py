import streamlit as st
import plotly.express as px
from src.dashboard.utils.data_loader import load_network_stats

st.set_page_config(page_title="Velocidad de Red - IPS/IDS", page_icon="⚡", layout="wide")

st.title("⚡ Velocidad y Rendimiento de Red")
st.markdown("Monitorización en tiempo real del uso de ancho de banda y rendimiento del sistema base.")

# Filtros
col_filtro, _ = st.columns([1, 3])
horas = col_filtro.selectbox("Periodo de tiempo", [1, 3, 6, 12, 24], index=1, format_func=lambda x: f"Últimas {x} horas")

stats_df = load_network_stats(limit=1000, hours=horas)

if stats_df.empty:
    st.info("Aún no hay suficientes datos de red recolectados en este periodo.")
else:
    # Métricas Top
    current = stats_df.iloc[-1]
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Ancho de Banda Actual", f"{current['bandwidth_mbps']:.2f} Mbps")
    col2.metric("Latencia", f"{current['latency_ms']:.1f} ms")
    col3.metric("Uso CPU", f"{current['cpu_percent']}%")
    col4.metric("Conexiones Activas", current['active_connections'])
    
    st.divider()

    # Gráficos principales
    st.subheader("Tráfico de Red a lo largo del tiempo")
    
    fig_bw = px.area(stats_df, x="timestamp", y="bandwidth_mbps", 
                    labels={"timestamp": "Hora", "bandwidth_mbps": "Megabits por Segundo (Mbps)"},
                    color_discrete_sequence=["#8e44ad"])
    
    st.plotly_chart(fig_bw, use_container_width=True)
    
    st.subheader("Métricas del Sistema Host (Raspberry Pi)")
    col_chart1, col_chart2 = st.columns(2)
    
    with col_chart1:
        fig_cpu = px.line(stats_df, x="timestamp", y="cpu_percent", 
                        title="Consumo de CPU (%)",
                        color_discrete_sequence=["#e67e22"])
        st.plotly_chart(fig_cpu, use_container_width=True)
        
    with col_chart2:
        fig_mem = px.line(stats_df, x="timestamp", y="memory_percent", 
                        title="Consumo de Memoria RAM (%)",
                        color_discrete_sequence=["#27ae60"])
        st.plotly_chart(fig_mem, use_container_width=True)
