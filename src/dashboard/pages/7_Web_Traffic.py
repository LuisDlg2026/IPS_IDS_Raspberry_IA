import streamlit as st
import pandas as pd
from src.dashboard.utils.data_loader import load_web_traffic, load_devices

import time
from src.config import DASHBOARD_REFRESH_RATE

st.set_page_config(page_title="Tráfico Web (DPI) - IPS/IDS", page_icon="🌐", layout="wide")

st.markdown("""
<style>
    .dpi-header {
        background: linear-gradient(135deg, #1b263b 0%, #0d1b2a 100%);
        padding: 20px;
        border-radius: 12px;
        color: white;
        border: 1px solid #415a77;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    .metric-card {
        background-color: #1e1e1e;
        padding: 15px;
        border-radius: 8px;
        text-align: center;
        border-bottom: 2px solid #e0e1dd;
    }
</style>
""", unsafe_allow_html=True)

# Toggle de Auto-Refresco
st.sidebar.markdown(f"⏱️ **Auto-Refresco:** `{DASHBOARD_REFRESH_RATE}s`")
auto_refresh = st.sidebar.toggle("Habilitar Auto-Refresco", value=True)

st.markdown("""
<div class="dpi-header">
    <h1 style="margin-top:0;">🌐 Auditoría de Navegación y Deep Packet Inspection</h1>
    <p style="font-size: 1.1em; color: #a9bcd0;">Inspección de tráfico de capa de Aplicación (Capa 7 OSI) capturado mediante SNI e interrogatorios DNS nativos.</p>
</div><br>
""", unsafe_allow_html=True)

col1, col2 = st.columns([8, 2])
with col2:
    if auto_refresh:
        st.info("🔄 Activo (Streaming)")
    else:
        st.warning("⏸️ Modo Historico")

# Filtros
devices_df = load_devices()
device_ips = ["Todas las IPs"]
if not devices_df.empty:
    device_ips.extend(devices_df["ip"].dropna().unique().tolist())

col_f1, col_f2 = st.columns(2)
with col_f1:
    selected_ip = st.selectbox("📍 Rastrear nodo concreto (IP Origen):", device_ips)
    
with col_f2:
    search_query = st.text_input("🔍 Buscar término, app o protocolo (ej: whatsapp, netflix, DNS):", "")

st.divider()

# Cargar y mostrar datos
with st.spinner("Decodificando buffers de tráfico..."):
    df = load_web_traffic(limit=1000)

if df.empty:
    st.info("Aún no hay intercepciones de navegación HTTP/S o DNS en la base de datos.")
else:
    # Aplicar filtros
    if selected_ip != "Todas las IPs":
        df = df[df["src_ip"] == selected_ip]
        
    if search_query:
        mask = (
            df["domain_url"].str.contains(search_query, case=False, na=False) |
            df["protocol"].str.contains(search_query, case=False, na=False)
        )
        df = df[mask]

    if df.empty:
        st.warning("No hay registros que coincidan con los filtros de búsqueda.")
    else:
        # Colores por protocolo para la interfaz
        def color_protocol(val):
            color = ""
            if val == "DNS":
                color = "color: #00b4d8; font-weight: bold;"
            elif val == "HTTPS":
                color = "color: #21c354; font-weight: bold;"
            elif val == "HTTP":
                color = "color: #ffa421; font-weight: bold;"
            elif val == "FTP":
                color = "color: #ff4b4b; font-weight: bold;"
            elif val == "SMTP":
                color = "color: #9b59b6; font-weight: bold;"
            return color

        # Formatear la tabla
        display_df = df[["timestamp", "src_ip", "dst_ip", "protocol", "domain_url"]].copy()
        display_df.rename(columns={
            "timestamp": "Hora",
            "src_ip": "Origen",
            "dst_ip": "Destino",
            "protocol": "Protocolo",
            "domain_url": "Dominio Resoluto / Petición"
        }, inplace=True)
        
        # Ordenar por fecha descendente
        display_df = display_df.sort_values(by="Hora", ascending=False)
        
        st.dataframe(
            display_df.style.map(color_protocol, subset=['Protocolo']),
            use_container_width=True,
            hide_index=True,
            height=600
        )

        st.caption(f"Visualizando spool temporal: **{len(display_df)} tramas extraídas**.")

# Métricas rápidas
if not df.empty:
    st.divider()
    st.markdown("### 📊 Inteligencia de Navegación Extraída")
    
    m1, m2, m3 = st.columns(3)
    
    with m1:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Total Intercepciones Hoy", len(df))
        st.markdown('</div>', unsafe_allow_html=True)
        
    with m2:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        top_protocol = df["protocol"].value_counts().index[0] if not df["protocol"].empty else "N/A"
        st.metric("Protocolo Dominante", top_protocol)
        st.markdown('</div>', unsafe_allow_html=True)
        
    with m3:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        if "DNS" in df["protocol"].values or "HTTPS" in df["protocol"].values:
            # Filtrar solo dominios
            domains = df[df["protocol"].isin(["DNS", "HTTPS"])]["domain_url"]
            top_domain = domains.value_counts().index[0] if not domains.empty else "N/A"
            # Truncar si es muy largo
            if len(top_domain) > 30:
                top_domain = top_domain[:27] + "..."
            st.metric("Top Destino Mundial", top_domain)
        st.markdown('</div>', unsafe_allow_html=True)

# -- Auto-Refresh --
if auto_refresh:
    time.sleep(DASHBOARD_REFRESH_RATE)
    st.rerun()
