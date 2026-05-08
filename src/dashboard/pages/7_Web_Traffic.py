import streamlit as st
import pandas as pd
from src.dashboard.utils.data_loader import load_web_traffic, load_devices

st.set_page_config(page_title="Tráfico Web (DPI) - IPS/IDS", page_icon="🌐", layout="wide")

st.title("🌐 Auditoría de Tráfico Web (DPI)")
st.markdown("Monitorización en tiempo real de la navegación (Capa 7), extrayendo dominios visitados, consultas DNS, transferencias FTP y tráfico de correo, usando Inspección Profunda de Paquetes.")

# Refresco manual
col1, col2 = st.columns([8, 2])
with col2:
    if st.button("🔄 Actualizar Registros", use_container_width=True):
        st.rerun()

# Filtros
devices_df = load_devices()
device_ips = ["Todas las IPs"]
if not devices_df.empty:
    device_ips.extend(devices_df["ip"].dropna().unique().tolist())

col_f1, col_f2 = st.columns(2)
with col_f1:
    selected_ip = st.selectbox("Filtrar por IP Origen:", device_ips)
    
with col_f2:
    search_query = st.text_input("🔍 Buscar dominio o protocolo:", "")

st.divider()

# Cargar y mostrar datos
with st.spinner("Leyendo historial de navegación..."):
    df = load_web_traffic(limit=1000)

if df.empty:
    st.info("No se ha detectado tráfico web todavía. Navega por alguna página web o realiza una petición DNS desde algún dispositivo de la red.")
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
        st.warning("No hay registros que coincidan con los filtros.")
    else:
        # Colores por protocolo para la interfaz
        def color_protocol(val):
            color = ""
            if val == "DNS":
                color = "color: #3498db"
            elif val == "HTTPS":
                color = "color: #2ecc71"
            elif val == "HTTP":
                color = "color: #f1c40f"
            elif val == "FTP":
                color = "color: #e67e22"
            elif val == "SMTP":
                color = "color: #9b59b6"
            return color

        # Formatear la tabla
        display_df = df[["timestamp", "src_ip", "dst_ip", "protocol", "domain_url"]].copy()
        display_df.rename(columns={
            "timestamp": "Hora",
            "src_ip": "Origen",
            "dst_ip": "Destino",
            "protocol": "Protocolo",
            "domain_url": "Dominio / URL / Comando"
        }, inplace=True)
        
        # Ordenar por fecha descendente
        display_df = display_df.sort_values(by="Hora", ascending=False)
        
        st.dataframe(
            display_df.style.map(color_protocol, subset=['Protocolo']),
            use_container_width=True,
            hide_index=True,
            height=600
        )

        st.caption(f"Mostrando {len(display_df)} registros de navegación.")

# Métricas rápidas
if not df.empty:
    st.divider()
    st.subheader("Resumen Estadístico")
    
    m1, m2, m3 = st.columns(3)
    
    with m1:
        st.metric("Total Registros Web", len(df))
        
    with m2:
        top_protocol = df["protocol"].value_counts().index[0] if not df["protocol"].empty else "N/A"
        st.metric("Protocolo más usado", top_protocol)
        
    with m3:
        if "DNS" in df["protocol"].values or "HTTPS" in df["protocol"].values:
            # Filtrar solo dominios
            domains = df[df["protocol"].isin(["DNS", "HTTPS"])]["domain_url"]
            top_domain = domains.value_counts().index[0] if not domains.empty else "N/A"
            # Truncar si es muy largo
            if len(top_domain) > 30:
                top_domain = top_domain[:27] + "..."
            st.metric("Sitio Web más visitado", top_domain)
