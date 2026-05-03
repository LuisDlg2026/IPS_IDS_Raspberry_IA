import streamlit as st
from pyvis.network import Network
import tempfile
import pandas as pd
from src.dashboard.utils.data_loader import load_devices

st.set_page_config(page_title="Mapa de Red - IPS/IDS", page_icon="🌐", layout="wide")

st.title("🌐 Mapa de Red (Topología)")
st.markdown("Visualización interactiva de los dispositivos descubiertos y su nivel de riesgo.")

# Cargar dispositivos
devices_df = load_devices()

if devices_df.empty:
    st.warning("No hay dispositivos registrados en la red. Asegúrate de que el módulo de descubrimiento esté funcionando.")
else:
    # 1. Crear el grafo interactivo con Pyvis
    st.subheader("Topología Interactiva")
    
    # Crear red pyvis
    net = Network(height="600px", width="100%", bgcolor="#222222", font_color="white")
    net.barnes_hut(gravity=-8000, spring_length=200)

    # Añadir nodo central (Gateway/Router)
    net.add_node("gateway", label="Gateway/Router", shape="database", color="#00a8e8", size=40)

    # Añadir dispositivos periféricos
    for _, row in devices_df.iterrows():
        mac = row.get("mac", "unknown")
        ip = row.get("ip", "unknown")
        vendor = row.get("vendor", "Unknown")
        risk = row.get("risk_level", "low")
        
        # Color basado en riesgo
        color = "#2ecc71" # Verde (low)
        if risk == "medium":
            color = "#f1c40f" # Amarillo
        elif risk == "high" or risk == "critical":
            color = "#e74c3c" # Rojo
            
        label = f"{vendor}\n{ip}"
        
        # Info extra al hacer hover
        title = f"MAC: {mac}\nSO: {row.get('os_guess', 'N/A')}\nRiesgo: {risk.upper()}"
        
        net.add_node(mac, label=label, title=title, color=color, shape="dot", size=25)
        net.add_edge("gateway", mac, color="#555555")

    # Guardar temporalmente como HTML y mostrarlo en Streamlit
    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp:
        net.save_graph(tmp.name)
        with open(tmp.name, "r", encoding="utf-8") as f:
            html_data = f.read()
    
    import streamlit.components.v1 as components
    components.html(html_data, height=620)

    # 2. Detalles en tabla
    st.divider()
    st.subheader("Detalles de Dispositivos")
    st.dataframe(
        devices_df[["ip", "mac", "vendor", "os_guess", "risk_level", "is_online", "last_seen"]],
        use_container_width=True,
        hide_index=True
    )
