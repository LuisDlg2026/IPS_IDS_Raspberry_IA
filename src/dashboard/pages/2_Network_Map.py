import streamlit as st
from pyvis.network import Network
import tempfile
import pandas as pd
from src.dashboard.utils.data_loader import load_devices

st.set_page_config(page_title="Mapa de Red - IPS/IDS", page_icon="🌐", layout="wide")

st.markdown("""
<style>
    .map-header {
        background-color: #2b2d42;
        padding: 20px;
        border-radius: 12px;
        border-left: 5px solid #8d99ae;
        color: white;
    }
    .legend-box {
        display: inline-block;
        width: 15px;
        height: 15px;
        margin-right: 5px;
        border-radius: 3px;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="map-header">
    <h1 style="margin-top:0;">🗺️ Topología de Red Interactiva</h1>
    <p>Visualización del perímetro de red local mediante grafos físicos. Pase el ratón sobre los nodos para obtener trazabilidad forense.</p>
</div><br>
""", unsafe_allow_html=True)

# Cargar dispositivos
devices_df = load_devices()

if devices_df.empty:
    st.warning("📡 Inicializando radares... No hay dispositivos descubiertos por el crawler todavía.")
else:
    col_map, col_legend = st.columns([5, 1])
    
    with col_legend:
        st.markdown("### 🔑 Leyenda")
        st.markdown('<div><span class="legend-box" style="background-color:#00b4d8;"></span> Gateway Core</div>', unsafe_allow_html=True)
        st.markdown('<div><span class="legend-box" style="background-color:#2ecc71;"></span> Nodo Limpio</div>', unsafe_allow_html=True)
        st.markdown('<div><span class="legend-box" style="background-color:#f1c40f;"></span> Riesgo Medio</div>', unsafe_allow_html=True)
        st.markdown('<div><span class="legend-box" style="background-color:#e74c3c;"></span> Riesgo CRÍTICO</div>', unsafe_allow_html=True)
        st.markdown('<div><span class="legend-box" style="background-color:#555555;"></span> Desconectado</div>', unsafe_allow_html=True)

    with col_map:
        # Crear red pyvis
        net = Network(height="650px", width="100%", bgcolor="#141414", font_color="white")
        net.barnes_hut(gravity=-8000, spring_length=200)

        # Añadir nodo central (Gateway/Router)
        net.add_node("gateway", label="🌐\nCore Gateway", shape="hexagon", color="#00b4d8", size=50)

        # Añadir dispositivos periféricos
        for _, row in devices_df.iterrows():
            mac = row.get("mac", "unknown")
            ip = row.get("ip", "unknown")
            vendor = row.get("vendor", "Unknown")
            risk = row.get("risk_level", "low")
            online = row.get("is_online", 0)
            hostname = row.get("hostname")
            
            # Color basado en riesgo y conexión
            if not online:
                color = "#555555" # Gris oscuro (Offline)
            else:
                color = "#2ecc71" # Verde (low)
                if risk == "medium":
                    color = "#f1c40f" # Amarillo
                elif risk in ["high", "critical"]:
                    color = "#e74c3c" # Rojo
                
            display_name = hostname if hostname and hostname != "None" else vendor
            label = f"{display_name}\n{ip}"
            
            # Info extra al hacer hover
            title = f"🔌 IP: {ip}\n📡 MAC: {mac}\n💻 SO: {row.get('os_guess', 'Desconocido')}\n⚠️ Riesgo: {risk.upper()}"
            
            net.add_node(mac, label=label, title=title, color=color, shape="dot", size=30)
            net.add_edge("gateway", mac, color="#333333" if not online else "#00b4d8", arrows="to")

        # Guardar temporalmente como HTML y mostrarlo en Streamlit
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp:
            net.save_graph(tmp.name)
            with open(tmp.name, "r", encoding="utf-8") as f:
                html_data = f.read()
        
        import streamlit.components.v1 as components
        components.html(html_data, height=670)
