import streamlit as st
import os
from src.dashboard.utils.data_loader import get_db

st.set_page_config(page_title="Configuración - IPS/IDS", page_icon="⚙️", layout="wide")

st.title("⚙️ Ajustes del Sistema")
st.markdown("Administra la base de datos y la configuración general del IDS/IPS.")

st.subheader("Base de Datos (SQLite)")

db = get_db()
stats = db.get_db_stats()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Alertas", stats.get("alerts", 0))
col2.metric("Dispositivos", stats.get("devices", 0))
col3.metric("Muestras de Red", stats.get("network_stats", 0))
col4.metric("Tamaño DB", f"{stats.get('file_size_mb', 0)} MB")

st.divider()

st.subheader("Mantenimiento")

col_m1, col_m2 = st.columns(2)

with col_m1:
    if st.button("🧹 Limpiar registros antiguos (> 30 días)", type="primary"):
        db.cleanup(days=30)
        st.success("Limpieza completada exitosamente.")
        st.rerun()
        
with col_m2:
    if st.button("🚨 Borrar TODAS las Alertas", type="primary"):
        db.clear_alerts()
        st.success("Todas las alertas han sido eliminadas.")
        st.rerun()
        
st.divider()

st.subheader("Configuración del Modelo ML")
st.info("Para cambiar el modelo activo, modifica la variable de entorno `IDS_MODEL` antes de iniciar el backend.")

current_model = os.environ.get("IDS_MODEL", "random_forest")
st.text_input("Modelo Activo Actual", value=current_model, disabled=True)

st.divider()

st.subheader("🕵️‍♂️ Intercepción Activa (Modo MITM / ARP Spoofing)")
st.warning("⚠️ **ATENCIÓN:** Esta función engaña a la red para redirigir el tráfico del dispositivo objetivo a través de la Raspberry Pi. Si la Raspberry Pi se apaga o hay un error, el dispositivo objetivo podría perder conexión a Internet.")

# Leer estado actual de la DB
mitm_enabled = db.get_setting("mitm_enabled") == "1"
current_target = db.get_setting("mitm_target_ip", "")

# Obtener dispositivos para el desplegable
devices = db.get_devices(online_only=True)
device_options = [""]
if devices:
    device_options.extend([d['ip'] for d in devices if d['ip'] != "192.168.1.1" and d['ip'] != "127.0.0.1"])

col_sp1, col_sp2 = st.columns([3, 1])

with col_sp1:
    try:
        default_idx = device_options.index(current_target) if current_target in device_options else 0
    except ValueError:
        default_idx = 0
        
    target_ip = st.selectbox(
        "Dispositivo Objetivo (IP):", 
        options=device_options, 
        index=default_idx,
        help="Selecciona la IP del dispositivo del que quieres capturar el tráfico web."
    )

with col_sp2:
    st.write("")
    st.write("")
    if not mitm_enabled:
        if st.button("▶️ Activar Intercepción", type="primary", use_container_width=True) and target_ip:
            db.set_setting("mitm_target_ip", target_ip)
            db.set_setting("mitm_enabled", "1")
            st.rerun()
    else:
        if st.button("⏹️ Detener Intercepción", type="secondary", use_container_width=True):
            db.set_setting("mitm_enabled", "0")
            st.rerun()

if mitm_enabled:
    st.success(f"📡 Interceptando tráfico de: **{current_target}**")
