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
