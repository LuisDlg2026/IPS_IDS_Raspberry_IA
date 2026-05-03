import streamlit as st
from src.dashboard.utils.data_loader import load_devices

st.set_page_config(page_title="Inventario - IPS/IDS", page_icon="📱", layout="wide")

st.title("📱 Inventario de Dispositivos")
st.markdown("Lista de todo el hardware detectado en la red mediante el descubrimiento activo y pasivo.")

# Filtros
online_only = st.checkbox("Mostrar solo dispositivos Online", value=False)

devices_df = load_devices(online_only=online_only)

if devices_df.empty:
    st.info("No se han descubierto dispositivos en la red todavía.")
else:
    # Métricas rápidas
    total = len(devices_df)
    online = len(devices_df[devices_df['is_online'] == 1])
    vuln = len(devices_df[devices_df['risk_level'].isin(['medium', 'high', 'critical'])])
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Descubiertos", total)
    col2.metric("Conectados (Online)", online)
    col3.metric("Riesgo Medio/Alto", vuln)
    
    st.divider()

    # Formateo visual
    def color_risk(val):
        color = 'white'
        if val in ['critical', 'high']: color = '#ff4b4b'
        elif val == 'medium': color = '#ffa421'
        elif val == 'low': color = '#21c354'
        return f'background-color: {color}; color: black;'

    def format_online(val):
        return '✅ Sí' if val == 1 else '❌ No'

    # Preparar el dataframe para mostrar
    display_df = devices_df.copy()
    display_df['is_online'] = display_df['is_online'].apply(format_online)
    
    styled_df = display_df.style.map(color_risk, subset=['risk_level'])
    
    st.dataframe(
        styled_df,
        column_config={
            "mac": st.column_config.TextColumn("Dirección MAC"),
            "ip": st.column_config.TextColumn("Dirección IP"),
            "vendor": st.column_config.TextColumn("Fabricante"),
            "os_guess": st.column_config.TextColumn("Sistema Operativo"),
            "risk_level": st.column_config.TextColumn("Nivel de Riesgo"),
            "is_online": st.column_config.TextColumn("Conectado"),
            "last_seen": st.column_config.DatetimeColumn("Última vez visto", format="DD/MM/YYYY HH:mm:ss"),
        },
        hide_index=True,
        use_container_width=True
    )
