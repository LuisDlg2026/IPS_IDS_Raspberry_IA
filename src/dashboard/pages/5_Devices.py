import streamlit as st
import time
from src.dashboard.utils.data_loader import load_devices
from src.config import DASHBOARD_REFRESH_RATE

st.set_page_config(page_title="Inventario - IPS/IDS", page_icon="📱", layout="wide")

st.markdown("""
<style>
    .kpi-devices {
        background-color: #1e1e1e;
        border-radius: 8px;
        padding: 15px;
        border-bottom: 4px solid #4a4a4a;
    }
    .kpi-online {
        border-bottom: 4px solid #21c354;
    }
    .kpi-vuln {
        border-bottom: 4px solid #ff4b4b;
    }
</style>
""", unsafe_allow_html=True)

# Toggle de Auto-Refresco
st.sidebar.markdown(f"⏱️ **Auto-Refresco:** `{DASHBOARD_REFRESH_RATE}s`")
auto_refresh = st.sidebar.toggle("Habilitar Auto-Refresco", value=True)

st.title("📱 Directorio de Hosts y Dispositivos")
st.markdown("Auditoría pasiva y activa de todo el hardware detectado operando en tu red.")

# Filtros
col_f1, col_f2 = st.columns([1, 4])
with col_f1:
    online_only = st.checkbox("🟢 Sólo dispositivos online", value=False)

devices_df = load_devices(online_only=online_only)

if devices_df.empty:
    st.info("Buscando dispositivos físicos en la capa de red...")
else:
    # Métricas rápidas
    total = len(devices_df)
    online = len(devices_df[devices_df['is_online'] == 1])
    vuln = len(devices_df[devices_df['risk_level'].isin(['medium', 'high', 'critical'])])
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown('<div class="kpi-devices">', unsafe_allow_html=True)
        st.metric("📡 Total Histórico Descubiertos", total)
        st.markdown('</div>', unsafe_allow_html=True)
    with col2:
        st.markdown('<div class="kpi-devices kpi-online">', unsafe_allow_html=True)
        st.metric("📶 Conectados (Vivientes)", online)
        st.markdown('</div>', unsafe_allow_html=True)
    with col3:
        st.markdown('<div class="kpi-devices kpi-vuln">', unsafe_allow_html=True)
        st.metric("🔥 Riesgo Medio/Alto", vuln)
        st.markdown('</div>', unsafe_allow_html=True)
    
    st.write("<br>", unsafe_allow_html=True)

    # Formateo visual
    def color_risk(val):
        color = 'transparent'
        if val in ['critical', 'high']: color = '#450000'
        elif val == 'medium': color = '#4a2f00'
        elif val == 'low': color = '#003310'
        return f'background-color: {color}; color: white; border: 1px solid #777;'

    def format_online(val):
        return '🟢 Activo' if val == 1 else '💤 Dormido'

    # Preparar el dataframe para mostrar
    display_df = devices_df.copy()
    display_df['is_online'] = display_df['is_online'].apply(format_online)
    
    # Convertir string JSON de open_ports a lista real para renderizarla bien
    import json
    def parse_ports(val):
        if not val: return []
        try: return json.loads(val)
        except: return []
        
    display_df['open_ports'] = display_df['open_ports'].apply(parse_ports)
    
    styled_df = display_df.style.map(color_risk, subset=['risk_level'])
    
    st.dataframe(
        styled_df,
        column_config={
            "mac": st.column_config.TextColumn("Dir. Física (MAC)"),
            "ip": st.column_config.TextColumn("Dir. Lógica (IP)"),
            "hostname": st.column_config.TextColumn("Alias / DNS"),
            "notes": st.column_config.TextColumn("📝 Tags"),
            "vendor": st.column_config.TextColumn("Hardware / OUI"),
            "os_guess": st.column_config.TextColumn("Kernel / SO"),
            "open_ports": st.column_config.ListColumn("Puertos (TCP)"),
            "risk_level": st.column_config.TextColumn("Nivel de Exposición"),
            "is_online": st.column_config.TextColumn("Status"),
            "last_seen": st.column_config.DatetimeColumn("Último Eco", format="DD/MM/YYYY - HH:mm:ss"),
        },
        height=400,
        hide_index=True,
        use_container_width=True
    )

    st.divider()

    # Formulario para editar dispositivos manualmente
    st.markdown("### 🔧 Operaciones Individuales de Nodo")
    
    col_sel, col_action = st.columns([1, 1.5])
    
    with col_sel:
        # Selector de IPs disponibles
        available_ips = devices_df['ip'].dropna().unique().tolist()
        selected_ip = st.selectbox("Apuntar radar al Dispositivo:", available_ips)
    
    with col_action:
        with st.expander("📝 Etiquetado Semántico Manual", expanded=False):
            with st.form("edit_device_form", clear_on_submit=False):
                st.info("Etiqueta la nevera o el movil para encontrarlo más rápido a gusto visual.")
                new_hostname = st.text_input("Alias (Ej. Portátil-Mamá):")
                new_notes = st.text_input("Comentarios:")
                
                submit = st.form_submit_button("Guardar en base de datos")
                
                if submit and selected_ip:
                    from src.dashboard.utils.data_loader import get_db
                    get_db().update_device_label(selected_ip, new_hostname, new_notes)
                    st.success(f"Dato persistido.")
                    st.rerun()

        with st.expander("🕵️‍♂️ Nmap Action Scanner (Force Ping)", expanded=False):
            st.warning("**Aviso de Invasión Acústica:** Esto puede disparar antivirus remotos si atacas a la familia u oficinas colaterales.")
            if st.button("Lanzar barrido TCP Full (Bloqueante)", type="primary"):
                if selected_ip:
                    with st.spinner(f"Escaneando espectro radiofónico y TCP en {selected_ip}..."):
                        from src.crawler.nmap_scanner import NmapScanner
                        from src.dashboard.utils.data_loader import get_db
                        
                        scanner = NmapScanner(db=get_db())
                        result = scanner.scan_device(selected_ip)
                        
                        if result and (result.get("open_ports") or result.get("os_guess")):
                            get_db().save_device(result)
                            st.success(f"OS Encontrado: {result.get('os_guess', 'Desconocido')}")
                            time.sleep(2.5)
                            st.rerun()
                        else:
                            st.error("El host rebotó todos los paquetes (Stealth Mode / Firewall encendido).")

# -- Auto-Refresh --
if auto_refresh:
    time.sleep(DASHBOARD_REFRESH_RATE)
    st.rerun()
