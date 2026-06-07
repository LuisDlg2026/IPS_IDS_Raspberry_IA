import streamlit as st
import os
import psutil
import json
import time
import pandas as pd
from datetime import datetime
from src.dashboard.utils.data_loader import get_db, load_devices
from src.dashboard.utils.demo_data import (
    is_demo_mode, set_demo_mode, generate_demo_data, clear_demo_data
)
from src.dashboard.utils.styles import (
    inject_global_css, render_page_header, render_metric_card,
    render_section_divider, render_status_badge, render_footer, COLORS
)

st.set_page_config(page_title="Configuración - IPS/IDS", page_icon="⚙️", layout="wide")
inject_global_css()

# ── Header ──────────────────────────────────────────────────────
render_page_header(
    icon="⚙️",
    title="Panel de Configuración del Sistema",
    subtitle="Ajuste los parámetros operativos del motor de prevención y respuesta en caliente sin reiniciar servicios.",
    gradient="linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.95) 100%)",
    accent="linear-gradient(90deg, var(--accent-purple), var(--accent-blue))"
)

db = get_db()

# ═══════════════════════════════════════════════════════════════
# SECCIÓN 0: Alternador de Datos (Demo / Real)
# ═══════════════════════════════════════════════════════════════
render_section_divider("🔀 Modo del Dashboard (Fuente de Datos)")

demo_active = is_demo_mode(db)

# Estado actual de los datos en el dashboard
if demo_active:
    mode_label = "DEMOSTRACIÓN"
    mode_color = "#f59e0b"
    mode_bg = "rgba(245, 158, 11, 0.10)"
    mode_border = "rgba(245, 158, 11, 0.3)"
    mode_icon = "🧪"
    mode_desc = "El dashboard muestra datos simulados y sintéticos para pruebas visuales. Las capturas reales del IDS de la Raspberry Pi están pausadas."
else:
    mode_label = "PRODUCCIÓN"
    mode_color = "#22c55e"
    mode_bg = "rgba(34, 197, 94, 0.10)"
    mode_border = "rgba(34, 197, 94, 0.3)"
    mode_icon = "🔒"
    mode_desc = "El dashboard está consumiendo el tráfico real capturado directamente desde la interfaz de la Raspberry Pi."

st.html(f"""
<div style="
    display: flex;
    align-items: center;
    gap: 24px;
    padding: 20px 28px;
    background: {mode_bg};
    border: 1px solid {mode_border};
    border-radius: 16px;
    margin-bottom: 20px;
">
    <div style="
        font-size: 2.8rem;
        flex-shrink: 0;
        width: 64px;
        height: 64px;
        display: flex;
        align-items: center;
        justify-content: center;
        background: rgba(0,0,0,0.15);
        border-radius: 50%;
    ">{mode_icon}</div>
    <div>
        <div style="
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.3rem;
            font-weight: 800;
            color: {mode_color};
            letter-spacing: 0.06em;
        ">MODO {mode_label}</div>
        <div style="
            color: var(--text-muted);
            font-size: 0.88rem;
            margin-top: 4px;
            line-height: 1.4;
        ">{mode_desc}</div>
    </div>
</div>
""")

# Inicializar flags en session_state si no existen
if "confirm_activate_demo" not in st.session_state:
    st.session_state.confirm_activate_demo = False
if "confirm_activate_real" not in st.session_state:
    st.session_state.confirm_activate_real = False

col_demo1, col_demo2 = st.columns(2)

with col_demo1:
    if not demo_active:
        if st.button("🧪 Activar Modo Demostración", type="primary", use_container_width=True):
            st.session_state.confirm_activate_demo = True
            st.session_state.confirm_activate_real = False
    else:
        if st.button("🔄 Regenerar Datos de Demo", type="secondary", use_container_width=True):
            generate_demo_data(db)
            st.toast("✅ Datos de demostración regenerados.", icon="🔄")
            st.rerun()

with col_demo2:
    if demo_active:
        if st.button("🔒 Cambiar a Datos Reales", type="primary", use_container_width=True):
            st.session_state.confirm_activate_real = True
            st.session_state.confirm_activate_demo = False
    else:
        st.html("""
        <div style="
            padding: 10px 16px;
            background: rgba(34, 197, 94, 0.05);
            border: 1px solid rgba(34, 197, 94, 0.12);
            border-radius: 10px;
            color: var(--text-muted);
            font-size: 0.8rem;
            text-align: center;
        ">
            ℹ️ En modo producción, el dashboard muestra las métricas de tráfico real de la red.
        </div>
        """)

# --- Contenedores de Confirmación ---
if st.session_state.confirm_activate_demo:
    st.html("<div style='margin-top: 15px;'></div>")
    st.warning("⚠️ **¡ATENCIÓN!** Activar el Modo Demostración **ELIMINARÁ COMPLETAMENTE todos los datos de tráfico real** de la base de datos para evitar su mezcla. Esta acción es irreversible.")
    c_col1, c_col2 = st.columns(2)
    with c_col1:
        if st.button("🔴 Entiendo, proceder y borrar todo el tráfico real", type="primary", use_container_width=True):
            db.clear_all_data()
            set_demo_mode(db, True)
            generate_demo_data(db)
            st.session_state.confirm_activate_demo = False
            st.toast("✅ Datos reales borrados. Modo Demo activado.", icon="🧪")
            st.rerun()
    with c_col2:
        if st.button("Cancelar", key="cancel_demo", type="secondary", use_container_width=True):
            st.session_state.confirm_activate_demo = False
            st.rerun()

if st.session_state.confirm_activate_real:
    st.html("<div style='margin-top: 15px;'></div>")
    st.warning("⚠️ **¡ATENCIÓN!** Cambiar a Datos Reales **ELIMINARÁ COMPLETAMENTE todos los datos simulados** de la base de datos para iniciar una captura limpia. Esta acción es irreversible.")
    c_col1, c_col2 = st.columns(2)
    with c_col1:
        if st.button("🔴 Entiendo, proceder y borrar todos los datos demo", type="primary", use_container_width=True):
            db.clear_all_data()
            set_demo_mode(db, False)
            st.session_state.confirm_activate_real = False
            st.toast("✅ Datos de demostración borrados. Modo producción activo.", icon="🔒")
            st.rerun()
    with c_col2:
        if st.button("Cancelar", key="cancel_real", type="secondary", use_container_width=True):
            st.session_state.confirm_activate_real = False
            st.rerun()

# ═══════════════════════════════════════════════════════════════
# CARGAR PARÁMETROS ACTIVOS DESDE LA TABLA CONFIG
# ═══════════════════════════════════════════════════════════════
# Sección 1
cfg_capture_iface = db.get_config("capture_interface", "eth0", "str")
cfg_flow_window = db.get_config("flow_aggregation_window", 15, "int")
cfg_buffer_size = db.get_config("max_alerts_buffer_size", 1000, "int")

# Sección 2
cfg_active_model = db.get_config("active_model", "random_forest", "str")
cfg_min_conf_general = db.get_config("min_confidence_general", 0.50, "float")
cfg_min_conf_ddos = db.get_config("min_confidence_ddos", 0.60, "float")
cfg_min_conf_mitm = db.get_config("min_confidence_mitm", 0.50, "float")
cfg_min_conf_scan = db.get_config("min_confidence_scan", 0.40, "float")
cfg_sev_info_warn = db.get_config("severity_threshold_info_to_warn", 0.40, "float")
cfg_sev_warn_crit = db.get_config("severity_threshold_warn_to_crit", 0.75, "float")

# Sección 3
cfg_arp_interval = db.get_config("arp_passive_scan_interval", 5, "int")
cfg_nmap_enabled = db.get_config("nmap_active_scan_enabled", True, "bool")
cfg_nmap_use_sudo = db.get_config("nmap_use_sudo", False, "bool")
cfg_whitelist = db.get_config("whitelist_ips", "192.168.1.10, 192.168.1.99", "str")

# Sección 4
cfg_resp_target = db.get_config("active_response_target_ip", "", "str")
cfg_rules_applied = db.get_config("active_response_rules_applied", False, "bool")
cfg_resp_logs_str = db.get_config("active_response_logs", "[]", "str")

try:
    resp_logs = json.loads(cfg_resp_logs_str)
except:
    resp_logs = []

# Configuración de Intercepción Activa (MITM)
cfg_mitm_target = db.get_setting("mitm_target_ip", "")
cfg_mitm_enabled = db.get_setting("mitm_enabled", "0") == "1"
cfg_mitm_gateway = db.get_setting("mitm_gateway_ip", "")

# ═══════════════════════════════════════════════════════════════
# CONFIGURACIÓN OPERATIVA (4 SECCIONES COLAPSABLES)
# ═══════════════════════════════════════════════════════════════
render_section_divider("⚙️ Parámetros de Operación (CU-04)")

# Formulario principal de configuración
with st.form("settings_form"):

    # 🟢 SECCIÓN 1: Parámetros de Captura
    with st.expander("🔌 1. Parámetros de Captura", expanded=True):
        st.markdown("Ajuste los parámetros del motor de recolección de tráfico de red local.")
        
        # Obtener interfaces disponibles en el sistema de forma dinámica
        try:
            available_ifaces = list(psutil.net_if_addrs().keys())
            if not available_ifaces:
                available_ifaces = ["eth0", "wlan0", "lo"]
        except:
            available_ifaces = ["eth0", "wlan0", "lo"]
            
        try:
            iface_index = available_ifaces.index(cfg_capture_iface)
        except ValueError:
            iface_index = 0
            
        capture_iface = st.selectbox(
            "Interfaz de red activa:",
            options=available_ifaces,
            index=iface_index,
            help="Interfaz física por la cual el sniffer capturará los paquetes de red."
        )
        
        flow_window = st.slider(
            "Ventana de agregación de flujos (segundos):",
            min_value=5,
            max_value=60,
            value=cfg_flow_window,
            step=1,
            help="Intervalo temporal para agrupar paquetes en un flujo antes de realizar inferencia."
        )
        
        buffer_size = st.number_input(
            "Tamaño máximo del buffer circular de alertas en memoria:",
            min_value=100,
            max_value=10000,
            value=cfg_buffer_size,
            step=100,
            help="Cantidad máxima de alertas que el motor retendrá en su caché local en caliente."
        )

    # 🧠 SECCIÓN 2: Umbrales de Clasificación e Inferencia
    with st.expander("🧠 2. Modelo de IA y Umbrales de Inferencia", expanded=True):
        st.markdown("Defina el modelo de Inteligencia Artificial activo y los parámetros de inferencia.")
        
        # Selector de Modelo ML
        model_options = {
            "random_forest": "Random Forest (Clásico - Menor tasa de falsos positivos)",
            "decision_tree": "Decision Tree (Clasificación rápida)",
            "mlp": "Multi-Layer Perceptron (Red Neuronal - Generaliza mejor en tráfico real)",
            "lightgbm": "LightGBM (Modelo ligero de gradiente)",
            "xgboost": "XGBoost (Modelo avanzado de gradiente)"
        }
        
        try:
            model_index = list(model_options.keys()).index(cfg_active_model)
        except ValueError:
            model_index = 0
            
        active_model = st.selectbox(
            "Modelo de Inteligencia Artificial activo:",
            options=list(model_options.keys()),
            format_func=lambda x: model_options[x],
            index=model_index,
            help="Seleccione el algoritmo de Machine Learning que procesará las conexiones en tiempo real."
        )
        
        st.write("") # Espaciador
        
        col_c1, col_c2 = st.columns(2)
        
        with col_c1:
            st.markdown("#### Umbrales de Confianza por Tipo de Ataque")
            
            conf_general = st.slider(
                "Umbral general mínimo de confianza:",
                min_value=0.0, max_value=1.0, value=cfg_min_conf_general, step=0.05,
                help="Confianza mínima requerida por el clasificador para disparar cualquier tipo de alerta."
            )
            st.html("""
            <div style="color: var(--text-muted); font-size: 0.8rem; margin-top: -10px; margin-bottom: 15px;">
                💡 <strong>Impacto:</strong> Aumentarlo disminuye la tasa de falsos positivos en el sistema (menos ruido), pero incrementa la tasa de falsos negativos (ataques omitidos).
            </div>
            """)
            
            conf_ddos = st.slider(
                "Umbral de confianza para ataques DDoS (TCP/UDP/ICMP):",
                min_value=0.0, max_value=1.0, value=cfg_min_conf_ddos, step=0.05
            )
            st.html("""
            <div style="color: var(--text-muted); font-size: 0.8rem; margin-top: -10px; margin-bottom: 15px;">
                💡 <strong>Impacto:</strong> Filtra ráfagas rápidas de tráfico sospechoso. Un valor alto evita falsas alertas de congestión por tráfico legítimo de alta intensidad.
            </div>
            """)
            
            conf_mitm = st.slider(
                "Umbral de confianza para ataques MITM / Spoofing:",
                min_value=0.0, max_value=1.0, value=cfg_min_conf_mitm, step=0.05
            )
            st.html("""
            <div style="color: var(--text-muted); font-size: 0.8rem; margin-top: -10px; margin-bottom: 15px;">
                💡 <strong>Impacto:</strong> Un umbral bajo permite detectar rápidamente alteraciones anómalas en tablas ARP y DNS antes de que se consume la exfiltración.
            </div>
            """)
            
            conf_scan = st.slider(
                "Umbral de confianza para Escaneo de Puertos y Fingerprinting:",
                min_value=0.0, max_value=1.0, value=cfg_min_conf_scan, step=0.05
            )
            st.html("""
            <div style="color: var(--text-muted); font-size: 0.8rem; margin-top: -10px; margin-bottom: 15px;">
                💡 <strong>Impacto:</strong> Los escaneos son fases previas. Un valor moderado previene alertas por software benigno local realizando descubrimientos de red.
            </div>
            """)

        with col_c2:
            st.markdown("#### Umbrales de Transición de Severidad")
            
            sev_info_warn = st.slider(
                "Umbral de transición Informativo ➡️ Advertencia:",
                min_value=0.0, max_value=1.0, value=cfg_sev_info_warn, step=0.05,
                help="El nivel de confianza del ataque que cambia la alerta de Informativa (info/low) a Advertencia (medium/high)."
            )
            st.html("""
            <div style="color: var(--text-muted); font-size: 0.8rem; margin-top: -10px; margin-bottom: 15px;">
                💡 <strong>Impacto:</strong> Afecta la priorización. Si es muy bajo, muchas alertas rutinarias se catalogarán como Advertencias, aumentando el cansancio del operador.
            </div>
            """)
            
            sev_warn_crit = st.slider(
                "Umbral de transición Advertencia ➡️ Crítico:",
                min_value=0.0, max_value=1.0, value=cfg_sev_warn_crit, step=0.05,
                help="Nivel de confianza del ataque a partir del cual el evento se clasifica como Crítico (critical)."
            )
            st.html("""
            <div style="color: var(--text-muted); font-size: 0.8rem; margin-top: -10px; margin-bottom: 15px;">
                💡 <strong>Impacto:</strong> Define las alertas que dispararán alertas sonoras, notificaciones externas o el módulo de respuesta activa inmediata en la red.
            </div>
            """)

    # 📱 SECCIÓN 3: Inventario de Dispositivos
    with st.expander("📱 3. Inventario de Dispositivos y Lista Blanca", expanded=True):
        st.markdown("Configuración del escáner ARP y las exclusiones de auditoría de red.")
        
        arp_interval = st.slider(
            "Intervalo de escaneo ARP pasivo (minutos):",
            min_value=1,
            max_value=60,
            value=cfg_arp_interval,
            step=1,
            help="Frecuencia con la que el motor envía tramas de descubrimiento ARP para verificar el estado de los hosts."
        )
        
        nmap_enabled = st.toggle(
            "Activar escaneo Nmap activo para nuevos dispositivos descubiertos",
            value=cfg_nmap_enabled,
            help="Lanza automáticamente un escaneo asíncrono Nmap (SO, puertos abiertos, servicios) al descubrir un host nuevo."
        )
        
        nmap_use_sudo = st.toggle(
            "Ejecutar Nmap con Sudo (Modo Privilegiado)",
            value=cfg_nmap_use_sudo,
            help="Permite a Nmap usar el motor de detección de S.O. (-O) y escaneos de puertos sigilosos TCP SYN (-sS). Requiere privilegios elevados o configurar Nmap sin contraseña en sudoers."
        )
        
        whitelist = st.text_area(
            "Dispositivos en Lista Blanca (IPs separadas por comas):",
            value=cfg_whitelist,
            help="Las direcciones IP listadas aquí no generarán alertas de anomalías del modelo de IA bajo ninguna circunstancia."
        )

    # 🛡️ SECCIÓN 4: Módulo de Respuesta Activa (IPS)
    with st.expander("🛡️ 4. Módulo de Respuesta Activa (IPS)", expanded=True):
        st.warning("⚠️ **ADVERTENCIA EXPLÍCITA:** La activación del cortafuegos o reglas de restricción activa aplica de forma inmediata reglas en el sistema iptables de la Raspberry Pi, lo que interrumpirá totalmente la conectividad de los dispositivos objetivo seleccionados.")
        
        # Cargar los dispositivos online
        online_devices = db.get_devices(online_only=True)
        device_ips = [""]
        if online_devices:
            # Filtrar la propia IP si es conocida o la pasarela común
            device_ips.extend([d['ip'] for d in online_devices if d['ip'] not in ("127.0.0.1", "192.168.1.1")])
            
        try:
            target_resp_idx = device_ips.index(cfg_resp_target)
        except ValueError:
            target_resp_idx = 0
            
        resp_target_ip = st.selectbox(
            "Seleccionar dispositivo para aplicar restricción de conectividad:",
            options=device_ips,
            index=target_resp_idx,
            help="Dirección IP del host anómalo que desea aislar."
        )
        
        col_btn1, col_btn2 = st.columns(2)
        with col_btn1:
            rules_state_text = "Activas" if cfg_rules_applied else "Inactivas"
            st.markdown(f"**Estado de Reglas iptables en el IPS:** `{rules_state_text}`")
        with col_btn2:
            st.write("") # Espaciador
            
        # Tabla de Logs de Respuesta Activa
        st.markdown("##### Historial de Acciones de Respuesta Ejecutadas")
        if resp_logs:
            log_df = pd.DataFrame(resp_logs)
            st.dataframe(
                log_df,
                column_config={
                    "timestamp": st.column_config.TextColumn("Fecha/Hora"),
                    "action": st.column_config.TextColumn("Acción"),
                    "ip": st.column_config.TextColumn("IP Objetivo"),
                    "details": st.column_config.TextColumn("Detalle Técnico"),
                },
                hide_index=True,
                use_container_width=True
            )
        else:
            st.info("💡 No se han registrado acciones de mitigación activa recientemente.")

    # 🕵️‍♂️ SECCIÓN 5: Módulo de Intercepción Activa (MITM)
    with st.expander("🕵️‍♂️ 5. Módulo de Intercepción Activa (MITM / ARP Spoofing)", expanded=True):
        st.info("💡 **Redes conmutadas (Switches):** Si la Raspberry Pi no está en modo puente físico, un Switch impedirá que escuche el tráfico de otros hosts. Activar ARP Spoofing redirige temporalmente el tráfico del host seleccionado hacia la Raspberry Pi para que el IDS/IPS y el motor de IA lo analicen.")
        
        mitm_enabled = st.toggle(
            "Habilitar Intercepción Activa (ARP Spoofing)",
            value=cfg_mitm_enabled,
            help="Envenena las tablas ARP del dispositivo objetivo y del Router para interceptar su tráfico."
        )
        
        # Reutilizar dispositivos online para seleccionar
        try:
            target_mitm_idx = device_ips.index(cfg_mitm_target)
        except ValueError:
            target_mitm_idx = 0
            
        mitm_target_ip = st.selectbox(
            "Seleccionar dispositivo objetivo para intercepción (MITM):",
            options=device_ips,
            index=target_mitm_idx,
            help="IP del dispositivo móvil, IoT o PC del cual se quiere auditar el tráfico."
        )
        
        mitm_gateway_ip = st.text_input(
            "Dirección IP del Router (Gateway) [Opcional]:",
            value=cfg_mitm_gateway,
            placeholder="Dejar en blanco para auto-detectar",
            help="Si se deja vacío, la Raspberry Pi resolverá automáticamente la puerta de enlace por defecto."
        )

    # Botón general de guardado de formulario
    st.markdown("<div style='text-align: right; margin-top: 15px;'>", unsafe_allow_html=True)
    save_submitted = st.form_submit_button("💾 Guardar Configuración", type="primary")
    st.markdown("</div>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════
# PROCESAR GUARDADO DE CONFIGURACIÓN
# ═══════════════════════════════════════════════════════════════
if save_submitted:
    # Sección 1
    db.set_config("capture_interface", capture_iface, "str")
    db.set_config("flow_aggregation_window", flow_window, "int")
    db.set_config("max_alerts_buffer_size", buffer_size, "int")
    
    # Sección 2
    db.set_config("active_model", active_model, "str")
    db.set_config("min_confidence_general", conf_general, "float")
    db.set_config("min_confidence_ddos", conf_ddos, "float")
    db.set_config("min_confidence_mitm", conf_mitm, "float")
    db.set_config("min_confidence_scan", conf_scan, "float")
    db.set_config("severity_threshold_info_to_warn", sev_info_warn, "float")
    db.set_config("severity_threshold_warn_to_crit", sev_warn_crit, "float")
    
    # Sección 3
    db.set_config("arp_passive_scan_interval", arp_interval, "int")
    db.set_config("nmap_active_scan_enabled", nmap_enabled, "bool")
    db.set_config("nmap_use_sudo", nmap_use_sudo, "bool")
    db.set_config("whitelist_ips", whitelist, "str")
    
    # Sección 4
    db.set_config("active_response_target_ip", resp_target_ip, "str")
    
    # Sección 5 (MITM - Guardados en la tabla 'settings' para uso del Spoofer)
    db.set_setting("mitm_target_ip", mitm_target_ip)
    db.set_setting("mitm_enabled", "1" if mitm_enabled else "0")
    db.set_setting("mitm_gateway_ip", mitm_gateway_ip)
    
    st.toast("⚙️ Configuración guardada correctamente en la tabla SQLite 'config' y 'settings'.", icon="💾")
    st.success("¡Configuración guardada! Los cambios transaccionales se han persistido e integrado en caliente.")
    time.sleep(1)
    st.rerun()

# ═══════════════════════════════════════════════════════════════
# BOTONES DE ACCIÓN PARA EL IPS (MANEJO DIRECTO DE REGLAS IPTABLES)
# ═══════════════════════════════════════════════════════════════
col_ipt1, col_ipt2 = st.columns(2)

with col_ipt1:
    if not cfg_rules_applied:
        if st.button("🔥 Activar Reglas iptables (Manual)", type="primary", use_container_width=True, disabled=(not cfg_resp_target)):
            # Aplicar reglas en el host e insertar log
            new_log = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "BLOQUEO IPTABLES",
                "ip": cfg_resp_target,
                "details": f"Mitigación activa manual. Comando: iptables -A FORWARD -s {cfg_resp_target} -j DROP."
            }
            resp_logs.append(new_log)
            
            db.set_config("active_response_rules_applied", True, "bool")
            db.set_config("active_response_logs", json.dumps(resp_logs), "str")
            
            st.toast(f"🔥 Regla iptables aplicada para bloquear a {cfg_resp_target}", icon="🛡️")
            st.rerun()
    else:
        if st.button("⏹️ Desactivar Reglas iptables", type="secondary", use_container_width=True):
            # Revocar e insertar log
            new_log = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "REVOCADO IPTABLES",
                "ip": cfg_resp_target,
                "details": f"Revocación de regla manual. Comando: iptables -D FORWARD -s {cfg_resp_target} -j DROP."
            }
            resp_logs.append(new_log)
            
            db.set_config("active_response_rules_applied", False, "bool")
            db.set_config("active_response_logs", json.dumps(resp_logs), "str")
            
            st.toast(f"⏹️ Reglas iptables eliminadas para {cfg_resp_target}", icon="🔓")
            st.rerun()

with col_ipt2:
    if st.button("🚨 Limpiar Historial de Mitigación IPS", type="secondary", use_container_width=True):
        db.set_config("active_response_logs", "[]", "str")
        st.toast("🧹 Historial de mitigación purgado.", icon="🗑️")
        st.rerun()

# ═══════════════════════════════════════════════════════════════
# BLOQUE ADICIONAL: Estado Físico de Base de Datos
# ═══════════════════════════════════════════════════════════════
st.write("")
render_section_divider("💾 Mantenimiento Físico de Base de Datos")
db_stats = db.get_db_stats()

col1, col2, col3, col4 = st.columns(4)
with col1:
    render_metric_card("🚨", "Alertas Históricas", str(db_stats.get("alerts", 0)), accent="red")
with col2:
    render_metric_card("📱", "Dispositivos en Caché", str(db_stats.get("devices", 0)), accent="blue")
with col3:
    render_metric_card("📊", "Registros Rendimiento", str(db_stats.get("network_stats", 0)), accent="purple")
with col4:
    render_metric_card("💾", "Tamaño en Disco", f"{db_stats.get('file_size_mb', 0)} MB", accent="cyan")

st.write("")
col_m1, col_m2 = st.columns(2)

with col_m1:
    if st.button("🧹 Purgar registros antiguos (> 30 días)", type="secondary", use_container_width=True):
        db.cleanup(days=30)
        st.success("Limpieza completada exitosamente.")
        st.rerun()

with col_m2:
    if st.button("🚨 Purgar Alertas RAW", type="secondary", use_container_width=True):
        db.clear_alerts()
        st.success("Todas las alertas han sido eliminadas.")
        st.rerun()

render_footer()
