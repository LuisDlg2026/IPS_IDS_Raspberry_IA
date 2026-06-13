import streamlit as st
from pyvis.network import Network
import tempfile
import time
import pandas as pd
from datetime import datetime, timedelta
from src.dashboard.utils.data_loader import load_devices, load_alerts
from src.dashboard.utils.styles import (
    inject_global_css, render_page_header, render_metric_card,
    render_section_divider, render_legend_item, render_footer,
    COLORS
)
from src.config import DASHBOARD_REFRESH_RATE

st.set_page_config(page_title="Mapa de Red - IPS/IDS", page_icon="🗺️", layout="wide")
inject_global_css()

# Auto-Refresco
st.sidebar.markdown(f"⏱️ **Auto-Refresco:** `{DASHBOARD_REFRESH_RATE}s`")
auto_refresh = st.sidebar.toggle("Habilitar Auto-Refresco", value=True)

# ── Header ──────────────────────────────────────────────────────
render_page_header(
    icon="🗺️",
    title="Topología de Red Interactiva",
    subtitle="Visualización del perímetro de red local y flujos de comunicación con superposición de alertas en tiempo real.",
    gradient="linear-gradient(135deg, rgba(76, 201, 240, 0.1) 0%, rgba(15, 23, 42, 0.95) 60%, rgba(124, 58, 237, 0.08) 100%)",
    accent="linear-gradient(90deg, var(--accent-blue), var(--accent-purple))"
)

# Colores del mapa alineados con el sistema de diseño
MAP_COLORS = {
    "gateway": COLORS["accent_blue"],
    "clean": "#10b981",         # Verde (Limpio)
    "warning": "#f59e0b",       # Naranja (Advertencia)
    "critical": "#ef4444",      # Rojo (Crítico)
    "medium_high_risk": "#8b5cf6", # Púrpura (Riesgo medio/alto, sin alertas activas)
    "offline": "#475569",       # Gris oscuro (Offline)
    "edge_normal": "rgba(76, 201, 240, 0.4)",
    "edge_warning": "rgba(245, 158, 11, 0.6)",
    "edge_critical": "rgba(239, 68, 68, 0.6)",
}

# Selector de Ventana Temporal
st.write("")
window_option = st.selectbox(
    "Seleccionar Ventana Temporal para el Grafo",
    ["Última hora", "Últimas 6 horas", "Últimas 24 horas"],
    index=0
)

# Mapeo de ventana a horas
hours_map = {
    "Última hora": 1,
    "Últimas 6 horas": 6,
    "Últimas 24 horas": 24
}
hours = hours_map[window_option]
since = (datetime.now() - timedelta(hours=hours)).isoformat()

# Cargar dispositivos y alertas
devices_df = load_devices()
alerts_df = load_alerts(limit=20000, since=since)

if devices_df.empty:
    st.markdown(f"""
    <div style="
        text-align: center; padding: 60px 40px;
        background: rgba(76, 201, 240, 0.05);
        border: 1px solid rgba(76, 201, 240, 0.15);
        border-radius: 16px;
    ">
        <div style="font-size: 3rem; margin-bottom: 12px; animation: sentinel-float 3s ease-in-out infinite; display: inline-block;">📡</div>
        <div style="color: var(--accent-blue); font-weight: 600; font-size: 1.1rem;">Inicializando radares...</div>
        <div style="color: var(--text-muted); font-size: 0.9rem; margin-top: 6px;">No hay dispositivos descubiertos por el crawler todavía</div>
    </div>
    """, unsafe_allow_html=True)
else:
    # Construir mapa de nodos
    nodes_info = {}
    
    # 1. Añadir dispositivos locales conocidos
    for _, row in devices_df.iterrows():
        ip = row.get("ip")
        if not ip:
            continue
            
        # Función para limpiar valores nulos de Pandas (NaN/None)
        def clean_val(val, default=""):
            if pd.isna(val) or str(val).strip().lower() in ("nan", "none", ""):
                return default
            return str(val).strip()
            
        nodes_info[ip] = {
            "type": "local",
            "mac": row.get("mac", "unknown"),
            "vendor": clean_val(row.get("vendor"), "Desconocido"),
            "hostname": clean_val(row.get("hostname"), None),
            "risk_level": row.get("risk_level", "low"),
            "is_online": row.get("is_online", 1),
            "os": clean_val(row.get("os_guess"), "Desconocido"),
            "alerts_count": 0,
            "critical_alerts": 0,
            "last_activity": row.get("last_seen", "N/A"),
            "flow_count": 0,
        }
        
    # 2. Registrar flujos y alertas
    flows_generated = {}
    edges_dict = {}
    
    if not alerts_df.empty:
        for _, row in alerts_df.iterrows():
            src = row.get("src_ip")
            dst = row.get("dst_ip")
            severity = row.get("severity", "info").lower()
            ts = row.get("timestamp")
            n_packets = row.get("n_packets", 1)
            if not isinstance(n_packets, (int, float)):
                n_packets = 1
                
            if not src or not dst:
                continue
                
            # Registrar flujo saliente
            flows_generated[src] = flows_generated.get(src, 0) + 1
            
            # Registrar IPs externas/desconocidas que intervengan en alertas
            for ip in [src, dst]:
                if ip not in nodes_info:
                    nodes_info[ip] = {
                        "type": "external",
                        "mac": "N/A",
                        "vendor": "Externo/Desconocido",
                        "hostname": None,
                        "risk_level": "medium" if severity in ["critical", "high"] else "low",
                        "is_online": 1,
                        "os": "N/A",
                        "alerts_count": 0,
                        "critical_alerts": 0,
                        "last_activity": ts,
                        "flow_count": 0,
                    }
                
                # Superponer alertas
                nodes_info[ip]["alerts_count"] += 1
                if severity == "critical":
                    nodes_info[ip]["critical_alerts"] += 1
                
                # Actualizar última actividad
                curr_act = nodes_info[ip]["last_activity"]
                if curr_act == "N/A" or str(ts) > str(curr_act):
                    nodes_info[ip]["last_activity"] = ts
            
            # Guardar arista
            edge_key = (src, dst)
            if edge_key not in edges_dict:
                edges_dict[edge_key] = {
                    "packets": 0,
                    "count": 0,
                    "severity": "info"
                }
            edges_dict[edge_key]["packets"] += n_packets
            edges_dict[edge_key]["count"] += 1
            if severity in ["critical", "high"]:
                edges_dict[edge_key]["severity"] = severity

    # Actualizar flujos generados en el mapa
    for ip, flow_cnt in flows_generated.items():
        if ip in nodes_info:
            nodes_info[ip]["flow_count"] = flow_cnt

    # ── KPIs de Red ─────────────────────────────────────────────
    total_nodes = len(nodes_info)
    nodes_with_alerts = sum(1 for info in nodes_info.values() if info["alerts_count"] > 0)
    nodes_critical = sum(1 for info in nodes_info.values() if info["critical_alerts"] > 0)
    active_flows = len(edges_dict)

    col_k1, col_k2, col_k3, col_k4 = st.columns(4)
    with col_k1:
        render_metric_card("📡", "Nodos Activos", str(total_nodes), accent="blue")
    with col_k2:
        render_metric_card("⚡", "Comunicaciones (Flujos)", str(active_flows), accent="cyan")
    with col_k3:
        render_metric_card("⚠️", "Nodos con Alertas", str(nodes_with_alerts), accent="amber" if nodes_with_alerts > 0 else "green", glow=(nodes_with_alerts > 0))
    with col_k4:
        render_metric_card("💀", "Nodos Críticos", str(nodes_critical), accent="red" if nodes_critical > 0 else "green", glow=(nodes_critical > 0))

    render_section_divider(f"Grafo de Topología ({window_option.lower()})")

    col_map, col_legend = st.columns([5, 1])

    with col_legend:
        st.markdown("#### 🔑 Leyenda")
        st.markdown(render_legend_item(MAP_COLORS["gateway"], "Core Gateway"), unsafe_allow_html=True)
        st.markdown(render_legend_item(MAP_COLORS["clean"], "Limpio (Riesgo Bajo)"), unsafe_allow_html=True)
        st.markdown(render_legend_item(MAP_COLORS["medium_high_risk"], "Riesgo Medio / Alto"), unsafe_allow_html=True)
        st.markdown(render_legend_item(MAP_COLORS["warning"], "Advertencia (Alerta)"), unsafe_allow_html=True)
        st.markdown(render_legend_item(MAP_COLORS["critical"], "Crítico (Ataque IA)"), unsafe_allow_html=True)
        st.markdown(render_legend_item(MAP_COLORS["offline"], "Desconectado (Offline)"), unsafe_allow_html=True)

    with col_map:
        # Inicializar red pyvis
        net = Network(height="650px", width="100%", bgcolor=COLORS["bg_deep"], font_color=COLORS["text_primary"])
        net.barnes_hut(gravity=-3000, spring_length=150)

        # Añadir nodos
        for ip, info in nodes_info.items():
            hostname = info.get("hostname")
            vendor = info.get("vendor") or "Desconocido"
            
            # Identificar Gateway (usualmente 192.168.1.1 o localhost)
            is_gw = (ip == "192.168.1.1" or info.get("mac") == "localhost")
            
            display_name = hostname if (hostname and hostname != "None" and hostname != "") else vendor
            if is_gw:
                display_name = f"🌐 Gateway ({display_name})"
                
            label = f"{display_name}\n{ip}"

            # Coloreado dinámico
            if info["alerts_count"] > 0:
                if info["critical_alerts"] > 0:
                    color = MAP_COLORS["critical"]
                else:
                    color = MAP_COLORS["warning"]
            else:
                if info["is_online"] == 0:
                    color = MAP_COLORS["offline"]
                elif info["risk_level"] == "low":
                    color = MAP_COLORS["clean"]
                else:
                    color = MAP_COLORS["medium_high_risk"]

            if is_gw:
                color = MAP_COLORS["gateway"]

            # Tamaño proporcional a flujos generados
            flows_gen = info.get("flow_count", 0)
            size = 18 + min(flows_gen * 4, 32)
            if is_gw:
                size = 40

            # Tooltip interactivo
            mac_addr = info.get("mac", "unknown")
            os_guess = info.get("os", "Desconocido")
            title = f"🔌 IP: {ip}\n📡 MAC: {mac_addr}\n🏢 Fabricante: {vendor}\n💻 SO: {os_guess}\n⚠️ Alertas: {info['alerts_count']}\n⏱️ Última actividad: {info['last_activity']}"

            shape = "hexagon" if is_gw else "dot"
            net.add_node(ip, label=label, title=title, color=color, shape=shape, size=size)

        # Añadir aristas
        for (src, dst), stats in edges_dict.items():
            packets = stats["packets"]
            # Grosor proporcional a volumen de tráfico
            thickness = 1 + min(int(packets / 100), 8)
            
            # Color de aristas según severidad de alerta asociada
            sev = stats["severity"]
            if sev == "critical":
                edge_color = MAP_COLORS["edge_critical"]
            elif sev in ["high", "medium"]:
                edge_color = MAP_COLORS["edge_warning"]
            else:
                edge_color = MAP_COLORS["edge_normal"]

            net.add_edge(src, dst, width=thickness, color=edge_color, arrows="to")

        # Guardar y renderizar HTML
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp:
            net.save_graph(tmp.name)
            with open(tmp.name, "r", encoding="utf-8") as f:
                html_data = f.read()

        import streamlit.components.v1 as components
        components.html(html_data, height=670)

    # ── Panel Lateral: Inspección de Nodo ──
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🔍 Inspección de Dispositivo")

    selected_ip = st.sidebar.selectbox(
        "Seleccionar IP del Mapa",
        options=["Ninguno"] + sorted(list(nodes_info.keys())),
        index=0
    )

    if selected_ip != "Ninguno":
        info = nodes_info[selected_ip]
        st.sidebar.markdown(f"#### 🖥️ {selected_ip}")
        
        # Atributos del dispositivo
        st.sidebar.markdown(f"**Nombre/Host:** `{info.get('hostname') or info.get('vendor') or 'Desconocido'}`")
        st.sidebar.markdown(f"**Fabricante:** {info.get('vendor') or 'Desconocido'}")
        st.sidebar.markdown(f"**MAC:** `{info.get('mac', 'Desconocida')}`")
        st.sidebar.markdown(f"**Nivel de Riesgo:** `{info.get('risk_level', 'low').upper()}`")
        
        # Alertas asociadas
        alerts_cnt = info.get("alerts_count", 0)
        crit_cnt = info.get("critical_alerts", 0)
        st.sidebar.markdown(f"**Alertas (Ventana):** `{alerts_cnt}` (Críticas: `{crit_cnt}`)")
        
        # Último timestamp de actividad
        last_act = info.get("last_activity", "N/A")
        if isinstance(last_act, datetime):
            last_act_str = last_act.strftime("%d/%m/%Y %H:%M:%S")
        else:
            last_act_str = str(last_act)
        st.sidebar.markdown(f"**Última Actividad:** `{last_act_str}`")
        
        if info.get("os") and info.get("os") != "Desconocido":
            st.sidebar.markdown(f"**S.O. Detectado:** {info.get('os')}")
    else:
        st.sidebar.info("💡 Pasa el cursor sobre un nodo del mapa para ver sus detalles rápidos, o selecciónalo en el menú de arriba para una auditoría detallada de su estado y nivel de riesgo.")

render_footer()

# Auto-Refresco
if auto_refresh:
    time.sleep(DASHBOARD_REFRESH_RATE)
    st.rerun()
