import streamlit as st
import pandas as pd
import time
import os
from datetime import datetime, timedelta
import plotly.express as px
from src.dashboard.utils.data_loader import load_network_stats, load_alerts, get_db
from src.dashboard.utils.demo_data import is_demo_mode
from src.dashboard.utils.styles import (
    inject_global_css, render_page_header, render_metric_card,
    render_section_divider, render_footer, get_plotly_layout, COLORS
)

st.set_page_config(page_title="Rendimiento de Red - IPS/IDS", page_icon="⚡", layout="wide")
inject_global_css()

# Auto-Refresco
st.sidebar.markdown("⏱️ **Auto-Refresco (Métricas en vivo):** `10s`")
auto_refresh = st.sidebar.toggle("Habilitar Auto-Refresco", value=True)

# ── Header ──────────────────────────────────────────────────────
col_title, col_btn = st.columns([5, 1])
with col_title:
    render_page_header(
        icon="⚡",
        title="Rendimiento y Telemetría SOC",
        subtitle="Monitorización en tiempo casi real de la interfaz de red de la Raspberry Pi e historial de throughput.",
        gradient="linear-gradient(135deg, rgba(245, 158, 11, 0.1) 0%, rgba(15, 23, 42, 0.95) 50%, rgba(76, 201, 240, 0.08) 100%)",
        accent="linear-gradient(90deg, var(--accent-amber), var(--accent-cyan))"
    )
with col_btn:
    st.write("")
    st.write("")
    if st.button("🔄 Refrescar", use_container_width=True):
        st.rerun()

# ── Calcular Métricas en Vivo leyendo /proc/net/dev o psutil ──
def read_proc_net_dev():
    if os.path.exists("/proc/net/dev"):
        try:
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()
            total_recv_bytes = 0
            total_recv_packets = 0
            total_sent_bytes = 0
            total_sent_packets = 0
            for line in lines[2:]:
                if ":" in line:
                    parts = line.split(":")
                    if parts[0].strip() == "lo":
                        continue
                    stats = parts[1].split()
                    if len(stats) >= 10:
                        total_recv_bytes += int(stats[0])
                        total_recv_packets += int(stats[1])
                        total_sent_bytes += int(stats[8])
                        total_sent_packets += int(stats[9])
            return {
                "bytes_recv": total_recv_bytes,
                "packets_recv": total_recv_packets,
                "bytes_sent": total_sent_bytes,
                "packets_sent": total_sent_packets,
            }
        except Exception:
            pass
    return None

# Inicializar y calcular delta de velocidad
if "prev_live_stats" not in st.session_state:
    live_stats = read_proc_net_dev()
    if live_stats is None:
        try:
            import psutil
            net = psutil.net_io_counters()
            live_stats = {
                "bytes_recv": net.bytes_recv,
                "packets_recv": net.packets_recv,
                "bytes_sent": net.bytes_sent,
                "packets_sent": net.packets_sent
            }
        except Exception:
            live_stats = {"bytes_recv": 0, "packets_recv": 0, "bytes_sent": 0, "packets_sent": 0}
    st.session_state.prev_live_stats = live_stats
    st.session_state.prev_live_time = time.time()
    time.sleep(0.2)

live_stats = read_proc_net_dev()
if live_stats is None:
    try:
        import psutil
        net = psutil.net_io_counters()
        live_stats = {
            "bytes_recv": net.bytes_recv,
            "packets_recv": net.packets_recv,
            "bytes_sent": net.bytes_sent,
            "packets_sent": net.packets_sent
        }
    except Exception:
        live_stats = {"bytes_recv": 0, "packets_recv": 0, "bytes_sent": 0, "packets_sent": 0}

now_time = time.time()
elapsed = now_time - st.session_state.prev_live_time
if elapsed <= 0:
    elapsed = 0.2

# Deltas
recv_bytes_delta = live_stats["bytes_recv"] - st.session_state.prev_live_stats["bytes_recv"]
sent_bytes_delta = live_stats["bytes_sent"] - st.session_state.prev_live_stats["bytes_sent"]
recv_pkts_delta = live_stats["packets_recv"] - st.session_state.prev_live_stats["packets_recv"]
sent_pkts_delta = live_stats["packets_sent"] - st.session_state.prev_live_stats["packets_sent"]

if recv_bytes_delta < 0: recv_bytes_delta = 0
if sent_bytes_delta < 0: sent_bytes_delta = 0
if recv_pkts_delta < 0: recv_pkts_delta = 0
if sent_pkts_delta < 0: sent_pkts_delta = 0

live_throughput_down = (recv_bytes_delta * 8 / elapsed) / 1_000_000
live_throughput_up = (sent_bytes_delta * 8 / elapsed) / 1_000_000
live_pps = (recv_pkts_delta + sent_pkts_delta) / elapsed

# Conexiones / flujos en vivo
try:
    import psutil
    live_flows = len(psutil.net_connections(kind='inet'))
except Exception:
    live_flows = 0

# Guardar estado para el siguiente ciclo
st.session_state.prev_live_stats = live_stats
st.session_state.prev_live_time = now_time

# ── 1. Métricas Top (Tiempo Real) ───────────────────────────
col1, col2, col3, col4 = st.columns(4)
with col1:
    render_metric_card("📥", "Throughput Entrante", f"{live_throughput_down:.2f} Mbps", accent="cyan")
with col2:
    render_metric_card("📤", "Throughput Saliente", f"{live_throughput_up:.2f} Mbps", accent="purple")
with col3:
    render_metric_card("📦", "Paquetes / Segundo", f"{int(live_pps)} pps", accent="amber")
with col4:
    render_metric_card("⚡", "Flujos Activos (Live)", str(live_flows), accent="blue")

# ── 2. Histórico de Ancho de Banda y PPS ────────────────────────────
render_section_divider("Evolución del Ancho de Banda (Última Hora)")

stats_df = load_network_stats(limit=500)

if stats_df.empty or len(stats_df) < 2:
    st.markdown("""
    <div style="
        text-align: center; padding: 60px 40px;
        background: rgba(245, 158, 11, 0.05);
        border: 1px solid rgba(245, 158, 11, 0.15);
        border-radius: 16px;
    ">
        <div style="font-size: 3rem; margin-bottom: 12px; animation: sentinel-float 3s ease-in-out infinite; display: inline-block;">⏳</div>
        <div style="color: var(--accent-amber); font-weight: 600; font-size: 1.1rem;">Esperando datos del sniffer...</div>
        <div style="color: var(--text-muted); font-size: 0.9rem; margin-top: 6px;">Refresca en un minuto para ver las primeras métricas históricas</div>
    </div>
    """, unsafe_allow_html=True)
else:
    # Filtrar última hora
    stats_df = stats_df.sort_values("timestamp")
    since_60m = datetime.now() - timedelta(minutes=60)
    hour_df = stats_df[stats_df["timestamp"] >= since_60m].copy()
    
    if len(hour_df) >= 2:
        # Calcular velocidades a partir del historial acumulado
        hour_df["time_diff"] = hour_df["timestamp"].diff().dt.total_seconds()
        hour_df["bytes_sent_diff"] = hour_df["bytes_sent"].diff()
        hour_df["bytes_recv_diff"] = hour_df["bytes_recv"].diff()
        hour_df["pkts_sent_diff"] = hour_df["packets_sent"].diff()
        hour_df["pkts_recv_diff"] = hour_df["packets_recv"].diff()
        
        # Limpiar
        hour_df.loc[hour_df["time_diff"] <= 0, "time_diff"] = 30.0
        hour_df.loc[hour_df["bytes_sent_diff"] < 0, "bytes_sent_diff"] = 0
        hour_df.loc[hour_df["bytes_recv_diff"] < 0, "bytes_recv_diff"] = 0
        hour_df.loc[hour_df["pkts_sent_diff"] < 0, "pkts_sent_diff"] = 0
        hour_df.loc[hour_df["pkts_recv_diff"] < 0, "pkts_recv_diff"] = 0
        
        # Calcular Mbps y PPS
        hour_df["incoming_mbps"] = (hour_df["bytes_recv_diff"] * 8 / hour_df["time_diff"]) / 1_000_000
        hour_df["outgoing_mbps"] = (hour_df["bytes_sent_diff"] * 8 / hour_df["time_diff"]) / 1_000_000
        hour_df["incoming_pps"] = hour_df["pkts_recv_diff"] / hour_df["time_diff"]
        hour_df["outgoing_pps"] = hour_df["pkts_sent_diff"] / hour_df["time_diff"]
        
        hour_df["incoming_mbps"] = hour_df["incoming_mbps"].fillna(0.0)
        hour_df["outgoing_mbps"] = hour_df["outgoing_mbps"].fillna(0.0)
        hour_df["incoming_pps"] = hour_df["incoming_pps"].fillna(0.0)
        hour_df["outgoing_pps"] = hour_df["outgoing_pps"].fillna(0.0)
        
        # Agrupar a granularidad de 1 minuto
        hour_df["minute"] = hour_df["timestamp"].dt.floor("1min")
        df_min = hour_df.groupby("minute").mean(numeric_only=True).reset_index()
        
        # Eje X temporal relativo (minutos transcurridos)
        max_time = df_min["minute"].max()
        df_min["relative_min"] = (df_min["minute"] - max_time).dt.total_seconds() / 60.0
        
        # Gráfica 1: Área apilada del Ancho de Banda
        df_melted_bw = df_min.melt(
            id_vars=["relative_min"],
            value_vars=["incoming_mbps", "outgoing_mbps"],
            var_name="Dirección",
            value_name="Ancho de Banda (Mbps)"
        )
        df_melted_bw["Dirección"] = df_melted_bw["Dirección"].map({
            "incoming_mbps": "Entrante (Descarga)",
            "outgoing_mbps": "Saliente (Carga)"
        })
        
        fig_bw = px.area(
            df_melted_bw,
            x="relative_min",
            y="Ancho de Banda (Mbps)",
            color="Dirección",
            color_discrete_map={
                "Entrante (Descarga)": COLORS["accent_cyan"],
                "Saliente (Carga)": COLORS["accent_purple"]
            },
            labels={"relative_min": "Tiempo Relativo (minutos)", "Ancho de Banda (Mbps)": "Ancho de Banda (Mbps)"}
        )
        layout_bw = get_plotly_layout()
        layout_bw["margin"] = dict(l=0, r=0, t=10, b=0)
        fig_bw.update_layout(**layout_bw)
        st.plotly_chart(fig_bw, use_container_width=True)
        
        # Gráfica 2: Área apilada de Paquetes por Segundo
        render_section_divider("Evolución de Paquetes por Segundo (Última Hora)")
        
        df_melted_pps = df_min.melt(
            id_vars=["relative_min"],
            value_vars=["incoming_pps", "outgoing_pps"],
            var_name="Dirección",
            value_name="Paquetes por Segundo (PPS)"
        )
        df_melted_pps["Dirección"] = df_melted_pps["Dirección"].map({
            "incoming_pps": "Entrante (Recibido)",
            "outgoing_pps": "Saliente (Enviado)"
        })
        
        fig_pps = px.area(
            df_melted_pps,
            x="relative_min",
            y="Paquetes por Segundo (PPS)",
            color="Dirección",
            color_discrete_map={
                "Entrante (Recibido)": COLORS["accent_amber"],
                "Saliente (Enviado)": COLORS["accent_rose"]
            },
            labels={"relative_min": "Tiempo Relativo (minutos)", "Paquetes por Segundo (PPS)": "Paquetes por Segundo (PPS)"}
        )
        layout_pps = get_plotly_layout()
        layout_pps["margin"] = dict(l=0, r=0, t=10, b=0)
        fig_pps.update_layout(**layout_pps)
        st.plotly_chart(fig_pps, use_container_width=True)
    else:
        st.info("📊 Acumulando historial del sniffer para generar histogramas...")

# ── 3. Tabla de Flujos Activos de Mayor Volumen ─────────────────────
render_section_divider("Flujos de Comunicación de Mayor Volumen (Top 10)")

# Traer alertas recientes (últimos 15 minutos)
since_alerts = (datetime.now() - timedelta(minutes=15)).isoformat()
alerts_df = load_alerts(limit=100, since=since_alerts)

def get_active_flows(alerts_df, demo_active=False):
    flows = []
    
    # Procesar flujos de alerta reales
    if not alerts_df.empty:
        for _, row in alerts_df.iterrows():
            flow_key = row.get("flow_key", "")
            proto = "TCP"
            port = "80"
            if flow_key:
                parts = flow_key.split(":")
                if parts[0] in ["TCP", "UDP", "ICMP", "ARP"]:
                    proto = parts[0]
                if "->" in flow_key:
                    try:
                        dst_part = flow_key.split("->")[1]
                        dst_subparts = dst_part.split(":")
                        if len(dst_subparts) >= 2:
                            port = dst_subparts[1]
                    except Exception:
                        pass
            
            n_packets = row.get("n_packets", 10)
            if not isinstance(n_packets, (int, float)):
                n_packets = 10
                
            bytes_est = n_packets * 850
            
            flows.append({
                "src_ip": row.get("src_ip", "0.0.0.0"),
                "dst_ip": row.get("dst_ip", "0.0.0.0"),
                "port": port,
                "protocol": proto,
                "bytes": bytes_est,
                "classification": row.get("attack_type", "Unknown").replace("Normal", "Normal (Benigno)")
            })
            
    # Añadir flujos normales de simulación para realismo y variedad (solo en modo demostración)
    if demo_active:
        normal_traffic = [
            ("192.168.1.100", "142.250.184.4", "443", "TCP", 1250000),
            ("192.168.1.20", "192.168.1.1", "554", "TCP", 8900000),
            ("192.168.1.30", "192.168.1.1", "502", "TCP", 340000),
            ("192.168.1.100", "8.8.8.8", "53", "UDP", 45000),
            ("192.168.1.200", "192.168.1.1", "22", "TCP", 67000),
            ("192.168.1.100", "13.107.4.52", "443", "TCP", 2300000),
            ("192.168.1.10", "192.168.1.1", "80", "TCP", 12000),
            ("192.168.1.11", "192.168.1.1", "80", "TCP", 15000),
            ("192.168.1.200", "1.1.1.1", "53", "UDP", 8000),
            ("192.168.1.30", "192.168.1.200", "80", "TCP", 450000),
        ]
        
        for src, dst, port, proto, b_val in normal_traffic:
            # Evitar duplicados
            if not any(f["src_ip"] == src and f["dst_ip"] == dst and f["port"] == port for f in flows):
                flows.append({
                    "src_ip": src,
                    "dst_ip": dst,
                    "port": port,
                    "protocol": proto,
                    "bytes": b_val,
                    "classification": "Normal (Benigno)"
                })
            
    # Ordenar por bytes y tomar los top 10
    if not flows:
        return pd.DataFrame()
        
    flows = sorted(flows, key=lambda x: x["bytes"], reverse=True)
    return pd.DataFrame(flows[:10])

db = get_db()
demo_active = is_demo_mode(db)
flows_df = get_active_flows(alerts_df, demo_active=demo_active)

if flows_df.empty:
    st.info("💡 No hay flujos activos registrados en este momento.")
else:
    # Formatear bytes a formato legible
    def format_bytes(val):
        if val >= 1_000_000:
            return f"{val / 1_000_000:.2f} MB"
        elif val >= 1_000:
            return f"{val / 1_000:.1f} KB"
        else:
            return f"{val} B"
            
    flows_df["bytes_formatted"] = flows_df["bytes"].apply(format_bytes)
    
    # Mostrar tabla estilizada
    st.dataframe(
        flows_df[["src_ip", "dst_ip", "port", "protocol", "bytes_formatted", "classification"]],
        column_config={
            "src_ip": st.column_config.TextColumn("IP Origen"),
            "dst_ip": st.column_config.TextColumn("IP Destino"),
            "port": st.column_config.TextColumn("Puerto Destino"),
            "protocol": st.column_config.TextColumn("Protocolo"),
            "bytes_formatted": st.column_config.TextColumn("Volumen Transferido"),
            "classification": st.column_config.TextColumn("Clasificación IDS"),
        },
        hide_index=True,
        use_container_width=True
    )

render_footer()

# Auto-Refresco
if auto_refresh:
    time.sleep(10)
    st.rerun()
