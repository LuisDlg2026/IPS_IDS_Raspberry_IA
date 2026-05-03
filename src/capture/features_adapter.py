"""
Adaptador de features: convierte paquetes de red capturados con scapy
en los vectores de features que el modelo ML espera.

El modelo fue entrenado con features del dataset Edge-IIoTset que usan
nomenclatura de Wireshark/tshark. Este módulo mapea campos de scapy
a esas features.

Features del modelo (36):
    arp.opcode, icmp.seq_le, mqtt.protoname, tcp.options,
    http.request.version, tcp.dstport, mqtt.topic, dns.qry.name.len,
    http.request.method, http.response, tcp.connection.rst,
    tcp.flags.ack, tcp.payload, http.request.full_uri, dns.qry.name,
    mqtt.conack.flags, tcp.len, tcp.checksum, http.file_data,
    tcp.connection.syn, tcp.ack_raw, icmp.transmit_timestamp,
    tcp.connection.synack, http.referer, udp.time_delta,
    http.content_length, tcp.flags, tcp.seq, http.request.uri.query,
    udp.stream, dns.qry.qu, udp.port, icmp.checksum,
    tcp.srcport, mqtt.msg, tcp.ack
"""

import logging
import time
from collections import defaultdict
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class FlowAggregator:
    """
    Agrega paquetes individuales en flujos de red y calcula features.

    Un flujo se define como: (src_ip, dst_ip, src_port, dst_port, protocol).
    Los paquetes se acumulan en ventanas temporales y al cerrar la ventana
    se calculan las features para cada flujo.
    """

    def __init__(self):
        # Almacenar paquetes por flujo
        self._flows: Dict[str, List[dict]] = defaultdict(list)
        self._flow_start_times: Dict[str, float] = {}
        # Contadores para features de conexión
        self._syn_counts: Dict[str, int] = defaultdict(int)
        self._synack_counts: Dict[str, int] = defaultdict(int)
        self._rst_counts: Dict[str, int] = defaultdict(int)
        # Contadores UDP para time_delta
        self._last_udp_time: Dict[str, float] = {}
        self._udp_stream_counter = 0
        self._udp_stream_map: Dict[str, int] = {}

    def add_packet(self, packet) -> Optional[str]:
        """
        Añade un paquete scapy al flujo correspondiente.

        Args:
            packet: Paquete scapy

        Returns:
            flow_key si el paquete fue añadido, None si fue descartado
        """
        try:
            pkt_info = self._extract_packet_info(packet)
            if pkt_info is None:
                return None

            flow_key = pkt_info.get("flow_key", "unknown")
            self._flows[flow_key].append(pkt_info)

            if flow_key not in self._flow_start_times:
                self._flow_start_times[flow_key] = time.time()

            # Trackear flags TCP
            if pkt_info.get("proto") == "TCP":
                flags = pkt_info.get("tcp_flags_int", 0)
                if flags & 0x02 and not (flags & 0x10):  # SYN sin ACK
                    self._syn_counts[flow_key] += 1
                if flags & 0x02 and flags & 0x10:  # SYN+ACK
                    self._synack_counts[flow_key] += 1
                if flags & 0x04:  # RST
                    self._rst_counts[flow_key] += 1

            return flow_key

        except Exception as e:
            logger.debug(f"Error procesando paquete: {e}")
            return None

    def get_flow_features(self, flow_key: str) -> Dict[str, float]:
        """
        Calcula las 36 features del modelo para un flujo dado.

        Args:
            flow_key: Identificador del flujo

        Returns:
            Diccionario {feature_name: value} con las 36 features del modelo
        """
        packets = self._flows.get(flow_key, [])
        if not packets:
            return self._empty_features()

        # Tomar el último paquete como referencia para features de paquete
        last_pkt = packets[-1]
        first_pkt = packets[0]

        features = {}

        # ─── ARP ────────────────────────────────────────────────
        features["arp.opcode"] = last_pkt.get("arp_opcode", 0)

        # ─── ICMP ───────────────────────────────────────────────
        features["icmp.seq_le"] = last_pkt.get("icmp_seq", 0)
        features["icmp.transmit_timestamp"] = last_pkt.get("icmp_ts", 0)
        features["icmp.checksum"] = last_pkt.get("icmp_checksum", 0)

        # ─── MQTT ───────────────────────────────────────────────
        features["mqtt.protoname"] = last_pkt.get("mqtt_protoname", 0)
        features["mqtt.topic"] = last_pkt.get("mqtt_topic", 0)
        features["mqtt.conack.flags"] = last_pkt.get("mqtt_conack_flags", 0)
        features["mqtt.msg"] = last_pkt.get("mqtt_msg", 0)

        # ─── TCP ────────────────────────────────────────────────
        features["tcp.options"] = last_pkt.get("tcp_options_len", 0)
        features["tcp.dstport"] = last_pkt.get("dport", 0)
        features["tcp.srcport"] = last_pkt.get("sport", 0)
        features["tcp.len"] = last_pkt.get("tcp_len", 0)
        features["tcp.checksum"] = last_pkt.get("tcp_checksum", 0)
        features["tcp.seq"] = last_pkt.get("tcp_seq", 0)
        features["tcp.ack"] = last_pkt.get("tcp_ack", 0)
        features["tcp.ack_raw"] = last_pkt.get("tcp_ack", 0)  # Mismo valor
        features["tcp.flags"] = last_pkt.get("tcp_flags_int", 0)
        features["tcp.flags.ack"] = 1 if (last_pkt.get("tcp_flags_int", 0) & 0x10) else 0
        features["tcp.payload"] = last_pkt.get("payload_len", 0)

        # Features de conexión TCP (conteos por flujo)
        features["tcp.connection.syn"] = self._syn_counts.get(flow_key, 0)
        features["tcp.connection.synack"] = self._synack_counts.get(flow_key, 0)
        features["tcp.connection.rst"] = self._rst_counts.get(flow_key, 0)

        # ─── UDP ────────────────────────────────────────────────
        features["udp.port"] = last_pkt.get("dport", 0) if last_pkt.get("proto") == "UDP" else 0
        features["udp.time_delta"] = last_pkt.get("udp_time_delta", 0)

        # UDP stream ID
        if flow_key not in self._udp_stream_map and last_pkt.get("proto") == "UDP":
            self._udp_stream_map[flow_key] = self._udp_stream_counter
            self._udp_stream_counter += 1
        features["udp.stream"] = self._udp_stream_map.get(flow_key, 0)

        # ─── DNS ────────────────────────────────────────────────
        features["dns.qry.name"] = last_pkt.get("dns_qry_name_hash", 0)
        features["dns.qry.name.len"] = last_pkt.get("dns_qry_name_len", 0)
        features["dns.qry.qu"] = last_pkt.get("dns_qry_qu", 0)

        # ─── HTTP ───────────────────────────────────────────────
        features["http.request.version"] = last_pkt.get("http_version", 0)
        features["http.request.method"] = last_pkt.get("http_method", 0)
        features["http.response"] = last_pkt.get("http_response", 0)
        features["http.request.full_uri"] = last_pkt.get("http_uri_hash", 0)
        features["http.file_data"] = last_pkt.get("http_file_data_len", 0)
        features["http.referer"] = last_pkt.get("http_referer_hash", 0)
        features["http.content_length"] = last_pkt.get("http_content_length", 0)
        features["http.request.uri.query"] = last_pkt.get("http_uri_query_hash", 0)

        return features

    def get_all_flow_features(self) -> List[Dict[str, Any]]:
        """
        Calcula features para todos los flujos activos.

        Returns:
            Lista de dicts con flow_key, features, y metadata
        """
        results = []
        for flow_key in list(self._flows.keys()):
            features = self.get_flow_features(flow_key)
            packets = self._flows[flow_key]
            results.append({
                "flow_key": flow_key,
                "features": features,
                "n_packets": len(packets),
                "start_time": self._flow_start_times.get(flow_key, 0),
                "src_ip": packets[0].get("src_ip", "unknown") if packets else "unknown",
                "dst_ip": packets[0].get("dst_ip", "unknown") if packets else "unknown",
            })
        return results

    def clear(self):
        """Limpia todos los flujos acumulados."""
        self._flows.clear()
        self._flow_start_times.clear()
        self._syn_counts.clear()
        self._synack_counts.clear()
        self._rst_counts.clear()
        self._last_udp_time.clear()

    def _extract_packet_info(self, packet) -> Optional[dict]:
        """
        Extrae información relevante de un paquete scapy.

        Soporta: Ethernet/IP/TCP/UDP/ICMP/ARP/DNS/HTTP
        """
        from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, Raw

        info = {
            "timestamp": time.time(),
            "proto": "OTHER",
            "src_ip": "0.0.0.0",
            "dst_ip": "0.0.0.0",
            "sport": 0,
            "dport": 0,
            "payload_len": 0,
        }

        # ─── ARP ─────────────────────────────
        if packet.haslayer(ARP):
            arp = packet[ARP]
            info["proto"] = "ARP"
            info["src_ip"] = str(arp.psrc)
            info["dst_ip"] = str(arp.pdst)
            info["arp_opcode"] = int(arp.op)
            info["flow_key"] = f"ARP:{arp.psrc}->{arp.pdst}"
            return info

        # ─── IP ──────────────────────────────
        if not packet.haslayer(IP):
            return None  # Solo procesamos IP y ARP

        ip = packet[IP]
        info["src_ip"] = str(ip.src)
        info["dst_ip"] = str(ip.dst)

        # ─── ICMP ────────────────────────────
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            info["proto"] = "ICMP"
            info["icmp_seq"] = int(icmp.seq) if hasattr(icmp, 'seq') else 0
            info["icmp_checksum"] = int(icmp.chksum) if icmp.chksum else 0
            info["icmp_ts"] = int(icmp.ts_ori) if hasattr(icmp, 'ts_ori') else 0
            info["flow_key"] = f"ICMP:{ip.src}->{ip.dst}"
            return info

        # ─── TCP ─────────────────────────────
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            info["proto"] = "TCP"
            info["sport"] = int(tcp.sport)
            info["dport"] = int(tcp.dport)
            info["tcp_flags_int"] = int(tcp.flags)
            info["tcp_seq"] = int(tcp.seq)
            info["tcp_ack"] = int(tcp.ack)
            info["tcp_len"] = int(ip.len) - (ip.ihl * 4) - (tcp.dataofs * 4) if tcp.dataofs else 0
            info["tcp_checksum"] = int(tcp.chksum) if tcp.chksum else 0
            info["tcp_options_len"] = len(tcp.options) if tcp.options else 0

            # Payload
            if packet.haslayer(Raw):
                raw = packet[Raw].load
                info["payload_len"] = len(raw)
                # Intentar detectar HTTP
                self._parse_http(raw, info)

            info["flow_key"] = f"TCP:{ip.src}:{tcp.sport}->{ip.dst}:{tcp.dport}"
            return info

        # ─── UDP ─────────────────────────────
        if packet.haslayer(UDP):
            udp = packet[UDP]
            info["proto"] = "UDP"
            info["sport"] = int(udp.sport)
            info["dport"] = int(udp.dport)

            # Time delta para UDP
            flow_key = f"UDP:{ip.src}:{udp.sport}->{ip.dst}:{udp.dport}"
            now = time.time()
            if flow_key in self._last_udp_time:
                info["udp_time_delta"] = now - self._last_udp_time[flow_key]
            else:
                info["udp_time_delta"] = 0
            self._last_udp_time[flow_key] = now

            # DNS
            if packet.haslayer(DNS):
                dns = packet[DNS]
                if dns.qd:
                    qname = dns.qd.qname.decode() if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
                    info["dns_qry_name_hash"] = hash(qname) % (2**16)
                    info["dns_qry_name_len"] = len(qname)
                    info["dns_qry_qu"] = int(dns.qd.qclass) if hasattr(dns.qd, 'qclass') else 0

            if packet.haslayer(Raw):
                info["payload_len"] = len(packet[Raw].load)

            info["flow_key"] = flow_key
            return info

        return None

    def _parse_http(self, raw_data: bytes, info: dict):
        """Intenta parsear datos HTTP del payload TCP."""
        try:
            text = raw_data[:2048].decode('utf-8', errors='ignore')

            # HTTP Request
            if text.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')):
                parts = text.split('\r\n')
                request_line = parts[0]
                method, uri, version = request_line.split(' ', 2)

                method_map = {'GET': 1, 'POST': 2, 'PUT': 3, 'DELETE': 4,
                              'HEAD': 5, 'OPTIONS': 6, 'PATCH': 7}
                info["http_method"] = method_map.get(method, 0)
                info["http_version"] = 11 if '1.1' in version else 10
                info["http_uri_hash"] = hash(uri) % (2**16)

                # Query string
                if '?' in uri:
                    query = uri.split('?', 1)[1]
                    info["http_uri_query_hash"] = hash(query) % (2**16)

                # Headers
                for header in parts[1:]:
                    if header.lower().startswith('referer:'):
                        info["http_referer_hash"] = hash(header.split(':', 1)[1].strip()) % (2**16)
                    elif header.lower().startswith('content-length:'):
                        try:
                            info["http_content_length"] = int(header.split(':', 1)[1].strip())
                        except ValueError:
                            pass

                info["http_request.full_uri"] = info.get("http_uri_hash", 0)

            # HTTP Response
            elif text.startswith('HTTP/'):
                parts = text.split(' ', 2)
                if len(parts) >= 2:
                    try:
                        info["http_response"] = int(parts[1])
                    except ValueError:
                        pass
                info["http_file_data_len"] = len(raw_data)

        except Exception:
            pass

    def _empty_features(self) -> Dict[str, float]:
        """Retorna un vector de features vacío (todos ceros)."""
        feature_names = [
            "arp.opcode", "icmp.seq_le", "mqtt.protoname", "tcp.options",
            "http.request.version", "tcp.dstport", "mqtt.topic",
            "dns.qry.name.len", "http.request.method", "http.response",
            "tcp.connection.rst", "tcp.flags.ack", "tcp.payload",
            "http.request.full_uri", "dns.qry.name", "mqtt.conack.flags",
            "tcp.len", "tcp.checksum", "http.file_data",
            "tcp.connection.syn", "tcp.ack_raw", "icmp.transmit_timestamp",
            "tcp.connection.synack", "http.referer", "udp.time_delta",
            "http.content_length", "tcp.flags", "tcp.seq",
            "http.request.uri.query", "udp.stream", "dns.qry.qu",
            "udp.port", "icmp.checksum", "tcp.srcport", "mqtt.msg", "tcp.ack"
        ]
        return {f: 0.0 for f in feature_names}
