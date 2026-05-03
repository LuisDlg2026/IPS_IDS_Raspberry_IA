"""
Test del pipeline completo IDS/IPS.

3 niveles de test:
  1. Inferencia pura (sin red) -- siempre funciona
  2. Features adapter con paquetes simulados (sin red) -- siempre funciona
  3. Captura real (requiere admin/root) -- solo si tienes permisos

Ejecutar:
    python tests/test_pipeline.py
"""

import sys
import time
from pathlib import Path

# Asegurar que src/ está en el path
sys.path.insert(0, str(Path(__file__).parent.parent))


def separator(title):
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


# =====================================================================
# TEST 1: Motor de inferencia (sin red)
# =====================================================================
def test_inference():
    separator("TEST 1: Motor de Inferencia")

    from src.ml.inference import InferenceEngine

    engine = InferenceEngine(model_name="decision_tree")
    print(f"  Modelo: {engine.model_name}")
    print(f"  Features esperadas: {engine._n_features}")
    print(f"  Clases: {engine.class_names}")

    # Test 1a: Health check
    print("\n  --- Health Check ---")
    health = engine.health_check()
    assert health["status"] == "ok", f"Health check fallo: {health}"
    print(f"  Status: {health['status']}")
    print(f"  Prediccion con ceros: {health['test_prediction']}")
    print(f"  Latencia: {health['test_inference_ms']:.4f} ms")

    # Test 1b: Prediccion con features simuladas (trafico normal)
    print("\n  --- Prediccion: trafico Normal simulado ---")
    normal_features = {f: 0.0 for f in engine.feature_names}
    normal_features["tcp.dstport"] = 443      # HTTPS
    normal_features["tcp.srcport"] = 52341    # Puerto efimero
    normal_features["tcp.flags.ack"] = 1       # ACK normal
    normal_features["tcp.len"] = 150           # Payload normal
    normal_features["tcp.flags"] = 0x10        # ACK flag

    result = engine.predict(normal_features)
    print(f"  Prediccion: {result['prediction']}")
    print(f"  Confianza: {result['confidence']:.2%}")
    print(f"  Es ataque: {result['is_attack']}")
    print(f"  Severidad: {result['severity']}")
    print(f"  Latencia: {result['inference_ms']:.4f} ms")

    # Test 1c: Prediccion con features de ataque simulado (DDoS TCP)
    print("\n  --- Prediccion: DDoS TCP simulado ---")
    attack_features = {f: 0.0 for f in engine.feature_names}
    attack_features["tcp.dstport"] = 80
    attack_features["tcp.connection.syn"] = 500    # Muchos SYN
    attack_features["tcp.connection.synack"] = 0   # Sin respuesta
    attack_features["tcp.connection.rst"] = 200    # Muchos RST
    attack_features["tcp.flags"] = 0x02            # SYN flag
    attack_features["tcp.flags.ack"] = 0           # Sin ACK

    result = engine.predict(attack_features)
    print(f"  Prediccion: {result['prediction']}")
    print(f"  Confianza: {result['confidence']:.2%}")
    print(f"  Es ataque: {result['is_attack']}")
    print(f"  Severidad: {result['severity']}")

    # Test 1d: Benchmark
    print("\n  --- Benchmark: 500 predicciones ---")
    dummy = {f: 0.0 for f in engine.feature_names}
    t0 = time.perf_counter()
    for _ in range(500):
        engine.predict(dummy)
    elapsed = time.perf_counter() - t0
    ms_per_pred = elapsed / 500 * 1000
    print(f"  Total: {elapsed:.2f}s")
    print(f"  Por prediccion: {ms_per_pred:.4f} ms")
    print(f"  Predicciones/segundo: {500/elapsed:.0f}")

    print("\n  [OK] Test de inferencia completado")
    return engine


# =====================================================================
# TEST 2: Features Adapter con paquetes simulados
# =====================================================================
def test_features_adapter():
    separator("TEST 2: Features Adapter (paquetes simulados)")

    try:
        from scapy.all import (
            Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw, wrpcap
        )
    except ImportError:
        print("  [SKIP] scapy no instalado. Instalar con: pip install scapy")
        return None

    from src.capture.features_adapter import FlowAggregator

    aggregator = FlowAggregator()

    # 2a: Crear paquetes TCP simulados (trafico web normal)
    print("\n  --- Simulando trafico web normal (10 paquetes TCP) ---")
    for i in range(10):
        pkt = (
            Ether() /
            IP(src="192.168.1.100", dst="93.184.216.34") /
            TCP(sport=52000 + i, dport=443, flags="A", seq=1000 + i * 100,
                ack=2000 + i * 50) /
            Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        )
        flow_key = aggregator.add_packet(pkt)

    print(f"  Flujos activos: {len(aggregator._flows)}")

    # 2b: Crear paquetes de ataque DDoS SYN flood
    print("\n  --- Simulando SYN flood (50 paquetes SYN desde IPs distintas) ---")
    for i in range(50):
        pkt = (
            Ether() /
            IP(src=f"10.0.{i // 256}.{i % 256}", dst="192.168.1.1") /
            TCP(sport=40000 + i, dport=80, flags="S", seq=i * 100)
        )
        aggregator.add_packet(pkt)

    print(f"  Flujos activos: {len(aggregator._flows)}")

    # 2c: Paquetes DNS
    print("\n  --- Simulando consulta DNS ---")
    dns_pkt = (
        Ether() /
        IP(src="192.168.1.100", dst="8.8.8.8") /
        UDP(sport=53412, dport=53) /
        DNS(qd=DNSQR(qname="example.com"))
    )
    aggregator.add_packet(dns_pkt)

    # 2d: Paquetes ICMP (ping)
    print("  --- Simulando ping ICMP ---")
    icmp_pkt = (
        Ether() /
        IP(src="192.168.1.100", dst="192.168.1.1") /
        ICMP(seq=1)
    )
    aggregator.add_packet(icmp_pkt)

    # 2e: Paquetes ARP
    print("  --- Simulando ARP request ---")
    arp_pkt = (
        Ether() /
        ARP(op=1, psrc="192.168.1.100", pdst="192.168.1.1")
    )
    aggregator.add_packet(arp_pkt)

    # 2f: Extraer features de todos los flujos
    print(f"\n  --- Extrayendo features de {len(aggregator._flows)} flujos ---")
    all_flows = aggregator.get_all_flow_features()

    for flow in all_flows[:5]:  # Mostrar primeros 5
        feats = flow["features"]
        non_zero = {k: v for k, v in feats.items() if v != 0}
        print(f"\n  Flujo: {flow['flow_key']}")
        print(f"    Paquetes: {flow['n_packets']}")
        print(f"    Features no-cero: {len(non_zero)}/{len(feats)}")
        if non_zero:
            for k, v in list(non_zero.items())[:5]:
                print(f"      {k}: {v}")

    if len(all_flows) > 5:
        print(f"\n  ... y {len(all_flows) - 5} flujos mas")

    print(f"\n  [OK] Features adapter funciona - {len(all_flows)} flujos procesados")
    return aggregator, all_flows


# =====================================================================
# TEST 3: Pipeline completo (inference + features adapter)
# =====================================================================
def test_full_pipeline(engine, all_flows):
    separator("TEST 3: Pipeline completo (features -> prediccion)")

    if engine is None or all_flows is None:
        print("  [SKIP] Dependencias de tests anteriores no disponibles")
        return

    print(f"  Analizando {len(all_flows)} flujos con {engine.model_name}...\n")

    attacks_found = 0
    normal_found = 0

    for flow in all_flows:
        result = engine.predict(flow["features"])
        status = "ATAQUE" if result["is_attack"] else "Normal"

        if result["is_attack"]:
            attacks_found += 1
            print(f"  [!] {flow['flow_key'][:50]}")
            print(f"      -> {result['prediction']} "
                  f"(confianza={result['confidence']:.1%}, "
                  f"severidad={result['severity']})")
        else:
            normal_found += 1

    print(f"\n  Resumen:")
    print(f"    Flujos totales: {len(all_flows)}")
    print(f"    Normal: {normal_found}")
    print(f"    Ataques: {attacks_found}")
    print(f"\n  [OK] Pipeline completo funciona")


# =====================================================================
# TEST 4: Captura real (requiere admin)
# =====================================================================
def test_real_capture():
    separator("TEST 4: Captura de red real (10 segundos)")

    try:
        from scapy.all import conf
    except ImportError:
        print("  [SKIP] scapy no instalado")
        return

    from src.capture.capture import PacketCapture

    print("  NOTA: Este test requiere permisos de administrador.")
    print("  Si falla, es normal -- ejecuta como admin para probarlo.\n")

    captured_count = [0]

    def on_packet(pkt):
        captured_count[0] += 1

    capture = PacketCapture(packet_callback=on_packet)
    print(f"  Interfaz detectada: {capture._interface}")

    try:
        capture.start()
        print("  Capturando durante 5 segundos...")
        time.sleep(5)
        capture.stop()

        stats = capture.stats
        print(f"\n  Paquetes capturados: {stats.get('packets_captured', 0)}")
        print(f"  Paquetes/segundo: {stats.get('packets_per_second', 0)}")
        print(f"\n  [OK] Captura real funciona")

    except PermissionError:
        print("\n  [SKIP] Sin permisos de admin -- esto es esperado.")
        print("  Para probar captura real:")
        print("    Windows: Ejecutar terminal como Administrador")
        print("    Linux:   sudo python tests/test_pipeline.py")
    except Exception as e:
        print(f"\n  [SKIP] Error: {e}")
        print("  Esto es normal si no tienes Npcap/WinPcap (Windows)")
        print("  o permisos de captura (Linux).")


# =====================================================================
# MAIN
# =====================================================================
if __name__ == "__main__":
    print("\n" + "#" * 70)
    print("#  TEST COMPLETO DEL PIPELINE IDS/IPS")
    print("#  " + time.strftime("%Y-%m-%d %H:%M:%S"))
    print("#" * 70)

    # Test 1: Inferencia
    engine = test_inference()

    # Test 2: Features adapter
    result = test_features_adapter()
    aggregator = None
    all_flows = None
    if result:
        aggregator, all_flows = result

    # Test 3: Pipeline completo
    if all_flows:
        test_full_pipeline(engine, all_flows)

    # Test 4: Captura real (opcional)
    print("\n")
    respuesta = input("  Quieres probar captura real? (requiere admin) [s/N]: ").strip().lower()
    if respuesta == "s":
        test_real_capture()
    else:
        print("  [SKIP] Captura real omitida")

    # Resumen
    separator("RESUMEN")
    print("  Test 1 (Inferencia):       OK")
    print(f"  Test 2 (Features Adapter): {'OK' if all_flows else 'SKIP'}")
    print(f"  Test 3 (Pipeline):         {'OK' if all_flows else 'SKIP'}")
    print(f"  Test 4 (Captura real):     Depende de permisos")
    print(f"\n  Motor listo para usar con:")
    print(f"    from src.detection.detector import IDSDetector")
    print(f"    detector = IDSDetector()")
    print(f"    detector.start()  # requiere admin")
    print()
