r"""
Test de captura REAL de trafico de red + analisis ML.

Captura paquetes reales de tu red durante 30 segundos,
extrae features y clasifica cada flujo con el modelo entrenado.

REQUISITOS:
  - Npcap instalado (OK - ya verificado)
  - Ejecutar como ADMINISTRADOR

Ejecutar:
  1. Abrir terminal como Administrador
  2. cd c:\Users\Luis\Documents\GitHub\IPS_IDS_Raspberry_IA
  3. python tests\test_captura_real.py
"""

import sys
import time
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent.parent))

DURACION_CAPTURA = 30  # segundos


def main():
    import os
    
    # Valores por defecto
    duracion = DURACION_CAPTURA
    from scapy.all import sniff, conf, IP, TCP, UDP, ICMP
    iface = os.environ.get("IDS_CAPTURE_IFACE") or conf.iface
    
    # Procesar argumentos de línea de comandos
    if len(sys.argv) > 1:
        try:
            duracion = int(sys.argv[1])
            if len(sys.argv) > 2:
                iface = sys.argv[2]
        except ValueError:
            iface = sys.argv[1]
            if len(sys.argv) > 2:
                try:
                    duracion = int(sys.argv[2])
                except ValueError:
                    pass

    print()
    print("#" * 70)
    print("#  TEST DE CAPTURA REAL + ANALISIS ML")
    print(f"#  Duracion: {duracion} segundos")
    print("#" * 70)

    # ─── 1. Cargar motor de inferencia ──────────────────────
    print("\n[1/4] Cargando modelo ML...")
    from src.ml.inference import InferenceEngine
    engine = InferenceEngine(model_name="decision_tree")
    print(f"  Modelo: {engine.model_name}")
    print(f"  Features: {engine._n_features}")
    print(f"  Clases: {len(engine.class_names)}")

    # ─── 2. Preparar captura ────────────────────────────────
    print("\n[2/4] Preparando captura de red...")
    from src.capture.features_adapter import FlowAggregator

    aggregator = FlowAggregator()
    pkt_count = [0]
    proto_counts = Counter()

    def on_packet(pkt):
        pkt_count[0] += 1
        aggregator.add_packet(pkt)

        # Contar protocolos
        if pkt.haslayer(TCP):
            proto_counts["TCP"] += 1
        elif pkt.haslayer(UDP):
            proto_counts["UDP"] += 1
        elif pkt.haslayer(ICMP):
            proto_counts["ICMP"] += 1
        else:
            proto_counts["Otro"] += 1

        # Mostrar progreso cada 50 paquetes
        if pkt_count[0] % 50 == 0:
            print(f"    Capturados: {pkt_count[0]} paquetes, "
                  f"{len(aggregator._flows)} flujos...")

    print(f"  Interfaz: {iface}")
    print(f"  Duracion: {duracion}s")

    # ─── 3. Capturar ───────────────────────────────────────
    print(f"\n[3/4] Capturando trafico real durante {duracion}s...")
    print("  (navega por internet para generar trafico)\n")

    try:
        sniff(
            iface=iface,
            prn=on_packet,
            timeout=duracion,
            store=False,
        )
    except PermissionError:
        print("\n  ERROR: Sin permisos de administrador.")
        print("  Solucion: Ejecutar terminal como Administrador")
        print("    1. Click derecho en 'Terminal' o 'CMD'")
        print("    2. 'Ejecutar como administrador'")
        print("    3. cd c:\\Users\\Luis\\Documents\\GitHub\\IPS_IDS_Raspberry_IA")
        print("    4. python tests\\test_captura_real.py")
        return
    except Exception as e:
        print(f"\n  ERROR: {e}")
        return

    # ─── 4. Analizar con ML ─────────────────────────────────
    print(f"\n[4/4] Analizando {len(aggregator._flows)} flujos con ML...")

    all_flows = aggregator.get_all_flow_features()
    predictions = Counter()
    attacks = []

    for flow in all_flows:
        result = engine.predict(flow["features"])
        predictions[result["prediction"]] += 1

        if result["is_attack"]:
            attacks.append({
                "tipo": result["prediction"],
                "confianza": result["confidence"],
                "severidad": result["severity"],
                "flujo": flow["flow_key"],
                "src": flow["src_ip"],
                "dst": flow["dst_ip"],
                "paquetes": flow["n_packets"],
            })

    # ─── Resultados ─────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  RESULTADOS")
    print("=" * 70)

    print(f"\n  Captura:")
    print(f"    Paquetes totales: {pkt_count[0]}")
    print(f"    Flujos detectados: {len(all_flows)}")
    print(f"    Protocolos: {dict(proto_counts)}")

    print(f"\n  Clasificacion ML ({engine.model_name}):")
    for pred, count in predictions.most_common():
        pct = count / len(all_flows) * 100 if all_flows else 0
        marker = "  [!]" if pred != "Normal" else "     "
        print(f"  {marker} {pred:<25s}: {count:>5d} flujos ({pct:.1f}%)")

    if attacks:
        print(f"\n  Alertas de seguridad: {len(attacks)}")
        print(f"  {'─' * 60}")
        for a in attacks[:20]:  # Mostrar max 20
            print(f"    [{a['severidad'].upper():>8s}] {a['tipo']:<20s} "
                  f"{a['src']:>15s} -> {a['dst']:<15s} "
                  f"({a['paquetes']} pkts, {a['confianza']:.0%})")
        if len(attacks) > 20:
            print(f"    ... y {len(attacks) - 20} alertas mas")
    else:
        print("\n  Sin alertas de seguridad (todo Normal)")

    print(f"\n  Rendimiento:")
    stats = engine.stats
    print(f"    Predicciones: {stats['predictions']}")
    print(f"    Latencia media: {stats['avg_inference_ms']:.4f} ms/prediccion")
    print(f"    Tiempo total ML: {stats['total_inference_s']:.3f}s")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
