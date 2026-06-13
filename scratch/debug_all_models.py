import sys
import os
import numpy as np
import pandas as pd

# Agregar path
sys.path.insert(0, os.getcwd())

from src.ml.inference import InferenceEngine

def main():
    # El flujo real capturado del usuario:
    user_feats_50 = {f: 0.0 for f in ['arp.opcode', 'icmp.seq_le', 'mqtt.protoname', 'tcp.options', 'http.request.version', 'tcp.dstport', 'mqtt.topic', 'dns.qry.name.len', 'http.request.method', 'http.response', 'tcp.connection.rst', 'tcp.flags.ack', 'tcp.payload', 'http.request.full_uri', 'dns.qry.name', 'mqtt.conack.flags', 'tcp.len', 'tcp.checksum', 'http.file_data', 'tcp.connection.syn', 'tcp.ack_raw', 'icmp.transmit_timestamp', 'tcp.connection.synack', 'http.referer', 'udp.time_delta', 'http.content_length', 'tcp.flags', 'tcp.seq', 'http.request.uri.query', 'udp.stream', 'dns.qry.qu', 'udp.port', 'icmp.checksum', 'tcp.srcport', 'mqtt.msg', 'tcp.ack']}
    user_feats_50['tcp.dstport'] = 80.0
    user_feats_50['tcp.srcport'] = 1896.0
    user_feats_50['tcp.checksum'] = 3935.0
    user_feats_50['tcp.seq'] = 2057845967.0
    user_feats_50['tcp.ack'] = 1730409467.0
    user_feats_50['tcp.ack_raw'] = 1730409467.0
    user_feats_50['tcp.flags'] = 2.0
    user_feats_50['tcp.connection.syn'] = 50.0
    
    user_feats_5000 = user_feats_50.copy()
    user_feats_5000['tcp.connection.syn'] = 5000.0
    
    models = ["random_forest", "lightgbm", "xgboost", "decision_tree", "mlp"]
    
    print("--- MODEL COMPARISON ---")
    
    for model_name in models:
        print(f"\n=================== MODEL: {model_name} ===================")
        try:
            engine = InferenceEngine(model_name=model_name)
            
            for label, feats in [("syn=50", user_feats_50), ("syn=5000", user_feats_5000)]:
                res = engine.predict(feats)
                print(f"  [{label}] Pred: {res['prediction']} (Conf: {res['confidence']:.2%}) | Es Ataque: {res['is_attack']}")
                if not res['is_attack']:
                    probs = res.get('probabilities', {})
                    attack_probs = {k: v for k, v in probs.items() if k != 'Normal'}
                    if attack_probs:
                        max_attack = max(attack_probs, key=attack_probs.get)
                        print(f"    - Ataque alternativo más probable: {max_attack} ({attack_probs[max_attack]:.2%})")
        except Exception as e:
            print(f"  [ERROR] No se pudo cargar o evaluar {model_name}: {e}")

if __name__ == "__main__":
    main()
