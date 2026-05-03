import sys, time
sys.path.insert(0, '.')
from src.ml.inference import InferenceEngine

# Test Decision Tree (mas rapido, solo sklearn)
print("=== Decision Tree ===")
e = InferenceEngine(model_name='decision_tree')
h = e.health_check()
print(f"Status: {h['status']}")
print(f"Prediction: {h.get('test_prediction')}")
print(f"Latency: {h.get('test_inference_ms'):.4f} ms")

d = {f: 0.0 for f in e.feature_names}
t0 = time.perf_counter()
for _ in range(1000):
    e.predict(d)
t = time.perf_counter() - t0
print(f"Benchmark 1000 pred: {t:.2f}s = {t/1000*1000:.4f} ms/pred")

# Test Random Forest
print("\n=== Random Forest ===")
e2 = InferenceEngine(model_name='random_forest')
h2 = e2.health_check()
print(f"Latency: {h2.get('test_inference_ms'):.4f} ms")

t0 = time.perf_counter()
for _ in range(100):
    e2.predict(d)
t = time.perf_counter() - t0
print(f"Benchmark 100 pred: {t:.2f}s = {t/100*1000:.4f} ms/pred")
