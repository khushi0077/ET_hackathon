import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import sim
import ml_engine

batch = sim.generate_batch(size=200, anomaly_ratio=0.5)
for f in batch:
    raw = ml_engine.model.decision_function(ml_engine.extract_features(f))[0]
    score = ml_engine.score_event(f)
    print(f"Attack: {f['is_attack']}, Type: {f.get('attack_type')}, Raw: {raw:.3f}, Score: {score:.3f}, Bytes: {f['bytes_sent']}")
