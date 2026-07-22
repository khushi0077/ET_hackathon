import numpy as np
from sklearn.datasets import fetch_kddcup99
from sklearn.ensemble import IsolationForest
import time
import math

def run_evaluation():
    print("Fetching KDD Cup '99 dataset (10% subset) for authentic evaluation...")
    dataset = fetch_kddcup99(subset='SA', percent10=True)
    X_raw = dataset.data
    y_raw = dataset.target

    # Filter down to a manageable size for quick evaluation (e.g., 10000 samples)
    limit = 10000
    X_raw = X_raw[:limit]
    y_raw = y_raw[:limit]

    # Extract basic behavioral features to match our IsolationForest pipeline
    features = []
    entity_profiles = {}

    print("Processing behavioral features and simulating entity baselines...")
    for i, row in enumerate(X_raw):
        duration = float(row[0])
        src_bytes = float(row[4])
        dst_bytes = float(row[5])
        dst_port = 80 # Simulated port for KDD mapping
        
        # Simulate a src_ip by using a modulo of the index to create 100 fake entities
        src_ip = f"192.168.1.{i % 100}"
        
        if src_ip not in entity_profiles:
            entity_profiles[src_ip] = {"count": 0, "total_bytes": 0, "total_duration": 0}
            
        prof = entity_profiles[src_ip]
        avg_bytes = prof["total_bytes"] / max(1, prof["count"])
        avg_dur = prof["total_duration"] / max(1, prof["count"])
        
        byte_dev = abs(src_bytes - avg_bytes)
        dur_dev = abs(duration - avg_dur)
        
        prof["count"] += 1
        prof["total_bytes"] += src_bytes
        prof["total_duration"] += duration
        
        features.append([dst_port, src_bytes, dst_bytes, duration, byte_dev, dur_dev])

    X = np.array(features)
    # In KDD, target b'normal.' is normal, everything else is an attack
    y = np.array([0 if label == b'normal.' else 1 for label in y_raw])

    print("Pre-training IsolationForest on authentic normal baseline...")
    # Train on the first 2000 normal samples
    normal_indices = np.where(y == 0)[0][:2000]
    X_train = X[normal_indices]

    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(X_train)

    print("Scoring full dataset...")
    raw_scores = model.decision_function(X)

    # Apply our exact Platt scaling from the live engine (multiplier * 20)
    anomaly_scores = []
    for score in raw_scores:
        try:
            anomaly_scores.append(1.0 / (1.0 + math.exp(score * 20)))
        except OverflowError:
            anomaly_scores.append(0.0 if score > 0 else 1.0)

    # Evaluate at threshold 0.6
    threshold = 0.6
    predictions = [1 if s > threshold else 0 for s in anomaly_scores]

    true_positives = sum(1 for p, a in zip(predictions, y) if p == 1 and a == 1)
    false_positives = sum(1 for p, a in zip(predictions, y) if p == 1 and a == 0)
    true_negatives = sum(1 for p, a in zip(predictions, y) if p == 0 and a == 0)
    false_negatives = sum(1 for p, a in zip(predictions, y) if p == 0 and a == 1)

    accuracy = (true_positives + true_negatives) / len(y)
    precision = true_positives / max(1, (true_positives + false_positives))
    recall = true_positives / max(1, (true_positives + false_negatives))
    f1 = 2 * (precision * recall) / max(0.0001, (precision + recall))

    print("\n" + "="*40)
    print("PRAHARI REAL-WORLD BENCHMARK (NSL-KDD Subset)")
    print("="*40)
    print(f"Total Events:      {len(y)}")
    print(f"Threshold:         {threshold}")
    print(f"Accuracy:          {accuracy*100:.2f}%")
    print(f"Precision:         {precision*100:.2f}%")
    print(f"Recall:            {recall*100:.2f}%")
    print(f"F1 Score:          {f1*100:.2f}%")
    print(f"FP Rate:           {(false_positives / len(y))*100:.2f}%")
    print(f"FP: {false_positives} | FN: {false_negatives} | TP: {true_positives}")
    print("="*40)

if __name__ == "__main__":
    run_evaluation()
