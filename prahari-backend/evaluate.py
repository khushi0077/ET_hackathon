import sim
import ml_engine

def evaluate_model():
    print("Generating 5000 test flows for benchmarking...")
    test_batch = sim.generate_batch(size=5000, anomaly_ratio=0.05)
    
    thresholds = [0.6, 0.7, 0.8]
    
    print("Scoring events...")
    scores_and_labels = []
    for flow in test_batch:
        score = ml_engine.score_event(flow)
        is_actual_attack = flow.get("is_attack", False)
        scores_and_labels.append((score, is_actual_attack))
        
    print("\n" + "="*40)
    print("PRAHARI BENCHMARK RESULTS")
    print("="*40)
    print(f"Total Events:      {len(test_batch)}")
    
    for threshold in thresholds:
        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0
        
        for score, is_actual_attack in scores_and_labels:
            is_pred_attack = score > threshold
            if is_pred_attack and is_actual_attack:
                true_positives += 1
            elif is_pred_attack and not is_actual_attack:
                false_positives += 1
            elif not is_pred_attack and not is_actual_attack:
                true_negatives += 1
            else:
                false_negatives += 1
                
        accuracy = (true_positives + true_negatives) / len(test_batch)
        precision = true_positives / max(1, (true_positives + false_positives))
        recall = true_positives / max(1, (true_positives + false_negatives))
        f1 = 2 * (precision * recall) / max(0.0001, (precision + recall))
        
        print(f"\n--- Threshold: {threshold} ---")
        print(f"Accuracy:          {accuracy*100:.2f}%")
        print(f"Precision:         {precision*100:.2f}%")
        print(f"Recall:            {recall*100:.2f}%")
        print(f"F1 Score:          {f1*100:.2f}%")
        print(f"FP: {false_positives} | FN: {false_negatives} | TP: {true_positives}")
    print("="*40)

if __name__ == "__main__":
    evaluate_model()
