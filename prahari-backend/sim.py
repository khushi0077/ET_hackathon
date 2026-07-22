import asyncio
import random
import time
from faker import Faker

fake = Faker()
fake.seed_instance(42)

# Generate a static pool of IPs to allow behavioral baselining
SRC_IPS = [fake.ipv4_private() for _ in range(50)]
DST_IPS = [fake.ipv4_private() for _ in range(50)]
ATTACK_TYPES = ["port_scan", "dos_burst", "brute_force", "lateral_movement", "exfiltration"]

force_attack_queue = []

def generate_base_flow():
    src_ip = random.choice(SRC_IPS)
    dst_ip = random.choice(DST_IPS)
    dst_port = random.choice([80, 443, 22, 3389, 53, 445])
    return {
        "timestamp": time.time(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "bytes_sent": random.randint(100, 5000),
        "bytes_recv": random.randint(100, 5000),
        "duration": random.uniform(0.1, 2.0),
        "is_attack": False,
        "attack_type": None,
        "ot_telemetry": {
            "pressure": round(random.uniform(90.0, 110.0), 2),
            "temperature": round(random.uniform(35.0, 45.0), 2),
            "valve_status": "OPEN"
        }
    }

def inject_attack(flow):
    attack_type = random.choice(ATTACK_TYPES)
    flow["is_attack"] = True
    flow["attack_type"] = attack_type
    
    if attack_type == "port_scan":
        flow["dst_port"] = random.randint(1024, 65535)
        flow["bytes_sent"] = random.randint(40, 100)
        flow["bytes_recv"] = 0
    elif attack_type == "dos_burst":
        flow["bytes_sent"] = random.randint(10000, 50000)
    elif attack_type == "brute_force":
        flow["dst_port"] = random.choice([22, 3389])
        flow["bytes_sent"] = random.randint(200, 500)
    elif attack_type == "lateral_movement":
        flow["dst_port"] = 445
    elif attack_type == "exfiltration":
        flow["bytes_sent"] = random.randint(1000000, 5000000)
        
    if attack_type in ["lateral_movement", "exfiltration", "dos_burst"]:
        flow["ot_telemetry"]["pressure"] = round(random.uniform(200.0, 350.0), 2)
        flow["ot_telemetry"]["temperature"] = round(random.uniform(80.0, 120.0), 2)
        flow["ot_telemetry"]["valve_status"] = "CLOSED_ERR"
        
    return flow

async def event_stream():
    """Async generator yielding one event at a time."""
    while True:
        flow = generate_base_flow()
        
        # 5% chance of attack or forced attack
        if force_attack_queue:
            forced_type = force_attack_queue.pop(0)
            flow = inject_attack(flow)
            flow["attack_type"] = forced_type
        elif random.random() < 0.05:
            flow = inject_attack(flow)
            
        yield flow
        await asyncio.sleep(random.uniform(0.2, 0.5))

def generate_batch(size=1000, anomaly_ratio=0.01):
    """Generate a static batch for pre-training IsolationForest."""
    batch = []
    for _ in range(size):
        flow = generate_base_flow()
        if random.random() < anomaly_ratio:
            flow = inject_attack(flow)
        batch.append(flow)
    return batch
