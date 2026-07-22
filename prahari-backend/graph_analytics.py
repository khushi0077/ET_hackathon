import networkx as nx
import time

class GraphAnalytics:
    def __init__(self):
        self.G = nx.DiGraph()
        self.connections = [] # list of (timestamp, src, dst)

    def add_flow(self, flow):
        src = flow["src_ip"]
        dst = flow["dst_ip"]
        ts = flow["timestamp"]
        
        self.G.add_node(src)
        self.G.add_node(dst)
        
        if self.G.has_edge(src, dst):
            self.G[src][dst]["weight"] += 1
            self.G[src][dst]["last_seen"] = ts
        else:
            self.G.add_edge(src, dst, weight=1, last_seen=ts)
            
        self.connections.append((ts, src, dst))
        
    def detect_lateral_movement(self):
        now = time.time()
        # Clean up old connections > 60s
        self.connections = [c for c in self.connections if now - c[0] <= 60]
        
        src_dst_map = {}
        for ts, src, dst in self.connections:
            if src not in src_dst_map:
                src_dst_map[src] = set()
            src_dst_map[src].add(dst)
            
        anomalies = []
        for src, dsts in src_dst_map.items():
            if len(dsts) > 4:
                anomalies.append({
                    "src_ip": src,
                    "distinct_dsts": len(dsts),
                    "reason": "Touched >4 distinct destinations in 60s"
                })
        return anomalies

    def get_topology(self):
        nodes = [{"id": n} for n in self.G.nodes()]
        links = [{"source": u, "target": v, "weight": d["weight"]} for u, v, d in self.G.edges(data=True)]
        return {"nodes": nodes, "links": links}

graph_engine = GraphAnalytics()
