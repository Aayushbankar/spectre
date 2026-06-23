use petgraph::graph::{NodeIndex, DiGraph};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub enum NodeType {
    Process { pid: u32, comm: String },
    File { path: String },
    Socket { raddr: String },
}

#[derive(Debug, Clone)]
pub struct NodeData {
    pub node_type: NodeType,
    pub last_seen: u64,
}

#[derive(Debug, Clone)]
pub struct EdgeData {
    pub rel_type: String, // "SPAWNS", "READS", "CONNECTS"
    pub timestamp: u64,
}

pub struct ProcessGraph {
    pub graph: DiGraph<NodeData, EdgeData>,
    pub node_map: HashMap<String, NodeIndex>,
    pub window_size_sec: u64,
}

impl ProcessGraph {
    pub fn new(window_size_sec: u64) -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
            window_size_sec,
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    pub fn add_process(&mut self, pid: u32, comm: &str) -> NodeIndex {
        let key = format!("proc_{}", pid);
        let now = Self::now();
        if let Some(&idx) = self.node_map.get(&key) {
            self.graph[idx].last_seen = now;
            idx
        } else {
            let idx = self.graph.add_node(NodeData {
                node_type: NodeType::Process { pid, comm: comm.to_string() },
                last_seen: now,
            });
            self.node_map.insert(key, idx);
            idx
        }
    }

    pub fn add_spawn_edge(&mut self, parent_pid: u32, child_pid: u32, child_comm: &str) {
        let p_idx = self.add_process(parent_pid, "unknown");
        let c_idx = self.add_process(child_pid, child_comm);
        self.graph.add_edge(p_idx, c_idx, EdgeData {
            rel_type: "SPAWNS".to_string(),
            timestamp: Self::now(),
        });
    }

    pub fn expire_old_events(&mut self) {
        let cutoff = Self::now().saturating_sub(self.window_size_sec);
        
        // Remove expired edges
        let edges_to_remove: Vec<_> = self.graph.edge_indices()
            .filter(|&e| self.graph[e].timestamp < cutoff)
            .collect();
        for e in edges_to_remove {
            self.graph.remove_edge(e);
        }

        // Remove orphaned nodes that haven't been seen recently
        let nodes_to_remove: Vec<_> = self.graph.node_indices()
            .filter(|&n| self.graph[n].last_seen < cutoff && self.graph.edges(n).count() == 0)
            .collect();
        
        for n in nodes_to_remove {
            let data = self.graph.remove_node(n).unwrap();
            match data.node_type {
                NodeType::Process { pid, .. } => {
                    self.node_map.remove(&format!("proc_{}", pid));
                }
                NodeType::File { path } => {
                    self.node_map.remove(&format!("file_{}", path));
                }
                NodeType::Socket { raddr } => {
                    self.node_map.remove(&format!("sock_{}", raddr));
                }
            }
        }
    }
}
