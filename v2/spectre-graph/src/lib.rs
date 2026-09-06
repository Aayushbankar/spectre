use petgraph::stable_graph::{EdgeIndex, NodeIndex, StableDiGraph};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use std::collections::{HashMap, HashSet};
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
}

#[derive(Debug, Default)]
pub struct ProcessActions {
    pub children: Vec<ProcessKey>,
    pub opened_files: Vec<PathBuf>,
    pub connections: Vec<SocketKey>,
}

pub struct ProcessGraph {
    pub graph: StableDiGraph<NodePayload, EdgeData>,
    pub key_to_index: HashMap<NodeKey, NodeIndex>,
    pub active_pids: HashMap<u32, ProcessKey>,
    pub ttl_ns: u64,
}

impl ProcessGraph {
    pub fn new(ttl_ns: u64) -> Self {
        Self {
            graph: StableDiGraph::new(),
            key_to_index: HashMap::new(),
            active_pids: HashMap::new(),
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
            self.key_to_index.insert(node_key, idx);
            self.active_pids.insert(key.pid, key);
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
            let parent_idx = self.add_or_update_process(p_key, "unknown", "", 0, ts_ns);
            
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
            self.key_to_index.insert(file_key, idx);
            idx
        };

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
                key: socket.clone(),
                first_seen_ns: ts_ns,
                last_seen_ns: ts_ns,
            }));
            self.key_to_index.insert(sock_node_key, idx);
            idx
        };

        let edge_idx = self.graph.add_edge(
            proc_idx,
            sock_idx,
            EdgeData {
                kind: EdgeKind::ConnectedTo { proto: socket.proto },
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

        if let Some(&idx) = self.key_to_index.get(&NodeKey::Process(proc_key)) {
            if let Some(NodePayload::Process(proc)) = self.graph.node_weight_mut(idx) {
                proc.status = ProcessStatus::Exited {
                    exit_code,
                    exit_time_ns,
                };
                proc.last_seen_ns = exit_time_ns;
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

    pub fn prune_expired(&mut self, now_ns: u64) -> PruneStats {
        let cutoff = now_ns.saturating_sub(self.ttl_ns);
        let mut stats = PruneStats::default();

        let expired_edges: Vec<EdgeIndex> = self.graph
            .edge_indices()
            .filter(|&e| {
                let edge = &self.graph[e];
                if matches!(edge.kind, EdgeKind::Spawns) {
                    if let Some((_, child_idx)) = self.graph.edge_endpoints(e) {
                        if let Some(NodePayload::Process(child_proc)) = self.graph.node_weight(child_idx) {
                            if child_proc.status == ProcessStatus::Running {
                                return false;
                            }
                        }
                    }
                }
                edge.timestamp_ns < cutoff
            })
            .collect();

        for e in expired_edges {
            self.graph.remove_edge(e);
            stats.removed_edges += 1;
        }

        let expired_nodes: Vec<(NodeIndex, NodeKey)> = self.graph
            .node_indices()
            .filter_map(|n| {
                let weight = &self.graph[n];
                match weight {
                    NodePayload::Process(proc) => {
                        match proc.status {
                            ProcessStatus::Exited { exit_time_ns, .. } => {
                                if exit_time_ns < cutoff {
                                    let has_active_children = self.graph
                                        .edges_directed(n, Direction::Outgoing)
                                        .any(|e| matches!(e.weight().kind, EdgeKind::Spawns));

                                    if !has_active_children {
                                        Some((n, NodeKey::Process(proc.key)))
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            }
                            ProcessStatus::Running => None,
                        }
                    }
                    NodePayload::File(f) => {
                        if f.last_seen_ns < cutoff && self.graph.edges_directed(n, Direction::Incoming).count() == 0 {
                            Some((n, NodeKey::File(f.path.clone())))
                        } else {
                            None
                        }
                    }
                    NodePayload::Socket(s) => {
                        if s.last_seen_ns < cutoff && self.graph.edges_directed(n, Direction::Incoming).count() == 0 {
                            Some((n, NodeKey::Socket(s.key.clone())))
                        } else {
                            None
                        }
                    }
                }
            })
            .collect();

        for (idx, key) in expired_nodes {
            self.graph.remove_node(idx);
            self.key_to_index.remove(&key);
            stats.removed_nodes += 1;
        }

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pid_reuse_disambiguation() {
        let mut pg = ProcessGraph::new(60_000_000_000);

        let key1 = ProcessKey::new(1001, 1_000_000);
        let key2 = ProcessKey::new(1001, 5_000_000);

        pg.add_or_update_process(key1, "bash", "bash -i", 1000, 1_000_000);
        assert_eq!(pg.get_active_process_key(1001), Some(key1));

        pg.record_exit(key1, 0, 2_000_000);
        assert_eq!(pg.get_active_process_key(1001), None);

        pg.add_or_update_process(key2, "python3", "python3 exploit.py", 1000, 5_000_000);
        assert_eq!(pg.get_active_process_key(1001), Some(key2));

        let idx1 = *pg.key_to_index.get(&NodeKey::Process(key1)).unwrap();
        let idx2 = *pg.key_to_index.get(&NodeKey::Process(key2)).unwrap();
        assert_ne!(idx1, idx2);

        if let NodePayload::Process(p1) = &pg.graph[idx1] {
            assert_eq!(p1.comm, "bash");
            assert!(matches!(p1.status, ProcessStatus::Exited { .. }));
        }
        if let NodePayload::Process(p2) = &pg.graph[idx2] {
            assert_eq!(p2.comm, "python3");
            assert_eq!(p2.status, ProcessStatus::Running);
        }
    }

    #[test]
    fn test_ancestor_resolution_and_cycle_prevention() {
        let mut pg = ProcessGraph::new(60_000_000_000);

        let k_init = ProcessKey::new(1, 100);
        let k_sshd = ProcessKey::new(500, 200);
        let k_bash = ProcessKey::new(600, 300);
        let k_curl = ProcessKey::new(700, 400);

        pg.record_spawn(None, k_init, "systemd", "/sbin/init", 0, 100);
        pg.record_spawn(Some(k_init), k_sshd, "sshd", "/usr/sbin/sshd", 0, 200);
        pg.record_spawn(Some(k_sshd), k_bash, "bash", "-bash", 1000, 300);
        pg.record_spawn(Some(k_bash), k_curl, "curl", "curl evil.com", 1000, 400);

        let ancestors_2 = pg.resolve_ancestors(&k_curl, 2);
        assert_eq!(ancestors_2.len(), 2);
        assert_eq!(ancestors_2[0].key, k_bash);
        assert_eq!(ancestors_2[1].key, k_sshd);

        let ancestors_all = pg.resolve_ancestors(&k_curl, 10);
        assert_eq!(ancestors_all.len(), 3);
        assert_eq!(ancestors_all[2].key, k_init);

        // Inject cycle
        let curl_idx = *pg.key_to_index.get(&NodeKey::Process(k_curl)).unwrap();
        let init_idx = *pg.key_to_index.get(&NodeKey::Process(k_init)).unwrap();
        pg.graph.add_edge(curl_idx, init_idx, EdgeData {
            kind: EdgeKind::Spawns,
            timestamp_ns: 500,
        });

        let cycle_test = pg.resolve_ancestors(&k_curl, 50);
        assert_eq!(cycle_test.len(), 3);
    }
}
