use std::collections::HashMap;
use spectre_graph::{ProcessGraph, ProcessKey};

pub fn enrich_event_from_graph(
    graph: &ProcessGraph,
    proc_key: &ProcessKey,
    event_map: &mut HashMap<String, String>,
) {
    if let Some(parent) = graph.get_parent(proc_key) {
        event_map.insert("ParentImage".to_string(), parent.comm.clone());
        event_map.insert("ParentCommandLine".to_string(), parent.cmdline.clone());
    }

    let ancestors = graph.resolve_ancestors(proc_key, 10);
    if !ancestors.is_empty() {
        let ancestor_comms: Vec<&str> = ancestors.iter().map(|a| a.comm.as_str()).collect();
        event_map.insert("AncestorImages".to_string(), ancestor_comms.join(" "));
    }
}
