use std::collections::HashMap;
use spectre_rules::{SigmaRule, SigmaEngine};
use spectre_graph::{ProcessGraph, ProcessKey};

#[test]
fn test_graph_enriched_parent_behavioral_rule() {
    let mut graph = ProcessGraph::new(60_000_000_000);

    let rule_yaml = r#"
title: "Web Server Spawns Interactive Shell"
id: "spectre-webserver-shell"
detection:
  selection:
    ParentImage|endswith: "nginx"
    Image|endswith: "sh"
    CommandLine|contains: "whoami"
  condition: "selection"
"#;
    let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
    let engine = SigmaEngine::parse(&rule).unwrap();

    let t0 = 1000;
    let nginx_key = ProcessKey::new(500, t0);
    graph.add_or_update_process(nginx_key, "nginx", "/usr/sbin/nginx", 33, t0);

    let t1 = 2000;
    let shell_key = ProcessKey::new(501, t1);
    graph.record_spawn(Some(nginx_key), shell_key, "sh", "sh -c whoami", 33, t1);

    let mut event_map = HashMap::new();
    event_map.insert("Image".to_string(), "sh".to_string());
    event_map.insert("CommandLine".to_string(), "sh -c whoami".to_string());

    if let Some(parent) = graph.get_parent(&shell_key) {
        event_map.insert("ParentImage".to_string(), parent.comm);
        event_map.insert("ParentCommandLine".to_string(), parent.cmdline);
    }

    assert!(engine.evaluate(&event_map), "Expected behavioral rule to match via graph enrichment!");
}

#[test]
fn test_deep_ancestor_enrichment() {
    let mut graph = ProcessGraph::new(60_000_000_000);

    let rule_yaml = r#"
title: "Descendant Network Recon From Web Server"
id: "spectre-ancestor-recon"
detection:
  selection_tool:
    CommandLine|contains: "curl"
  selection_origin:
    AncestorImages|contains: "apache2"
  condition: "selection_tool and selection_origin"
"#;
    let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
    let engine = SigmaEngine::parse(&rule).unwrap();

    let k_apache = ProcessKey::new(400, 100);
    let k_php = ProcessKey::new(401, 200);
    let k_sh = ProcessKey::new(402, 300);
    let k_curl = ProcessKey::new(403, 400);

    graph.record_spawn(None, k_apache, "apache2", "/usr/sbin/apache2", 33, 100);
    graph.record_spawn(Some(k_apache), k_php, "php-fpm", "php-fpm: pool www", 33, 200);
    graph.record_spawn(Some(k_php), k_sh, "bash", "bash -i", 33, 300);
    graph.record_spawn(Some(k_sh), k_curl, "curl", "curl http://recon.internal", 33, 400);

    let mut event_map = HashMap::new();
    event_map.insert("Image".to_string(), "curl".to_string());
    event_map.insert("CommandLine".to_string(), "curl http://recon.internal".to_string());

    let ancestors = graph.resolve_ancestors(&k_curl, 10);
    let ancestor_images = ancestors.iter().map(|a| a.comm.as_str()).collect::<Vec<_>>().join(" ");
    event_map.insert("AncestorImages".to_string(), ancestor_images);

    assert!(engine.evaluate(&event_map), "Expected deep ancestor rule to match via graph traversal!");
}
