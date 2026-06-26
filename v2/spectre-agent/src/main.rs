use aya::Bpf;
use aya::programs::TracePoint;
use aya::maps::RingBuf;
use std::convert::TryInto;
use std::collections::HashMap;
use tokio::signal;
use std::env;

use spectre_rules::{SigmaRule, SigmaEngine};
use spectre_graph::ProcessGraph;

#[repr(C)]
#[derive(Debug)]
struct ProcessEvent {
    pid: u32,
    comm: [u8; 16],
}

fn load_dummy_rules() -> SigmaEngine {
    let mut detection = HashMap::new();
    let mut sel = serde_yaml::Mapping::new();
    sel.insert(
        serde_yaml::Value::String("CommandLine|contains".to_string()),
        serde_yaml::Value::String("malicious".to_string())
    );
    detection.insert("selection1".to_string(), serde_yaml::Value::Mapping(sel));
    detection.insert("condition".to_string(), serde_yaml::Value::String("selection1".to_string()));

    let rule = SigmaRule {
        title: "Test Malicious Rule".to_string(),
        id: "rule-1".to_string(),
        detection,
    };

    SigmaEngine::parse(&rule).unwrap()
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    
    let args: Vec<String> = env::args().collect();
    let mock_mode = args.contains(&"--mock".to_string());

    let mut graph = ProcessGraph::new(60);
    let engine = load_dummy_rules();
    println!("Loaded Sigma Rules and Initialized Process Graph.");

    if mock_mode {
        println!("Running in MOCK mode (no root required)...");
        let mut pid_counter = 1000;
        loop {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    println!("Exiting...");
                    break;
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
                    let comm_clean = "malicious_payload";
                    println!("[EVENT] PID: {} | Command: {}", pid_counter, comm_clean);
                    
                    graph.add_spawn_edge(1, pid_counter, comm_clean);
                    
                    let mut event_map = HashMap::new();
                    event_map.insert("CommandLine".to_string(), comm_clean.to_string());
                    
                    if engine.evaluate(&event_map) {
                        println!("🚨 [ALERT] Sigma Rule Triggered! Process matched malicious signature.");
                    }
                    
                    graph.expire_old_events();
                    pid_counter += 1;
                }
            }
        }
    } else {
        let bpf_path = "../ebpf-c/sensor.o";
        println!("Loading eBPF object from {}", bpf_path);
        let mut bpf = Bpf::load_file(bpf_path)?;
        
        let program: &mut TracePoint = bpf.program_mut("handle_exec").unwrap().try_into()?;
        program.load()?;
        program.attach("sched", "sched_process_exec")?;
        println!("Attached tracepoint sched:sched_process_exec!");
        
        let mut ring_buf = RingBuf::try_from(bpf.map_mut("events").unwrap())?;
        println!("Waiting for process events (exec)... Press Ctrl-C to quit.");
        
        loop {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    println!("Exiting...");
                    break;
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(10)) => {
                    while let Some(item) = ring_buf.next() {
                        let data = &*item;
                        if data.len() >= std::mem::size_of::<ProcessEvent>() {
                            let ptr = data.as_ptr() as *const ProcessEvent;
                            let event: &ProcessEvent = unsafe { &*ptr };
                            
                            let comm = String::from_utf8_lossy(&event.comm);
                            let comm_clean = comm.trim_matches(char::from(0));
                            println!("[EVENT] PID: {} | Command: {}", event.pid, comm_clean);
                            
                            graph.add_spawn_edge(1, event.pid, comm_clean);
                            
                            let mut event_map = HashMap::new();
                            event_map.insert("CommandLine".to_string(), comm_clean.to_string());
                            
                            if engine.evaluate(&event_map) {
                                println!("🚨 [ALERT] Sigma Rule Triggered! Process matched malicious signature.");
                            }
                        }
                    }
                    graph.expire_old_events();
                }
            }
        }
    }

    Ok(())
}
