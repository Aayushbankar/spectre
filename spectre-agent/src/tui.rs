use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph, Row, Table, Tabs},
    Frame, Terminal,
};
use std::collections::VecDeque;
use std::io::{self, Stdout};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct UiEventItem {
    pub timestamp: String,
    pub event_type: String,
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub cmdline: String,
}

#[derive(Debug, Clone)]
pub struct UiAlertItem {
    pub timestamp: String,
    pub rule_id: String,
    pub rule_title: String,
    pub pid: u32,
    pub comm: String,
    pub parent_comm: String,
    pub cmdline: String,
}

#[derive(Debug, Clone, Default)]
pub struct UiMetrics {
    pub events_total: u64,
    pub events_rate: u64,
    pub alerts_total: u64,
    pub drops_total: u64,
    pub graph_nodes: usize,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UiChainNode {
    pub pid: u32,
    pub comm: String,
    pub cmdline: String,
    pub uid: u32,
    pub is_active: bool,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct UiChainItem {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub cmdline: String,
    pub uid: u32,
    pub is_active: bool,
    pub exit_code: Option<i32>,
    pub timestamp_str: String,
    pub duration_str: String,
    pub ancestors: Vec<UiChainNode>,
    pub children: Vec<UiChainNode>,
    pub files: Vec<String>,
    pub sockets: Vec<String>,
    pub alert_title: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainFilter {
    All,
    RealtimeOnly,
    HistoricalOnly,
}

#[derive(Debug, Clone)]
pub enum UiMessage {
    Event(UiEventItem),
    Alert(UiAlertItem),
    Metrics(UiMetrics),
    Tree(Vec<String>),
    Chains(Vec<UiChainItem>),
    #[allow(dead_code)]
    Quit,
}

pub struct TuiApp {
    pub active_tab: usize,
    pub events: VecDeque<UiEventItem>,
    pub alerts: VecDeque<UiAlertItem>,
    pub metrics: UiMetrics,
    pub process_tree: Vec<String>,
    pub chains: Vec<UiChainItem>,
    pub selected_chain_idx: usize,
    pub chain_filter: ChainFilter,
    pub is_mock: bool,
    pub should_quit: bool,
    pub start_time: Instant,
}

impl TuiApp {
    pub fn new(is_mock: bool) -> Self {
        Self {
            active_tab: 0,
            events: VecDeque::with_capacity(100),
            alerts: VecDeque::with_capacity(50),
            metrics: UiMetrics::default(),
            process_tree: Vec::new(),
            chains: Vec::new(),
            selected_chain_idx: 0,
            chain_filter: ChainFilter::All,
            is_mock,
            should_quit: false,
            start_time: Instant::now(),
        }
    }

    pub fn push_event(&mut self, item: UiEventItem) {
        if self.events.len() >= 100 {
            self.events.pop_back();
        }
        self.events.push_front(item);
    }

    pub fn push_alert(&mut self, item: UiAlertItem) {
        if self.alerts.len() >= 50 {
            self.alerts.pop_back();
        }
        self.alerts.push_front(item);
    }

    pub fn update_metrics(&mut self, m: UiMetrics) {
        self.metrics = m;
    }

    pub fn update_tree(&mut self, tree: Vec<String>) {
        self.process_tree = tree;
    }

    pub fn update_chains(&mut self, incoming: Vec<UiChainItem>) {
        for inc in incoming {
            if let Some(pos) = self.chains.iter().position(|c| c.pid == inc.pid && c.comm == inc.comm) {
                let prev_alert = self.chains[pos].alert_title.clone();
                self.chains[pos] = inc;
                if self.chains[pos].alert_title.is_none() {
                    self.chains[pos].alert_title = prev_alert;
                }
            } else {
                self.chains.insert(0, inc);
                if self.chains.len() > 200 {
                    self.chains.pop();
                }
            }
        }
    }

    pub fn filtered_chains(&self) -> Vec<&UiChainItem> {
        self.chains.iter().filter(|c| {
            match self.chain_filter {
                ChainFilter::All => true,
                ChainFilter::RealtimeOnly => c.is_active,
                ChainFilter::HistoricalOnly => !c.is_active,
            }
        }).collect()
    }

    pub fn cycle_chain_filter(&mut self) {
        self.chain_filter = match self.chain_filter {
            ChainFilter::All => ChainFilter::RealtimeOnly,
            ChainFilter::RealtimeOnly => ChainFilter::HistoricalOnly,
            ChainFilter::HistoricalOnly => ChainFilter::All,
        };
        self.selected_chain_idx = 0;
    }

    pub fn handle_message(&mut self, msg: UiMessage) {
        match msg {
            UiMessage::Event(ev) => self.push_event(ev),
            UiMessage::Alert(al) => self.push_alert(al),
            UiMessage::Metrics(m) => self.update_metrics(m),
            UiMessage::Tree(t) => self.update_tree(t),
            UiMessage::Chains(c) => self.update_chains(c),
            UiMessage::Quit => self.should_quit = true,
        }
    }
}

pub struct TuiRunner {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TuiRunner {
    pub fn init() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    pub fn render(&mut self, app: &TuiApp) -> io::Result<()> {
        self.terminal.draw(|f| ui(f, app))?;
        Ok(())
    }

    pub fn handle_input(app: &mut TuiApp) -> io::Result<()> {
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                        app.should_quit = true;
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.should_quit = true;
                    }
                    KeyCode::Tab => {
                        app.active_tab = (app.active_tab + 1) % 4;
                    }
                    KeyCode::BackTab => {
                        if app.active_tab == 0 {
                            app.active_tab = 3;
                        } else {
                            app.active_tab -= 1;
                        }
                    }
                    KeyCode::Char('1') => app.active_tab = 0,
                    KeyCode::Char('2') => app.active_tab = 1,
                    KeyCode::Char('3') => app.active_tab = 2,
                    KeyCode::Char('4') => app.active_tab = 3,
                    KeyCode::Char('x') | KeyCode::Char('X') => {
                        app.alerts.clear();
                    }
                    KeyCode::Up | KeyCode::Char('k') | KeyCode::Char('K') if app.active_tab == 3 => {
                        app.selected_chain_idx = app.selected_chain_idx.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('J') if app.active_tab == 3 => {
                        let count = app.filtered_chains().len();
                        if count > 0 {
                            app.selected_chain_idx = (app.selected_chain_idx + 1).min(count - 1);
                        }
                    }
                    KeyCode::Char('f') | KeyCode::Char('F') if app.active_tab == 3 => {
                        app.cycle_chain_filter();
                    }
                    KeyCode::Home if app.active_tab == 3 => {
                        app.selected_chain_idx = 0;
                    }
                    KeyCode::End if app.active_tab == 3 => {
                        let count = app.filtered_chains().len();
                        if count > 0 {
                            app.selected_chain_idx = count - 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

impl Drop for TuiRunner {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
    }
}

fn ui(f: &mut Frame, app: &TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header & Tabs
            Constraint::Min(10),   // Main View Area
            Constraint::Length(4), // Metrics Summary Bar
            Constraint::Length(2), // Help / Footer
        ])
        .split(f.area());

    // 1. Header & Tabs
    render_header(f, chunks[0], app);

    // 2. Active View
    match app.active_tab {
        0 => render_dashboard_tab(f, chunks[1], app),
        1 => render_process_tree_tab(f, chunks[1], app),
        2 => render_alerts_tab(f, chunks[1], app),
        3 => render_chain_inspector_tab(f, chunks[1], app),
        _ => {}
    }

    // 3. Metrics Summary Bar
    render_metrics_bar(f, chunks[2], app);

    // 4. Footer Help
    render_footer(f, chunks[3]);
}

fn render_header(f: &mut Frame, area: Rect, app: &TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(32), Constraint::Min(20)])
        .split(area);

    let mode_badge = if app.is_mock {
        Span::styled(" [MOCK SIMULATION] ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" [KERNEL eBPF LIVE] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
    };

    let title = Paragraph::new(Line::from(vec![
        Span::styled("⚡ SPECTRE", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" HIDS Engine"),
        mode_badge,
    ]))
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded));
    f.render_widget(title, chunks[0]);

    let tab_titles = vec![" [1] Dashboard ", " [2] Lineage Tree ", " [3] Security Alerts ", " [4] Chain Inspector "];
    let tabs = Tabs::new(tab_titles)
        .select(app.active_tab)
        .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded))
        .style(Style::default().fg(Color::Gray))
        .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    f.render_widget(tabs, chunks[1]);
}

fn render_dashboard_tab(f: &mut Frame, area: Rect, app: &TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    // Left: Live Kernel Event Stream
    let rows: Vec<Row> = app
        .events
        .iter()
        .take(15)
        .map(|e| {
            let type_color = match e.event_type.as_str() {
                "EXEC" => Color::Green,
                "FORK" => Color::Blue,
                "EXIT" => Color::DarkGray,
                _ => Color::White,
            };
            Row::new(vec![
                Span::raw(&e.timestamp),
                Span::styled(&e.event_type, Style::default().fg(type_color)),
                Span::raw(format!("{}/{}", e.pid, e.ppid)),
                Span::styled(&e.comm, Style::default().fg(Color::Cyan)),
                Span::raw(&e.cmdline),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(9),
        Constraint::Length(6),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Min(20),
    ];

    let events_table = Table::new(rows, widths)
        .header(
            Row::new(vec!["Time", "Type", "PID/PPID", "Binary", "Command Line"])
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::default()
                .title(" 📥 Live Kernel Event Stream ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        );
    f.render_widget(events_table, chunks[0]);

    // Right: Active Alerts Feed
    let alert_items: Vec<ListItem> = app
        .alerts
        .iter()
        .take(10)
        .map(|a| {
            let title_line = Line::from(vec![
                Span::styled("🚨 ", Style::default().fg(Color::Red)),
                Span::styled(&a.rule_title, Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                Span::styled(format!(" [{}]", a.timestamp), Style::default().fg(Color::DarkGray)),
            ]);
            let detail_line = Line::from(vec![
                Span::raw("   PID: "),
                Span::styled(format!("{}", a.pid), Style::default().fg(Color::Yellow)),
                Span::raw(" | Comm: "),
                Span::styled(&a.comm, Style::default().fg(Color::Cyan)),
                Span::raw(" | Parent: "),
                Span::styled(&a.parent_comm, Style::default().fg(Color::Magenta)),
            ]);
            let cmd_line = Line::from(vec![
                Span::raw("   Cmd: "),
                Span::styled(&a.cmdline, Style::default().fg(Color::Gray)),
            ]);
            ListItem::new(vec![title_line, detail_line, cmd_line, Line::from("")])
        })
        .collect();

    let alerts_list = List::new(alert_items).block(
        Block::default()
            .title(format!(" 🚨 Critical Security Alerts ({}) ", app.alerts.len()))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(if !app.alerts.is_empty() {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Gray)
            }),
    );
    f.render_widget(alerts_list, chunks[1]);
}

fn render_process_tree_tab(f: &mut Frame, area: Rect, app: &TuiApp) {
    let items: Vec<ListItem> = if app.process_tree.is_empty() {
        vec![ListItem::new("No active process lineage branches recorded in graph.")]
    } else {
        app.process_tree
            .iter()
            .map(|line| {
                let style = if line.contains("🚨") {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                } else if line.contains("systemd") || line.contains("init") {
                    Style::default().fg(Color::Blue)
                } else {
                    Style::default().fg(Color::White)
                };
                ListItem::new(Span::styled(line, style))
            })
            .collect()
    };

    let tree_list = List::new(items).block(
        Block::default()
            .title(" 🌳 Generational Process Lineage Graph (StableDiGraph) ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded),
    );
    f.render_widget(tree_list, area);
}

fn render_alerts_tab(f: &mut Frame, area: Rect, app: &TuiApp) {
    let items: Vec<ListItem> = if app.alerts.is_empty() {
        vec![ListItem::new("No security alerts fired. System nominal.")]
    } else {
        app.alerts
            .iter()
            .map(|a| {
                let header = Line::from(vec![
                    Span::styled("🚨 RULE TRIGGERED: ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                    Span::styled(&a.rule_title, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    Span::styled(format!(" (ID: {})", a.rule_id), Style::default().fg(Color::DarkGray)),
                    Span::styled(format!(" @ {}", a.timestamp), Style::default().fg(Color::Yellow)),
                ]);
                let target = Line::from(vec![
                    Span::styled("   Target: ", Style::default().fg(Color::Cyan)),
                    Span::styled(format!("PID {}", a.pid), Style::default().fg(Color::Yellow)),
                    Span::raw(format!(" ({})", a.comm)),
                    Span::styled("  |  Parent: ", Style::default().fg(Color::Cyan)),
                    Span::styled(&a.parent_comm, Style::default().fg(Color::Magenta)),
                ]);
                let cmd = Line::from(vec![
                    Span::styled("   CommandLine: ", Style::default().fg(Color::Cyan)),
                    Span::styled(&a.cmdline, Style::default().fg(Color::White)),
                ]);
                let action = Line::from(vec![
                    Span::styled("   Containment: ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                    Span::styled("pidfd_send_signal -> SIGSTOP (Freeze) -> SIGKILL (Terminated)", Style::default().fg(Color::Green)),
                ]);
                ListItem::new(vec![header, target, cmd, action, Line::from("")])
            })
            .collect()
    };

    let full_alerts = List::new(items).block(
        Block::default()
            .title(format!(" 🚨 Security Incident & Mitigation Ledger ({}) ", app.alerts.len()))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Red)),
    );
    f.render_widget(full_alerts, area);
}

fn render_metrics_bar(f: &mut Frame, area: Rect, app: &TuiApp) {
    let uptime = app.start_time.elapsed().as_secs();
    let uptime_str = format!("{:02}:{:02}:{:02}", uptime / 3600, (uptime % 3600) / 60, uptime % 60);

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ])
        .split(area);

    let p1 = Paragraph::new(vec![
        Line::from(Span::styled("Total Ingested", Style::default().fg(Color::Gray))),
        Line::from(Span::styled(format!("{}", app.metrics.events_total), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
    ])
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded))
    .alignment(Alignment::Center);

    let p2 = Paragraph::new(vec![
        Line::from(Span::styled("Throughput Rate", Style::default().fg(Color::Gray))),
        Line::from(Span::styled(format!("{}/sec", app.metrics.events_rate), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))),
    ])
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded))
    .alignment(Alignment::Center);

    let p3 = Paragraph::new(vec![
        Line::from(Span::styled("Sigma Alerts", Style::default().fg(Color::Gray))),
        Line::from(Span::styled(
            format!("{}", app.metrics.alerts_total),
            if app.metrics.alerts_total > 0 {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            },
        )),
    ])
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded))
    .alignment(Alignment::Center);

    let p4 = Paragraph::new(vec![
        Line::from(Span::styled("Active Graph Nodes", Style::default().fg(Color::Gray))),
        Line::from(Span::styled(format!("{}", app.metrics.graph_nodes), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))),
    ])
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded))
    .alignment(Alignment::Center);

    let p5 = Paragraph::new(vec![
        Line::from(Span::styled("Uptime / RingBuf Drops", Style::default().fg(Color::Gray))),
        Line::from(Span::styled(format!("{} | Drops: {}", uptime_str, app.metrics.drops_total), Style::default().fg(Color::White))),
    ])
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded))
    .alignment(Alignment::Center);

    f.render_widget(p1, chunks[0]);
    f.render_widget(p2, chunks[1]);
    f.render_widget(p3, chunks[2]);
    f.render_widget(p4, chunks[3]);
    f.render_widget(p5, chunks[4]);
}

fn render_footer(f: &mut Frame, area: Rect) {
    let help_line = Line::from(vec![
        Span::styled(" [Tab/1-4]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Switch Tab  | "),
        Span::styled("[↑/↓ or j/k]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Select Chain  | "),
        Span::styled("[F]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Filter (All/Live/Old)  | "),
        Span::styled("[X]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Clear Alerts  | "),
        Span::styled("[Q]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Exit"),
    ]);

    let footer = Paragraph::new(help_line).alignment(Alignment::Center);
    f.render_widget(footer, area);
}

fn render_chain_inspector_tab(f: &mut Frame, area: Rect, app: &TuiApp) {
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(area);

    let filtered = app.filtered_chains();
    let selected_idx = app.selected_chain_idx.min(filtered.len().saturating_sub(1));

    // Left Panel: Process Chains List
    let filter_badge = match app.chain_filter {
        ChainFilter::All => "ALL (LIVE + OLD)",
        ChainFilter::RealtimeOnly => "LIVE REAL-TIME",
        ChainFilter::HistoricalOnly => "OLD / HISTORICAL",
    };

    let list_items: Vec<ListItem> = if filtered.is_empty() {
        vec![ListItem::new(Span::styled(
            "No process chains recorded under current filter.\nPress [F] to switch filter (All / Live / Old).",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        filtered
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let is_selected = i == selected_idx;
                let status_icon = if c.alert_title.is_some() {
                    Span::styled("🚨 ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
                } else if c.is_active {
                    Span::styled("● ", Style::default().fg(Color::Green))
                } else {
                    Span::styled("■ ", Style::default().fg(Color::DarkGray))
                };

                let prefix = if is_selected { "▶ " } else { "  " };

                let state_str = if c.is_active {
                    "LIVE"
                } else if let Some(code) = c.exit_code {
                    if code == 0 { "EXIT:0" } else { "EXIT:ERR" }
                } else {
                    "OLD"
                };

                let state_style = if c.is_active {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::DarkGray)
                };

                let primary_line = Line::from(vec![
                    Span::styled(prefix, if is_selected { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default() }),
                    status_icon,
                    Span::styled(format!("PID {} ", c.pid), if is_selected { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Cyan) }),
                    Span::styled(format!("[{}] ", c.comm), Style::default().fg(Color::White).add_modifier(if is_selected { Modifier::BOLD } else { Modifier::empty() })),
                    Span::styled(format!("({})", state_str), state_style),
                ]);

                let secondary_line = Line::from(vec![
                    Span::raw("    "),
                    Span::styled(format!("PPID: {} | UID: {} | {}", c.ppid, c.uid, c.timestamp_str), Style::default().fg(Color::DarkGray)),
                ]);

                let item_style = if is_selected {
                    Style::default().bg(Color::Rgb(30, 40, 60))
                } else {
                    Style::default()
                };

                ListItem::new(vec![primary_line, secondary_line]).style(item_style)
            })
            .collect()
    };

    let list_title = format!(" ⛓️ Process Chains [F: {}] ({}) ", filter_badge, filtered.len());
    let list_widget = List::new(list_items).block(
        Block::default()
            .title(list_title)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(list_widget, main_chunks[0]);

    // Right Panel: Graph (top) + Inspection Details (bottom)
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(56), Constraint::Percentage(44)])
        .split(main_chunks[1]);

    if let Some(&selected) = filtered.get(selected_idx) {
        // Render Visual Graph
        let mut graph_lines = Vec::new();
        graph_lines.push(Line::from(vec![
            Span::styled("KERNEL HOST ROOT NAMESPACE", Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        ]));

        let total_anc = selected.ancestors.len();
        for (i, anc) in selected.ancestors.iter().enumerate() {
            let indent = " │   ".repeat(i);
            let branch = " └──► ";
            let status_str = if anc.is_active { "[ACTIVE]" } else { "[EXITED]" };
            let status_color = if anc.is_active { Color::Green } else { Color::DarkGray };
            graph_lines.push(Line::from(vec![
                Span::raw(indent),
                Span::styled(branch, Style::default().fg(Color::Gray)),
                Span::styled(format!("PID {}: ", anc.pid), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(&anc.comm, Style::default().fg(Color::Cyan)),
                Span::raw(format!(" (uid: {}) ", anc.uid)),
                Span::styled(status_str, Style::default().fg(status_color)),
            ]));
        }

        let target_indent = " │   ".repeat(total_anc);
        let target_branch = " └──► ";
        let target_status = if let Some(code) = selected.exit_code {
            format!("[EXITED: Code {}]", code)
        } else if selected.is_active {
            "[ACTIVE LIVE]".to_string()
        } else {
            "[EXITED]".to_string()
        };
        let target_status_color = if selected.alert_title.is_some() {
            Color::Red
        } else if selected.is_active {
            Color::Green
        } else {
            Color::DarkGray
        };

        let target_badge = if selected.alert_title.is_some() { "🚨 [SELECTED TARGET] " } else { "⭐ [SELECTED TARGET] " };
        graph_lines.push(Line::from(vec![
            Span::raw(&target_indent),
            Span::styled(target_branch, Style::default().fg(Color::Yellow)),
            Span::styled(target_badge, Style::default().fg(if selected.alert_title.is_some() { Color::Red } else { Color::Yellow }).add_modifier(Modifier::BOLD)),
            Span::styled(format!("PID {}: ", selected.pid), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(&selected.comm, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(format!(" (uid: {}) ", selected.uid)),
            Span::styled(target_status, Style::default().fg(target_status_color).add_modifier(Modifier::BOLD)),
        ]));

        let child_indent = format!("{}      ", target_indent);
        for child in &selected.children {
            let c_status = if child.is_active { "[ACTIVE]" } else { "[EXITED]" };
            let c_color = if child.is_active { Color::Green } else { Color::DarkGray };
            graph_lines.push(Line::from(vec![
                Span::raw(&child_indent),
                Span::styled("├──► [CHILD PROCESS] ", Style::default().fg(Color::LightBlue)),
                Span::styled(format!("PID {}: ", child.pid), Style::default().fg(Color::Yellow)),
                Span::styled(&child.comm, Style::default().fg(Color::Cyan)),
                Span::raw(format!(" (uid: {}) ", child.uid)),
                Span::styled(c_status, Style::default().fg(c_color)),
            ]));
        }

        for sock in &selected.sockets {
            graph_lines.push(Line::from(vec![
                Span::raw(&child_indent),
                Span::styled("├──► 🌐 Network Socket: ", Style::default().fg(Color::LightMagenta)),
                Span::styled(sock, Style::default().fg(Color::White)),
            ]));
        }

        for file in &selected.files {
            graph_lines.push(Line::from(vec![
                Span::raw(&child_indent),
                Span::styled("└──► 📁 File Opened: ", Style::default().fg(Color::LightCyan)),
                Span::styled(file, Style::default().fg(Color::White)),
            ]));
        }

        if selected.children.is_empty() && selected.sockets.is_empty() && selected.files.is_empty() {
            graph_lines.push(Line::from(vec![
                Span::raw(&child_indent),
                Span::styled("└── (Leaf process - no further spawned children/edges)", Style::default().fg(Color::DarkGray)),
            ]));
        }

        let graph_block = Block::default()
            .title(" 🌳 Execution Chain Graph (Lineage & Offshoots) ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(if selected.alert_title.is_some() { Style::default().fg(Color::Red) } else { Style::default().fg(Color::Cyan) });
        let graph_widget = Paragraph::new(graph_lines).block(graph_block);
        f.render_widget(graph_widget, right_chunks[0]);

        // Render Telemetry & Inspection Details
        let mut detail_lines = Vec::new();
        detail_lines.push(Line::from(vec![
            Span::styled("Command Line: ", Style::default().fg(Color::Gray)),
            Span::styled(&selected.cmdline, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]));
        detail_lines.push(Line::from(vec![
            Span::styled("PID: ", Style::default().fg(Color::Gray)),
            Span::styled(format!("{}", selected.pid), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled("  |  PPID: ", Style::default().fg(Color::Gray)),
            Span::styled(format!("{}", selected.ppid), Style::default().fg(Color::Yellow)),
            Span::styled("  |  UID: ", Style::default().fg(Color::Gray)),
            Span::styled(format!("{}", selected.uid), Style::default().fg(Color::Cyan)),
            Span::styled("  |  State: ", Style::default().fg(Color::Gray)),
            if selected.is_active {
                Span::styled("● ACTIVE (Running)", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
            } else if let Some(code) = selected.exit_code {
                Span::styled(format!("■ EXITED (Exit Code: {})", code), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))
            } else {
                Span::styled("■ EXITED (Historical)", Style::default().fg(Color::DarkGray))
            },
        ]));
        detail_lines.push(Line::from(vec![
            Span::styled("First Seen: ", Style::default().fg(Color::Gray)),
            Span::styled(&selected.timestamp_str, Style::default().fg(Color::White)),
            Span::styled("  |  Duration: ", Style::default().fg(Color::Gray)),
            Span::styled(&selected.duration_str, Style::default().fg(Color::White)),
            Span::styled("  |  Lineage Depth: ", Style::default().fg(Color::Gray)),
            Span::styled(format!("{} hops", selected.ancestors.len()), Style::default().fg(Color::LightBlue)),
            Span::styled("  |  Spawned Children: ", Style::default().fg(Color::Gray)),
            Span::styled(format!("{}", selected.children.len()), Style::default().fg(Color::LightBlue)),
        ]));

        if let Some(ref alert) = selected.alert_title {
            detail_lines.push(Line::from(""));
            detail_lines.push(Line::from(vec![
                Span::styled("🚨 SECURITY ALERT: ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                Span::styled(alert, Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            ]));
            detail_lines.push(Line::from(vec![
                Span::styled("⚔️ CONTAINMENT: ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::styled("pidfd_send_signal -> SIGSTOP (Tree Freeze) -> SIGKILL (Terminated)", Style::default().fg(Color::Green)),
            ]));
        } else {
            detail_lines.push(Line::from(""));
            detail_lines.push(Line::from(vec![
                Span::styled("🛡️ POSTURE: ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::styled("Clean execution chain. No Sigma detection rules triggered.", Style::default().fg(Color::DarkGray)),
            ]));
        }

        let detail_block = Block::default()
            .title(" 🔍 Process Inspection & Telemetry Details ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded);
        let detail_widget = Paragraph::new(detail_lines).block(detail_block);
        f.render_widget(detail_widget, right_chunks[1]);
    } else {
        let empty_graph = Paragraph::new("Select a process chain on the left to view its execution graph.")
            .block(Block::default().title(" 🌳 Execution Chain Graph ").borders(Borders::ALL).border_type(BorderType::Rounded));
        let empty_detail = Paragraph::new("No process selected.")
            .block(Block::default().title(" 🔍 Process Inspection ").borders(Borders::ALL).border_type(BorderType::Rounded));
        f.render_widget(empty_graph, right_chunks[0]);
        f.render_widget(empty_detail, right_chunks[1]);
    }
}
