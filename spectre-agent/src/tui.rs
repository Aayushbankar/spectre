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
pub enum UiMessage {
    Event(UiEventItem),
    Alert(UiAlertItem),
    Metrics(UiMetrics),
    Tree(Vec<String>),
    #[allow(dead_code)]
    Quit,
}

pub struct TuiApp {
    pub active_tab: usize,
    pub events: VecDeque<UiEventItem>,
    pub alerts: VecDeque<UiAlertItem>,
    pub metrics: UiMetrics,
    pub process_tree: Vec<String>,
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

    pub fn handle_message(&mut self, msg: UiMessage) {
        match msg {
            UiMessage::Event(ev) => self.push_event(ev),
            UiMessage::Alert(al) => self.push_alert(al),
            UiMessage::Metrics(m) => self.update_metrics(m),
            UiMessage::Tree(t) => self.update_tree(t),
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
                        app.active_tab = (app.active_tab + 1) % 3;
                    }
                    KeyCode::BackTab => {
                        if app.active_tab == 0 {
                            app.active_tab = 2;
                        } else {
                            app.active_tab -= 1;
                        }
                    }
                    KeyCode::Char('1') => app.active_tab = 0,
                    KeyCode::Char('2') => app.active_tab = 1,
                    KeyCode::Char('3') => app.active_tab = 2,
                    KeyCode::Char('x') | KeyCode::Char('X') => {
                        app.alerts.clear();
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

    let tab_titles = vec![" [1] Dashboard ", " [2] Process Lineage ", " [3] Security Alerts "];
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
        Span::styled(" [Tab]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Switch View  | "),
        Span::styled("[1-3]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Jump Tab  | "),
        Span::styled("[X]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Clear Alerts  | "),
        Span::styled("[Q / Ctrl-C]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Exit"),
    ]);

    let footer = Paragraph::new(help_line).alignment(Alignment::Center);
    f.render_widget(footer, area);
}
