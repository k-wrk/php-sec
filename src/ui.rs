use crate::auditor::AuditReport;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap},
    Frame,
};

#[derive(Debug, PartialEq, Eq)]
pub enum AppMode {
    ViewingAudit,
    ConfirmFix,
    RunningFix,
}

pub struct AppState {
    pub reports: Vec<AuditReport>,
    pub selected_server_index: usize,
    pub mode: AppMode,
    pub status_message: String,
    pub fix_step: String,
    pub spinner_frame: usize,
}

const SPINNER_CHARS: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

impl AppState {
    pub fn new(reports: Vec<AuditReport>) -> Self {
        Self {
            reports,
            selected_server_index: 0,
            mode: AppMode::ViewingAudit,
            status_message: "Ready. [↑/↓] Navigate, [F] Fix/Upgrade, [R] Refresh, [Q] Quit.".into(),
            fix_step: String::new(),
            spinner_frame: 0,
        }
    }

    pub fn next_server(&mut self) {
        if !self.reports.is_empty() {
            self.selected_server_index = (self.selected_server_index + 1) % self.reports.len();
        }
    }

    pub fn prev_server(&mut self) {
        if !self.reports.is_empty() {
            if self.selected_server_index == 0 {
                self.selected_server_index = self.reports.len() - 1;
            } else {
                self.selected_server_index -= 1;
            }
        }
    }

    pub fn tick_spinner(&mut self) {
        self.spinner_frame = (self.spinner_frame + 1) % SPINNER_CHARS.len();
    }
}

pub fn draw_ui(frame: &mut Frame, state: &AppState) {
    let size = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(3),
        ])
        .split(size);

    // 1. Header
    let header_text = vec![
        Line::from(vec![
            Span::styled(" 🔒 PHP & Nginx Security Dashboard ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(" | "),
            Span::styled("Auditor & Remediator", Style::default().fg(Color::Gray)),
        ]),
    ];
    let header = Paragraph::new(header_text)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)))
        .alignment(Alignment::Center);
    frame.render_widget(header, chunks[0]);

    // 2. Middle Panel (Left: Server List / Right: Details Table)
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
        .split(chunks[1]);

    draw_server_list(frame, state, body_chunks[0]);
    draw_audit_details(frame, state, body_chunks[1]);

    // 3. Footer
    let footer_text = if state.mode == AppMode::RunningFix {
        Line::from(vec![
            Span::styled(" ● ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(&state.fix_step, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ])
    } else {
        let is_err = state.status_message.contains("failed") || state.status_message.contains("Failed") || state.status_message.contains("Error");
        let msg_style = if is_err {
            Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Green)
        };

        Line::from(vec![
            Span::styled(" [F] ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw("Fix  "),
            Span::styled(" [R] ", Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD)),
            Span::raw("Refresh  "),
            Span::styled(" [↑/↓] ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::raw("Nav  "),
            Span::styled(" [Q/Esc] ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::raw("Quit | "),
            Span::styled(&state.status_message, msg_style),
        ])
    };

    let footer = Paragraph::new(footer_text)
        .block(Block::default().borders(Borders::ALL))
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });
    frame.render_widget(footer, chunks[2]);

    // Modals
    match state.mode {
        AppMode::ConfirmFix => draw_confirm_modal(frame, state),
        AppMode::RunningFix => draw_running_modal(frame, state),
        _ => {}
    }
}

fn draw_server_list(frame: &mut Frame, state: &AppState, area: Rect) {
    let mut rows = Vec::new();
    for (i, report) in state.reports.iter().enumerate() {
        let is_selected = i == state.selected_server_index;
        let is_disconnected = report.connection_error.is_some();

        let (prefix, status_badge) = if is_disconnected {
            (
                Span::styled("✖ ", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
                Span::styled("OFFLINE", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
            )
        } else if report.checks.iter().all(|c| c.is_secure) {
            (
                Span::styled("● ", Style::default().fg(Color::Green)),
                Span::styled("OK", Style::default().fg(Color::Green)),
            )
        } else {
            (
                Span::styled("▲ ", Style::default().fg(Color::Yellow)),
                Span::styled("RISK", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
            )
        };

        let style = if is_selected {
            Style::default().bg(Color::Rgb(30, 45, 65)).fg(Color::White).add_modifier(Modifier::BOLD)
        } else if is_disconnected {
            Style::default().fg(Color::LightRed)
        } else {
            Style::default().fg(Color::White)
        };

        rows.push(Row::new(vec![
            Cell::from(Line::from(vec![
                prefix,
                Span::styled(report.server_name.clone(), style),
            ])),
            Cell::from(status_badge),
        ]));
    }

    let table = Table::new(rows, [Constraint::Percentage(65), Constraint::Percentage(35)])
        .block(
            Block::default()
                .title(" Servers / Hosts ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        );

    frame.render_widget(table, area);
}

fn draw_audit_details(frame: &mut Frame, state: &AppState, area: Rect) {
    if state.reports.is_empty() {
        let empty_msg = Paragraph::new("No servers found in report.")
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(empty_msg, area);
        return;
    }

    let report = &state.reports[state.selected_server_index];

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(8)])
        .split(area);

    let fpm_status = if report.fpm_active { "Active (OK)" } else { "Inactive/Not found" };
    let nginx_status = if report.nginx_active { "Active (OK)" } else { "Inactive" };

    let summary_line = vec![
        Line::from(vec![
            Span::styled(" Host: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!("{} ({})  |  ", report.host, report.os_info)),
            Span::styled("PHP: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!("{}  |  ", report.php_version)),
            Span::styled("FPM Service: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!("{} ({})  |  ", report.fpm_service.as_deref().unwrap_or("None"), fpm_status)),
            Span::styled("Nginx: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(nginx_status),
        ]),
    ];
    let summary = Paragraph::new(summary_line)
        .block(Block::default().borders(Borders::ALL).title(" Environment "))
        .wrap(Wrap { trim: true });
    frame.render_widget(summary, layout[0]);

    let header_row = Row::new(vec![
        Cell::from(Span::styled("Category", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
        Cell::from(Span::styled("Audited Item", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
        Cell::from(Span::styled("Current", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
        Cell::from(Span::styled("Expected", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
        Cell::from(Span::styled("Status", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
        Cell::from(Span::styled("Remediation / Recommendation", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
    ]);

    let rows: Vec<Row> = report.checks.iter().map(|chk| {
        let (status_text, style) = if chk.is_secure {
            ("✔ Secure", Style::default().fg(Color::Green))
        } else {
            ("✖ Vulnerable", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
        };

        Row::new(vec![
            Cell::from(chk.category.as_str()),
            Cell::from(chk.item.as_str()),
            Cell::from(chk.current_value.as_str()),
            Cell::from(chk.expected_value.as_str()),
            Cell::from(Span::styled(status_text, style)),
            Cell::from(chk.recommendation.as_str()),
        ])
    }).collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Length(24),
            Constraint::Length(14),
            Constraint::Length(14),
            Constraint::Length(14),
            Constraint::Min(30),
        ],
    )
    .header(header_row)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Security Audit: {} ", report.server_name)),
    );

    frame.render_widget(table, layout[1]);
}

fn draw_confirm_modal(frame: &mut Frame, state: &AppState) {
    let area = centered_rect(65, 35, frame.area());
    frame.render_widget(Clear, area);

    let server_name = &state.reports[state.selected_server_index].server_name;
    let text = vec![
        Line::from(vec![
            Span::styled(" REMEDIATION & UPGRADE CONFIRMATION ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(format!("Apply security fixes and updates to server '{}'?", server_name)),
        Line::from(""),
        Line::from("Planned operations:"),
        Line::from("  1. Run apt-get --only-upgrade on php*-fpm and php*-cli"),
        Line::from("  2. Inject '99-security-hardening.ini' into PHP-FPM conf.d"),
        Line::from("  3. Set 'server_tokens off;' with timestamped backup in Nginx"),
        Line::from("  4. Verify syntax ('nginx -t' and 'php-fpm -t')"),
        Line::from("  5. Safe service restart/reload"),
        Line::from(""),
        Line::from(vec![
            Span::styled(" [Y / Enter] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::raw("Confirm and Execute    "),
            Span::styled(" [N / Esc] ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::raw("Cancel"),
        ]),
    ];

    let modal = Paragraph::new(text)
        .block(
            Block::default()
                .title(" Confirmation Required ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(modal, area);
}

fn draw_running_modal(frame: &mut Frame, state: &AppState) {
    let area = centered_rect(55, 25, frame.area());
    frame.render_widget(Clear, area);

    let server_name = &state.reports[state.selected_server_index].server_name;

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("Applying fixes to '{}'...", server_name), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Current Step: ", Style::default().fg(Color::Gray)),
            Span::styled(&state.fix_step, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(Span::styled("Please do not interrupt or close the terminal.", Style::default().fg(Color::DarkGray))),
    ];

    let modal = Paragraph::new(text)
        .block(
            Block::default()
                .title(" Executing Operations ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(modal, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
