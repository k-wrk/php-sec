mod auditor;
mod config;
mod remediator;
mod ssh;
mod ui;

use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::stdout;
use std::path::PathBuf;

use crate::config::AppConfig;
use crate::remediator::Remediator;
use crate::ssh::RemoteClient;
use crate::ui::{AppMode, AppState};

#[derive(Parser, Debug)]
#[command(
    name = "php-sec",
    about = "Security Audit and Remediation for PHP/PHP-FPM and Nginx on Remote Servers"
)]
struct Args {
    #[arg(short, long, default_value = "servers.toml")]
    config: PathBuf,

    #[arg(long, help = "Run fast terminal audit without TUI")]
    cli: bool,

    #[arg(long, help = "Force prompt for SSH key passphrase before connecting")]
    ask_pass: bool,

    #[arg(long, help = "Initialize a default servers.toml configuration file and add it to .gitignore")]
    init: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.init {
        init_configuration()?;
        return Ok(());
    }

    if !args.config.exists() {
        eprintln!(
            "Configuration file '{}' not found. Run 'php-sec --init' to generate one.",
            args.config.display()
        );
        std::process::exit(1);
    }

    let cfg = config::load_config(&args.config)?;
    if cfg.servers.is_empty() {
        eprintln!("No servers found in {}", args.config.display());
        std::process::exit(1);
    }

    // Always prompt for passphrase if needed
    println!("🔑 SSH Key Passphrase (press Enter if no passphrase):");
    let passphrase = match rpassword::prompt_password("Enter passphrase: ") {
        Ok(p) if !p.trim().is_empty() => Some(p),
        _ => None,
    };

    println!("Connecting to droplets for initial audit...");
    let reports = audit_all_servers(&cfg, passphrase.as_deref())?;

    if args.cli {
        for report in &reports {
            println!("\n=== {} ({}) ===", report.server_name, report.host);
            println!("OS: {} | PHP: {}", report.os_info, report.php_version);
            for chk in &report.checks {
                let sym = if chk.is_secure { "✔" } else { "✖" };
                println!("  [{}] {}: {} (Expected: {})", sym, chk.item, chk.current_value, chk.expected_value);
            }
        }
        return Ok(());
    }

    // Initialize Ratatui TUI
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState::new(reports);

    // Main TUI Event Loop
    loop {
        terminal.draw(|f| ui::draw_ui(f, &state))?;

        if event::poll(std::time::Duration::from_millis(80))? {
            if let Event::Key(key) = event::read()? {
                match state.mode {
                    AppMode::ViewingAudit => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Down | KeyCode::Char('j') => state.next_server(),
                        KeyCode::Up | KeyCode::Char('k') => state.prev_server(),
                        KeyCode::Char('f') => {
                            if !state.reports.is_empty() {
                                state.mode = AppMode::ConfirmFix;
                            }
                        }
                        KeyCode::Char('r') => {
                            state.status_message = "Refreshing audit...".into();
                            terminal.draw(|f| ui::draw_ui(f, &state))?;
                            if let Ok(updated_reports) = audit_all_servers(&cfg, passphrase.as_deref()) {
                                state.reports = updated_reports;
                                state.status_message = "Audit refreshed successfully!".into();
                            }
                        }
                        _ => {}
                    },
                    AppMode::ConfirmFix => match key.code {
                        KeyCode::Char('y') | KeyCode::Enter => {
                            state.mode = AppMode::RunningFix;

                            let server = &cfg.servers[state.selected_server_index];
                            let identity_path = server.resolved_identity_file(cfg.defaults.as_ref());
                            let user = server.resolved_user(cfg.defaults.as_ref());
                            let port = server.resolved_port(cfg.defaults.as_ref());

                            // Step 1: Connect SSH
                            state.fix_step = "Connecting via SSH...".into();
                            state.tick_spinner();
                            terminal.draw(|f| ui::draw_ui(f, &state))?;

                            match RemoteClient::connect(&server.host, port, &user, identity_path.as_deref(), passphrase.as_deref()) {
                                Ok(client) => {
                                    let mut fix_success = true;
                                    let mut error_msg = String::new();

                                    // Extract needed info beforehand to avoid borrow checker conflicts
                                    let (php_version, nginx_active, fpm_service_name) = {
                                        let rep = &state.reports[state.selected_server_index];
                                        (
                                            rep.php_version.clone(),
                                            rep.nginx_active,
                                            rep.fpm_service.clone(),
                                        )
                                    };

                                    // Step 2: Upgrade PHP Packages
                                    state.fix_step = "Updating apt packages (php*-fpm, php*-cli)...".into();
                                    state.tick_spinner();
                                    terminal.draw(|f| ui::draw_ui(f, &state))?;

                                    if let Err(e) = Remediator::upgrade_php_packages(&client) {
                                        error_msg = format!("Package upgrade failed: {}", e);
                                        fix_success = false;
                                    }

                                    // Step 3: Apply php.ini Hardening
                                    if fix_success {
                                        state.fix_step = "Injecting PHP security hardening (conf.d)...".into();
                                        state.tick_spinner();
                                        terminal.draw(|f| ui::draw_ui(f, &state))?;

                                        let php_ver_parts: Vec<&str> = php_version.split('.').collect();
                                        if php_ver_parts.len() >= 2 {
                                            let major_minor = format!("{}.{}", php_ver_parts[0], php_ver_parts[1]);
                                            if let Err(e) = Remediator::apply_php_hardening(&client, &major_minor) {
                                                error_msg = format!("PHP hardening failed: {}", e);
                                                fix_success = false;
                                            }
                                        }
                                    }

                                    // Step 4: Apply Nginx Hardening
                                    if fix_success && nginx_active {
                                        state.fix_step = "Hardening Nginx (server_tokens off)...".into();
                                        state.tick_spinner();
                                        terminal.draw(|f| ui::draw_ui(f, &state))?;

                                        if let Err(e) = Remediator::apply_nginx_hardening(&client) {
                                            error_msg = format!("Nginx hardening failed: {}", e);
                                            fix_success = false;
                                        }
                                    }

                                    // Step 5: Safe Restart of Services
                                    if fix_success {
                                        state.fix_step = "Testing syntax & reloading services...".into();
                                        state.tick_spinner();
                                        terminal.draw(|f| ui::draw_ui(f, &state))?;

                                        let fpm_unit = fpm_service_name
                                            .as_deref()
                                            .unwrap_or("php-fpm");

                                        if let Err(e) = Remediator::restart_services(&client, fpm_unit) {
                                            error_msg = format!("Failed to restart services: {}", e);
                                            fix_success = false;
                                        }
                                    }

                                    // Step 6: Post-audit
                                    if fix_success {
                                        state.fix_step = "Running post-flight verification...".into();
                                        state.tick_spinner();
                                        terminal.draw(|f| ui::draw_ui(f, &state))?;

                                        if let Ok(new_rep) = auditor::run_audit(&server.name, &server.host, &client) {
                                            state.reports[state.selected_server_index] = new_rep;
                                        }
                                        state.status_message = "All fixes applied & verified successfully!".into();
                                    } else {
                                        state.status_message = error_msg;
                                    }
                                }
                                Err(e) => {
                                    state.status_message = format!("SSH connection failed: {}", e);
                                }
                            }

                            state.mode = AppMode::ViewingAudit;
                        }
                        KeyCode::Char('n') | KeyCode::Esc => {
                            state.mode = AppMode::ViewingAudit;
                            state.status_message = "Operation canceled by user.".into();
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
    }

    // Clean terminal exit
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

fn init_configuration() -> Result<()> {
    let servers_path = std::path::Path::new("servers.toml");
    if servers_path.exists() {
        println!("ℹ️  'servers.toml' already exists in the current directory.");
    } else {
        let template = r#"# Droplets / servers configuration for security audit and remediation

[defaults]
ssh_port = 22
user = "root"
# identity_file = "~/.ssh/id_ed25519" # Optional

[[servers]]
name = "prod-app-01"
host = "192.168.1.10"
user = "root"
port = 22
"#;
        std::fs::write(servers_path, template)?;
        println!("✔ Created default 'servers.toml'.");
    }

    // Check .gitignore
    let gitignore_path = std::path::Path::new(".gitignore");
    if gitignore_path.exists() {
        let content = std::fs::read_to_string(gitignore_path)?;
        let lines: Vec<&str> = content.lines().collect();
        let already_ignored = lines.iter().any(|line| line.trim() == "servers.toml");

        if !already_ignored {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(gitignore_path)?;
            if !content.ends_with('\n') && !content.is_empty() {
                writeln!(file)?;
            }
            writeln!(file, "servers.toml")?;
            println!("✔ Added 'servers.toml' to .gitignore.");
        } else {
            println!("ℹ️  'servers.toml' is already in .gitignore.");
        }
    } else {
        std::fs::write(gitignore_path, "/target\nservers.toml\n")?;
        println!("✔ Created .gitignore with 'servers.toml' included.");
    }

    println!("\n🚀 Initialization complete! Edit 'servers.toml' with your droplet IPs and run 'php-sec'.");
    Ok(())
}

fn audit_all_servers(cfg: &AppConfig, passphrase: Option<&str>) -> Result<Vec<auditor::AuditReport>> {
    let mut reports = Vec::new();

    for srv in &cfg.servers {
        let identity_path = srv.resolved_identity_file(cfg.defaults.as_ref());
        let user = srv.resolved_user(cfg.defaults.as_ref());
        let port = srv.resolved_port(cfg.defaults.as_ref());

        match RemoteClient::connect(&srv.host, port, &user, identity_path.as_deref(), passphrase) {
            Ok(client) => match auditor::run_audit(&srv.name, &srv.host, &client) {
                Ok(rep) => reports.push(rep),
                Err(e) => {
                    eprintln!("Error auditing {}: {}", srv.name, e);
                    reports.push(auditor::AuditReport::disconnected(&srv.name, &srv.host, e.to_string()));
                }
            },
            Err(e) => {
                eprintln!("Failed to connect to {} ({}): {}", srv.name, srv.host, e);
                reports.push(auditor::AuditReport::disconnected(&srv.name, &srv.host, e.to_string()));
            }
        }
    }

    Ok(reports)
}
