use crate::ssh::RemoteClient;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub server_name: String,
    pub host: String,
    pub os_info: String,
    pub php_installed: bool,
    pub php_version: String,
    pub fpm_service: Option<String>,
    pub fpm_active: bool,
    pub nginx_active: bool,
    pub checks: Vec<SecurityCheck>,
    pub connection_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCheck {
    pub category: String, // "PHP Version", "php.ini", "Nginx"
    pub item: String,
    pub current_value: String,
    pub expected_value: String,
    pub is_secure: bool,
    pub recommendation: String,
}

pub fn run_audit(server_name: &str, host: &str, client: &RemoteClient) -> Result<AuditReport> {
    // 1. Detect OS
    let (_, os_out, _) = client.execute("grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '\"'")?;
    let os_info = os_out.trim().to_string();

    // 2. Detect PHP version
    let (code_php, php_v_out, _) = client.execute("php -r 'echo PHP_VERSION;' 2>/dev/null")?;
    let php_installed = code_php == 0 && !php_v_out.trim().is_empty();
    let php_version = if php_installed { php_v_out.trim().to_string() } else { "Not installed".to_string() };

    // 3. Detect PHP-FPM service (actively running or enabled)
    let (_, fpm_srv_out, _) = client.execute("systemctl list-units 'php*-fpm.service' --state=active --no-legend 2>/dev/null | awk '{print $1}' | head -n 1")?;
    let mut fpm_service = if !fpm_srv_out.trim().is_empty() {
        Some(fpm_srv_out.trim().to_string())
    } else {
        None
    };

    // If no active service found, check for non-masked unit file
    if fpm_service.is_none() {
        let (_, fpm_unit_out, _) = client.execute("systemctl list-unit-files 'php*-fpm.service' --no-legend 2>/dev/null | grep -v 'masked' | awk '{print $1}' | head -n 1")?;
        if !fpm_unit_out.trim().is_empty() {
            fpm_service = Some(fpm_unit_out.trim().to_string());
        }
    }

    // Fallback: check generic php-fpm
    if fpm_service.is_none() {
        let (fpm_code, _, _) = client.execute("systemctl status php-fpm >/dev/null 2>&1")?;
        if fpm_code == 0 {
            fpm_service = Some("php-fpm.service".to_string());
        }
    }

    let fpm_active = if let Some(ref srv) = fpm_service {
        let (code, _, _) = client.execute(&format!("systemctl is-active --quiet {}", srv))?;
        code == 0
    } else {
        false
    };

    // 4. Detect Nginx
    let (nginx_code, _, _) = client.execute("systemctl is-active --quiet nginx")?;
    let nginx_active = nginx_code == 0;

    let mut checks = Vec::new();

    // PHP Version Audit (PHP 8.1 >= 8.1.31, 8.2 >= 8.2.26, 8.3 >= 8.3.14, 8.4 >= 8.4.1)
    if php_installed {
        let is_php_updated = is_version_safe(&php_version);
        checks.push(SecurityCheck {
            category: "PHP Version".into(),
            item: "PHP Security Patch".into(),
            current_value: php_version.clone(),
            expected_value: "Security patched version".into(),
            is_secure: is_php_updated,
            recommendation: "Run 'apt-get --only-upgrade install php*-fpm php*-cli'".into(),
        });

        // 5. Audit php.ini directives: check FPM ini if present, otherwise CLI
        let php_major_minor = php_version.split('.').take(2).collect::<Vec<&str>>().join(".");
        let fpm_ini_opt = format!("-c /etc/php/{}/fpm/php.ini", php_major_minor);

        let ini_audits = [
            ("expose_php", "0", "Off", "Disables HTTP X-Powered-By header"),
            ("display_errors", "0", "Off", "Hides error details from visitors"),
            ("display_startup_errors", "0", "Off", "Hides startup errors"),
            ("allow_url_include", "0", "Off", "Blocks Remote File Inclusion (RFI)"),
            ("session.cookie_httponly", "1", "On", "Protects session cookies against XSS"),
        ];

        for (directive, expected_raw, expected_display, rec) in ini_audits {
            // Check with FPM ini path first, fallback to standard php command
            let cmd = format!(
                "php {} -r 'echo (int)ini_get(\"{}\");' 2>/dev/null || php -r 'echo (int)ini_get(\"{}\");' 2>/dev/null",
                fpm_ini_opt, directive, directive
            );
            let (_, val_out, _) = client.execute(&cmd)?;
            let current_raw = val_out.trim();
            let is_sec = current_raw == expected_raw;
            checks.push(SecurityCheck {
                category: "php.ini".into(),
                item: directive.into(),
                current_value: if current_raw == "1" { "On".into() } else { "Off".into() },
                expected_value: expected_display.into(),
                is_secure: is_sec,
                recommendation: rec.into(),
            });
        }
    }

    // 6. Audit Nginx (server_tokens off)
    if nginx_active {
        let (tokens_code, tokens_out, _) = client.execute("nginx -T 2>/dev/null | grep -E 'server_tokens\\s+off;'")?;
        let tokens_secure = tokens_code == 0 && !tokens_out.trim().is_empty();
        checks.push(SecurityCheck {
            category: "Nginx".into(),
            item: "server_tokens".into(),
            current_value: if tokens_secure { "off".into() } else { "on (or default)".into() },
            expected_value: "off".into(),
            is_secure: tokens_secure,
            recommendation: "Add 'server_tokens off;' to /etc/nginx/nginx.conf".into(),
        });
    }

    Ok(AuditReport {
        server_name: server_name.to_string(),
        host: host.to_string(),
        os_info,
        php_installed,
        php_version,
        fpm_service,
        fpm_active,
        nginx_active,
        checks,
        connection_error: None,
    })
}

impl AuditReport {
    pub fn disconnected(server_name: &str, host: &str, error: String) -> Self {
        Self {
            server_name: server_name.to_string(),
            host: host.to_string(),
            os_info: "Unknown / Unreachable".to_string(),
            php_installed: false,
            php_version: "N/A".to_string(),
            fpm_service: None,
            fpm_active: false,
            nginx_active: false,
            checks: vec![SecurityCheck {
                category: "Connection".into(),
                item: "SSH Reachability".into(),
                current_value: "Offline / Auth Failed".into(),
                expected_value: "Connected".into(),
                is_secure: false,
                recommendation: format!("Check SSH credentials, firewall or IP: {}", error),
            }],
            connection_error: Some(error),
        }
    }
}

fn is_version_safe(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() < 3 {
        return false;
    }
    let major: u32 = parts[0].parse().unwrap_or(0);
    let minor: u32 = parts[1].parse().unwrap_or(0);
    let patch_str = parts[2].chars().take_while(|c| c.is_ascii_digit()).collect::<String>();
    let patch: u32 = patch_str.parse().unwrap_or(0);

    match (major, minor) {
        (8, 1) => patch >= 31,
        (8, 2) => patch >= 26,
        (8, 3) => patch >= 14,
        (8, 4) => patch >= 1,
        (m, _) if m > 8 => true,
        _ => false,
    }
}
