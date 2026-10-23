# PHP Security & Hardening Tool

Interactive CLI tool in **Rust** built with **Ratatui** and **SSH2** to audit PHP/PHP-FPM and Nginx security across remote Linux servers / VPS (DigitalOcean, AWS, Hetzner, Linode, private servers, or any Linux VPS accessible via SSH), allowing on-demand package upgrades and security hardening with syntax validation and automatic rollback.

---

## Features

1. **Interactive TUI Dashboard (Ratatui)**:
   - Visual list of servers with compliance indicators (`● OK` / `▲ RISK` / `✖ OFFLINE`).
   - Detailed audit table (PHP security patch version, `expose_php`, `display_errors`, `server_tokens`, etc.).
   - Interactive modal confirmation before executing modifications.
2. **Safe Package Upgrades**:
   - Upgrades only PHP ecosystem packages (`apt-get --only-upgrade install -y php*-fpm php*-cli php*-common`), avoiding unintended full-system upgrades.
3. **Non-destructive Hardening**:
   - Injects `/etc/php/<version>/fpm/conf.d/99-security-hardening.ini` and `/etc/php/<version>/cli/conf.d/99-security-hardening.ini` to enforce secure runtime directives without modifying stock configuration files.
   - Enforces `server_tokens off;` in Nginx after taking a timestamped backup.
4. **Failure Prevention & Automatic Rollback**:
   - Executes `nginx -t` and `php-fpm -t`.
   - If any syntax error occurs, immediate rollback is triggered and service reloads are aborted.
5. **Headless / Quick Mode (`--cli`)**:
   - Inspects servers directly on stdout without opening the full-screen TUI.

---

## Getting Started

### 1. Initialize Configuration

Run `--init` to generate a fresh `servers.toml` template and automatically add it to `.gitignore`:

```bash
cargo run -- --init
```

Edit `servers.toml` with your servers' IP addresses, user, and SSH details:

```toml
[defaults]
ssh_port = 22
user = "root"
# identity_file = "~/.ssh/id_ed25519" # Optional: uses default ~/.ssh keys if omitted

[[servers]]
name = "prod-app-01"
host = "192.168.1.10"

[[servers]]
name = "prod-app-02"
host = "192.168.1.11"
```

### 2. Run the Interactive Dashboard (TUI)

```bash
cargo run -- --config servers.toml
```

> **Note on Passphrase-Protected SSH Keys**:
> If your SSH private key is encrypted with a passphrase, you have two options:
> 1. **Option A (Interactive Prompt)**: Run `cargo run`. The CLI will automatically prompt for your passphrase masked in the terminal:
>    ```bash
>    🔑 SSH Key Passphrase (press Enter if no passphrase):
>    Enter passphrase: ****
>    ```
>    You can also force prompting with `cargo run -- --ask-pass`.
> 2. **Option B (SSH Agent)**: Add your key to your SSH agent once:
>    ```bash
>    ssh-add --apple-use-keychain ~/.ssh/id_ed25519 # or ~/.ssh/id_rsa
>    ```
>    The tool will then automatically authenticate without asking for the passphrase again.

#### Dashboard Keybindings:
- `↑` / `↓` or `j` / `k`: Navigate between servers.
- `F`: Open confirmation modal to **Fix/Upgrade** the selected server.
  - `Y` or `Enter`: Confirm and execute.
  - `N` or `Esc`: Cancel.
- `R`: Re-audit all servers and refresh dashboard.
- `Q` or `Esc`: Quit the application.

### 3. Command Line Mode (No TUI)

To quickly view the audit table in plain terminal text:
```bash
cargo run -- --cli
```

---

## Homebrew Installation (via Tappub)

This package is managed and published using [tappub](https://github.com/k-wrk/tappub) to `k-wrk/homebrew-tap`:

```bash
brew tap k-wrk/tap
brew install php-sec
```

---

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE) (SPDX: `PolyForm-Noncommercial-1.0.0`).
