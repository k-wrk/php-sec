use anyhow::{anyhow, Context, Result};
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

pub struct RemoteClient {
    session: Session,
}

impl RemoteClient {
    pub fn connect(
        host: &str,
        port: u16,
        user: &str,
        identity_file: Option<&Path>,
        passphrase: Option<&str>,
    ) -> Result<Self> {
        let addr = format!("{}:{}", host, port);
        let tcp = TcpStream::connect_timeout(
            &addr
                .parse()
                .or_else(|_| {
                    use std::net::ToSocketAddrs;
                    addr.to_socket_addrs()?.next().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::NotFound, "Host address not resolved")
                    })
                })
                .context(format!("Could not resolve address: {}", addr))?,
            Duration::from_secs(10),
        )?;

        let mut session = Session::new()?;
        session.set_tcp_stream(tcp);
        session.handshake()?;

        let mut authenticated = false;

        // 1. Try SSH Agent first
        if let Ok(mut agent) = session.agent() {
            if agent.connect().is_ok() && agent.list_identities().is_ok() {
                for identity in agent.identities().unwrap_or_default() {
                    if agent.userauth(user, &identity).is_ok() {
                        authenticated = true;
                        break;
                    }
                }
            }
        }

        // 2. Try specified identity file (with optional passphrase)
        if !authenticated {
            if let Some(key_path) = identity_file {
                if key_path.exists() {
                    if session
                        .userauth_pubkey_file(user, None, key_path, passphrase)
                        .is_ok()
                    {
                        authenticated = true;
                    }
                }
            }
        }

        // 3. Try standard SSH keys with the provided passphrase
        if !authenticated {
            if let Some(home) = dirs::home_dir() {
                let candidates = [
                    home.join(".ssh/id_ed25519"),
                    home.join(".ssh/id_rsa"),
                ];
                for cand in candidates {
                    if cand.exists() {
                        if session.userauth_pubkey_file(user, None, &cand, passphrase).is_ok() {
                            authenticated = true;
                            break;
                        }
                    }
                }
            }
        }

        if !authenticated {
            return Err(anyhow!(
                "Failed to authenticate on host {} as user {}. Please verify ssh-agent, SSH keys or passphrase.",
                host,
                user
            ));
        }

        Ok(Self { session })
    }

    pub fn execute(&self, command: &str) -> Result<(i32, String, String)> {
        let mut channel = self.session.channel_session()?;
        channel.exec(command)?;

        let mut stdout = String::new();
        let mut stderr = String::new();

        channel.read_to_string(&mut stdout)?;
        channel.stderr().read_to_string(&mut stderr)?;

        channel.wait_close()?;
        let exit_code = channel.exit_status()?;

        Ok((exit_code, stdout, stderr))
    }
}
