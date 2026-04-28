use anyhow::{anyhow, bail, Context, Result};
use log::{debug, error, log, Level};
use std::io::Error;
use std::net::Shutdown;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::str::FromStr;
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader, ReadBuf};
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::intercept_conf::InterceptConf;
use crate::messages::{TransportCommand, TransportEvent};
use crate::network::add_network_layer;
use crate::packet_sources::{forward_packets, PacketSourceConf, PacketSourceTask};
use crate::shutdown;
use tempfile::{tempdir, TempDir};
use tokio::net::UnixDatagram;
use tokio::process::Command;
use tokio::time::timeout;

async fn start_redirector(
    executable: &Path,
    listener_addr: &Path,
    shutdown: shutdown::Receiver,
) -> Result<PathBuf> {
    debug!("Elevating privileges...");
    // Try to elevate privileges using a dummy sudo invocation.
    // The idea here is to block execution and give the user time to enter their password.
    // For now, we naively assume that all systems 1) have sudo and 2) timestamp_timeout > 0.
    let mut sudo = Command::new("sudo")
        .arg("echo")
        .arg("-n")
        .spawn()
        .context("Failed to run sudo.")?;
    sudo.stdin.take();
    if !sudo.wait().await.is_ok_and(|x| x.success()) {
        bail!("Failed to elevate privileges");
    }

    debug!("Starting mitmproxy-linux-redirector...");
    let mut redirector_process = Command::new("sudo")
        .arg("--non-interactive")
        .arg("--preserve-env")
        .arg(executable)
        .arg(listener_addr)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to launch mitmproxy-linux-redirector.")?;

    let stdout = redirector_process.stdout.take().unwrap();
    let stderr = redirector_process.stderr.take().unwrap();
    let shutdown2 = shutdown.clone();
    tokio::spawn(async move {
        let mut stderr = BufReader::new(stderr).lines();
        let mut level = Level::Error;
        while let Ok(Some(line)) = stderr.next_line().await {
            if shutdown2.is_shutting_down() {
                // We don't want to log during exit, https://github.com/vorner/pyo3-log/issues/30
                eprintln!("{}", line);
                continue;
            }

            let new_level = line
                .strip_prefix("[")
                .and_then(|s| s.split_once(" "))
                .and_then(|(level, line)| {
                    Level::from_str(level)
                        .ok()
                        .map(|l| (l, line.trim_ascii_start()))
                });
            if let Some((l, line)) = new_level {
                level = l;
                log!(level, "[{line}");
            } else {
                log!(level, "{line}");
            }
        }
    });
    tokio::spawn(async move {
        match redirector_process.wait().await {
            Ok(status) if status.success() => {
                if shutdown.is_shutting_down() {
                    // We don't want to log during exit, https://github.com/vorner/pyo3-log/issues/30
                } else {
                    debug!("[linux-redirector] exited successfully.")
                }
            }
            other => {
                if shutdown.is_shutting_down() {
                    eprintln!("[linux-redirector] exited during shutdown: {:?}", other)
                } else {
                    error!("[linux-redirector] exited: {:?}", other)
                }
            }
        }
    });

    timeout(
        Duration::from_secs(5),
        BufReader::new(stdout).lines().next_line(),
    )
    .await
    .context("failed to establish connection to Linux redirector")?
    .context("failed to read redirector stdout")?
    .map(PathBuf::from)
    .context("redirector did not produce stdout")
}

pub struct LinuxConf {
    pub executable_path: PathBuf,
    pub max_reconnect_attempts: Option<u32>,
}

// We implement AsyncRead/AsyncWrite for UnixDatagram to have a common interface
// with Windows' NamedPipeServer.
pub struct AsyncUnixDatagram(UnixDatagram);

impl AsyncRead for AsyncUnixDatagram {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.0.poll_recv(cx, buf)
    }
}
impl AsyncWrite for AsyncUnixDatagram {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, Error>> {
        self.0.poll_send(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), Error>> {
        self.0.poll_send_ready(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), Error>> {
        Poll::Ready(self.0.shutdown(Shutdown::Write))
    }
}

impl PacketSourceConf for LinuxConf {
    type Task = LinuxTask;
    type Data = UnboundedSender<InterceptConf>;

    fn name(&self) -> &'static str {
        "Linux proxy"
    }

    async fn build(
        self,
        transport_events_tx: Sender<TransportEvent>,
        transport_commands_rx: UnboundedReceiver<TransportCommand>,
        shutdown: shutdown::Receiver,
    ) -> Result<(Self::Task, Self::Data)> {
        let datagram_dir = tempdir().context("failed to create temp dir")?;

        let (conf_tx, conf_rx) = unbounded_channel();

        Ok((
            LinuxTask {
                datagram_dir,
                executable_path: self.executable_path,
                transport_events_tx,
                transport_commands_rx,
                conf_rx,
                shutdown,
                max_reconnect_attempts: self.max_reconnect_attempts,
            },
            conf_tx,
        ))
    }
}

pub struct LinuxTask {
    datagram_dir: TempDir,
    executable_path: PathBuf,
    transport_events_tx: Sender<TransportEvent>,
    transport_commands_rx: UnboundedReceiver<TransportCommand>,
    conf_rx: UnboundedReceiver<InterceptConf>,
    shutdown: shutdown::Receiver,
    max_reconnect_attempts: Option<u32>,
}

impl PacketSourceTask for LinuxTask {
    async fn run(mut self) -> Result<()> {
        use std::time::Duration;

        // Create network layer once, before reconnection loop
        let (task_handle, tx, rx) = add_network_layer(
            self.transport_events_tx,
            self.transport_commands_rx,
            self.shutdown.clone(),
        );
        let mut network = crate::packet_sources::NetworkLayer {
            task_handle,
            tx,
            rx,
        };

        let mut delay = Duration::from_secs(1);
        let mut attempts = 0u32;
        let mut current_conf = InterceptConf::disabled();

        loop {
            if self.shutdown.is_shutting_down() {
                log::info!("Linux redirector shutting down");
                break;
            }

            // Create new socket for this connection attempt
            let channel = match UnixDatagram::bind(self.datagram_dir.path().join("mitmproxy")) {
                Ok(ch) => ch,
                Err(e) => {
                    log::warn!("Failed to bind Unix datagram socket: {}", e);

                    if let Some(max) = self.max_reconnect_attempts {
                        attempts += 1;
                        if attempts > max {
                            drop(self.datagram_dir);
                            return Err(anyhow!(
                                "Failed to bind Unix datagram socket after {} attempts",
                                max
                            ));
                        }
                    }

                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(30));
                    continue;
                }
            };

            let dst = match start_redirector(
                &self.executable_path,
                self.datagram_dir.path(),
                self.shutdown.clone(),
            )
            .await
            {
                Ok(dst) => dst,
                Err(e) => {
                    log::warn!("Failed to start Linux redirector: {}", e);

                    if let Some(max) = self.max_reconnect_attempts {
                        attempts += 1;
                        if attempts > max {
                            drop(self.datagram_dir);
                            return Err(anyhow!(
                                "Failed to start Linux redirector after {} attempts",
                                max
                            ));
                        }
                    }

                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(30));
                    continue;
                }
            };

            if let Err(e) = channel
                .connect(&dst)
                .with_context(|| format!("Failed to connect to redirector at {}", dst.display()))
            {
                log::warn!("{}", e);

                if let Some(max) = self.max_reconnect_attempts {
                    attempts += 1;
                    if attempts > max {
                        drop(self.datagram_dir);
                        return Err(anyhow!(
                            "Failed to connect to Linux redirector after {} attempts",
                            max
                        ));
                    }
                }

                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(30));
                continue;
            }

            log::info!("Connected to Linux redirector");
            attempts = 0;
            delay = Duration::from_secs(1);

            // Forward packets until disconnection. May update current_conf if new config arrives on conf_rx.
            match forward_packets(
                AsyncUnixDatagram(channel),
                &mut network,
                &mut self.conf_rx,
                &mut current_conf,
            )
            .await
            {
                Ok(_) => {
                    log::info!("Linux redirector exited normally");
                    break;
                }
                Err(e) => {
                    log::warn!("Redirector disconnected: {}", e);

                    if let Some(max) = self.max_reconnect_attempts {
                        attempts += 1;
                        if attempts > max {
                            drop(self.datagram_dir);
                            return Err(anyhow!(
                                "Failed to reconnect to Linux redirector after {} attempts",
                                max
                            ));
                        }
                    }

                    log::info!(
                        "Attempting to reconnect (attempt {}, waiting {}s)...",
                        attempts + 1,
                        delay.as_secs()
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(30));
                }
            }
        }

        drop(self.datagram_dir);
        Ok(())
    }
}
