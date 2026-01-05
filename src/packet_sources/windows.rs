use std::iter;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use windows::core::w;
use windows::core::PCWSTR;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL};

use crate::intercept_conf::InterceptConf;
use crate::messages::{TransportCommand, TransportEvent};
use crate::network::add_network_layer;
use crate::packet_sources::{forward_packets, PacketSourceConf, PacketSourceTask, IPC_BUF_SIZE};
use crate::shutdown;

// Try to spawn the redirector process (with elevated privileges)
// Failure is ignored here, but it will be detected and handled later when trying to connect to the pipe
fn start_redirector(executable_path: &[u16], pipe_name: &[u16]) {
    unsafe {
        ShellExecuteW(
            None,
            w!("runas"),
            PCWSTR::from_raw(executable_path.as_ptr()),
            PCWSTR::from_raw(pipe_name.as_ptr()),
            None,
            if cfg!(debug_assertions) {
                SW_SHOWNORMAL
            } else {
                SW_HIDE
            },
        )
    };
}

pub struct WindowsConf {
    pub executable_path: PathBuf,
    pub max_reconnect_attempts: Option<u32>,
}

impl PacketSourceConf for WindowsConf {
    type Task = WindowsTask;
    type Data = UnboundedSender<InterceptConf>;

    fn name(&self) -> &'static str {
        "Windows proxy"
    }

    async fn build(
        self,
        transport_events_tx: Sender<TransportEvent>,
        transport_commands_rx: UnboundedReceiver<TransportCommand>,
        shutdown: shutdown::Receiver,
    ) -> Result<(Self::Task, Self::Data)> {
        let pipe_name = format!(
            r"\\.\pipe\mitmproxy-transparent-proxy-{}",
            std::process::id()
        );

        let pipe_name_str = pipe_name.clone();

        let pipe_name = pipe_name
            .encode_utf16()
            .chain(iter::once(0))
            .collect::<Vec<u16>>();

        let executable_path = self
            .executable_path
            .as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect::<Vec<u16>>();

        let (conf_tx, conf_rx) = unbounded_channel();

        Ok((
            WindowsTask {
                executable_path,
                pipe_name,
                pipe_name_str,
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

pub struct WindowsTask {
    executable_path: Vec<u16>,
    pipe_name: Vec<u16>,
    pipe_name_str: String,
    transport_events_tx: Sender<TransportEvent>,
    transport_commands_rx: UnboundedReceiver<TransportCommand>,
    conf_rx: UnboundedReceiver<InterceptConf>,
    shutdown: shutdown::Receiver,
    max_reconnect_attempts: Option<u32>,
}

impl PacketSourceTask for WindowsTask {
    async fn run(mut self) -> Result<()> {
        use std::time::Duration;

        // Create network layer once, before the reconnection loop
        let (task_handle, tx, rx) = add_network_layer(
            self.transport_events_tx,
            self.transport_commands_rx,
            self.shutdown.clone(),
        );
        let mut network_layer = crate::packet_sources::NetworkLayer {
            task_handle,
            tx,
            rx,
        };

        let mut delay = Duration::from_secs(1);
        let mut attempts = 0u32;
        let mut current_conf = InterceptConf::disabled();

        loop {
            if self.shutdown.is_shutting_down() {
                log::info!("Windows redirector shutting down");
                break;
            }

            // Spawn the redirector process
            log::debug!("Starting redirector: {} {}", 
                String::from_utf16_lossy(&self.executable_path).trim_end_matches('\0'),
                String::from_utf16_lossy(&self.pipe_name).trim_end_matches('\0'));
            
            start_redirector(&self.executable_path, &self.pipe_name);

            // Create the named pipe for this connection
            let ipc_server = match ServerOptions::new()
                .pipe_mode(PipeMode::Message)
                .first_pipe_instance(attempts == 0)
                .max_instances(1)
                .in_buffer_size(IPC_BUF_SIZE as u32)
                .out_buffer_size(IPC_BUF_SIZE as u32)
                .reject_remote_clients(true)
                .create(&self.pipe_name_str)
            {
                Ok(server) => server,
                Err(e) => {
                    log::warn!("Failed to create named pipe: {}", e);

                    if let Some(max) = self.max_reconnect_attempts {
                        attempts += 1;
                        if attempts > max {
                            return Err(anyhow!(
                                "Failed to reconnect to Windows redirector after {} attempts",
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
                    continue;
                }
            };

            log::debug!("Waiting for IPC connection...");
            match ipc_server.connect().await {
                Ok(_) => {
                    log::info!("Connected to Windows redirector");
                }
                Err(e) => {
                    log::warn!("Failed to connect to named pipe: {}", e);

                    if let Some(max) = self.max_reconnect_attempts {
                        attempts += 1;
                        if attempts > max {
                            return Err(anyhow!(
                                "Failed to reconnect to Windows redirector after {} attempts",
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
                    continue;
                }
            }

            // Forward packets until disconnection. May update current_conf if new config arrives on conf_rx.
            match forward_packets(
                ipc_server,
                &mut network_layer,
                &mut self.conf_rx,
                &mut current_conf,
            )
            .await
            {
                Ok(_) => {
                    log::info!("Windows redirector exited normally");
                    break;
                }
                Err(e) => {
                    log::warn!("Redirector connection failed: {}", e);

                    if let Some(max) = self.max_reconnect_attempts {
                        attempts += 1;
                        if attempts > max {
                            return Err(anyhow!(
                                "Failed to reconnect to Windows redirector after {} attempts",
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

        Ok(())
    }
}
