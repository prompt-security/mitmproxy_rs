use crate::intercept_conf::InterceptConf;
use crate::ipc::PacketWithMeta;
use crate::messages::{
    NetworkCommand, NetworkEvent, SmolPacket, TransportCommand, TransportEvent, TunnelInfo,
};
use crate::{ipc, shutdown, MAX_PACKET_SIZE};
use anyhow::{anyhow, Context, Result};
use prost::bytes::Bytes;
use prost::Message;
use std::future::Future;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver};
use tokio::task::JoinHandle;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "linux")]
pub mod tun;
pub mod udp;
#[cfg(windows)]
pub mod windows;
pub mod wireguard;

pub trait PacketSourceConf {
    type Task: PacketSourceTask + Send + 'static;
    type Data: Send + 'static;

    fn name(&self) -> &'static str;

    fn build(
        self,
        transport_events_tx: mpsc::Sender<TransportEvent>,
        transport_commands_rx: mpsc::UnboundedReceiver<TransportCommand>,
        shutdown: shutdown::Receiver,
    ) -> impl Future<Output = Result<(Self::Task, Self::Data)>> + Send;
}

pub trait PacketSourceTask: Send {
    fn run(self) -> impl Future<Output = Result<()>> + Send;
}

pub const IPC_BUF_SIZE: usize = MAX_PACKET_SIZE + 1024;

pub struct NetworkLayer {
    pub task_handle: JoinHandle<Result<()>>,
    pub tx: Sender<NetworkEvent>,
    pub rx: Receiver<NetworkCommand>,
}

/// Feed packets from a socket into smol, and the other way around.
///
/// Returns an error when a disconnection is detected (empty read) or any I/O error occurs,
/// allowing the caller to handle it (e.g., by attempting reconnection).
#[allow(dead_code)]
async fn forward_packets<T: AsyncRead + AsyncWrite + Unpin>(
    mut channel: T,
    network: &mut NetworkLayer,
    conf_rx: &mut UnboundedReceiver<InterceptConf>,
) -> Result<()> {
    let mut buf = Vec::with_capacity(IPC_BUF_SIZE);

    // Send initial InterceptConf immediately after connection.
    // Without this, we have a deadlock: redirector waits for config, mitmproxy waits for packets.
    // The redirector won't send packets until it gets a non-disabled config.
    let initial_conf = InterceptConf::disabled();
    let msg = ipc::FromProxy {
        message: Some(ipc::from_proxy::Message::InterceptConf(initial_conf.into())),
    };
    msg.encode(&mut buf)?;
    channel.write_all(&buf).await.context("failed to send initial configuration")?;

    loop {
        buf.clear();
        tokio::select! {
            // Monitor the network task for errors or planned shutdown.
            // This way we implicitly monitor the shutdown channel.
            exit = &mut network.task_handle => break exit.context("network task panic")?.context("network task error")?,
            // pipe through changes to the intercept list
            Some(conf) = conf_rx.recv() => {
                let msg = ipc::FromProxy {
                    message: Some(ipc::from_proxy::Message::InterceptConf(conf.into())),
                };
                msg.encode(&mut buf)?;
                channel.write_all(&buf).await.context("failed to propagate interception config update")?;
            },
            // read packets from the IPC pipe into our network stack.
            _ = channel.read_buf(&mut buf) => {
                if buf.is_empty() {
                    // https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-client
                    // Because the client is reading from the pipe in message-read mode, it is
                    // possible for the ReadFile operation to return zero after reading a partial
                    // message. This happens when the message is larger than the read buffer.
                    //
                    // We don't support messages larger than the buffer, so this cannot happen.
                    // Instead, empty reads indicate that the IPC client has disconnected.
                    return Err(anyhow!("redirect daemon exited prematurely."));
                }

                let Ok(PacketWithMeta { data, tunnel_info}) = PacketWithMeta::decode(buf.as_slice()) else {
                    return Err(anyhow!("Received invalid IPC message from redirector: {:?}", &buf));
                };

                // TODO: Use Bytes in SmolPacket to avoid copy
                let data = data.to_vec();

                let Ok(mut packet) = SmolPacket::try_from(data) else {
                    log::error!("Skipping invalid packet: {:?}", &buf);
                    continue;
                };

                // debug!("Receiving packet: {:?}", &packet);

                // WinDivert packets do not have correct IP checksums yet, we need fix that here
                // otherwise smoltcp will be unhappy with us.
                packet.fill_ip_checksum();

                let event = NetworkEvent::ReceivePacket {
                    packet,
                    tunnel_info: TunnelInfo::LocalRedirector {
                        pid: tunnel_info.as_ref().and_then(|t| t.pid),
                        process_name: tunnel_info.and_then(|t| t.process_name),
                        remote_endpoint: None,
                    },
                };
                if network.tx.try_send(event).is_err() {
                    log::warn!("Dropping incoming packet, TCP channel is full.")
                };
            },
            // write packets from the network stack to the IPC pipe to be reinjected.
            Some(e) = network.rx.recv() => {
                match e {
                    NetworkCommand::SendPacket(packet) => {
                        let packet = ipc::FromProxy { message: Some(ipc::from_proxy::Message::Packet( ipc::Packet { data: Bytes::from(packet.into_inner()) }))};
                        packet.encode(&mut buf)?;
                        // debug!("Sending packet: {} {:?}", buf.len(), &packet.message.as_ref().unwrap());
                        channel.write_all(&buf).await.context("failed to send packet")?;
                    }
                }
            }
        }
    }
    log::info!("Redirector shutting down.");
    Ok(())
}
