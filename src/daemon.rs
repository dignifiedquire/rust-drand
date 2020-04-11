use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use async_std::prelude::*;
use async_std::{
    sync::{channel, Receiver, Sender},
    task,
};
use futures::StreamExt;
use libp2p::Multiaddr;
use log::{error, info};

use crate::control;
use crate::key::{self, Group, Pair, Store};
use crate::swarm::{DkgProtocolMessage, Node, NodeAction, NodeEvent};

#[derive(Debug)]
pub struct Config {
    addrs: Vec<Multiaddr>,
    config_folder: PathBuf,
    control_port: usize,
}

impl Config {
    pub fn new(addrs: Vec<Multiaddr>, config_folder: PathBuf, control_port: usize) -> Self {
        Self {
            addrs,
            config_folder,
            control_port,
        }
    }
}

#[derive(Debug)]
pub struct Daemon {
    /// Configuration for the daemon.
    config: Config,
    /// The local key pair.
    local_key_pair: Pair,
}

impl Daemon {
    /// Construct a new daemon.
    pub fn new(config: Config) -> Result<Self> {
        let store = key::FileStore::new(&config.config_folder)?;
        let local_key_pair = store.load_key_pair()?;

        Ok(Self {
            config,
            local_key_pair,
        })
    }

    fn create_node(
        &self,
        receiver: Receiver<NodeAction>,
        sender: Sender<NodeEvent>,
    ) -> Result<Node> {
        Node::new(
            self.local_key_pair.private_swarm(),
            self.local_key_pair.public().peer_id(),
            self.local_key_pair.public().address().clone(),
            receiver,
            sender,
        )
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("daemon starting");

        let (control_sender, control_receiver) = channel(100);
        let (shutdown_control_sender, shutdown_control_receiver) = channel(1);
        let control_addr = format!("127.0.0.1:{}", self.config.control_port);

        task::spawn(async move {
            use futures::future::FutureExt;

            let control_server = control::Server::new(control_sender);
            // TODO: configurable address

            info!("Control server listening at {}", &control_addr);
            control_server
                .listen(control_addr)
                .race(shutdown_control_receiver.recv().map(|_| Ok(())))
                .await
        });

        // Setup the libp2p node
        let (action_sender, action_receiver) = channel(10);
        let (event_sender, event_receiver) = channel(10);

        let actions = action_sender;
        let mut node = self.create_node(action_receiver, event_sender)?;

        task::spawn(async move { node.run().await });

        // Initial connect to the known peers.
        for addr in &self.config.addrs {
            actions.send(NodeAction::Dial(addr.clone())).await;
        }
        enum E {
            Swarm(NodeEvent),
            Daemon(DaemonAction),
        }

        let mut cr = control_receiver.map(E::Daemon);
        let mut ar = event_receiver.map(E::Swarm);

        while let Some(action) = cr.next().race(ar.next()).await {
            match action {
                E::Daemon(DaemonAction::Stop) => {
                    actions.send(NodeAction::Stop).await;
                    shutdown_control_sender.send(()).await;
                }
                E::Daemon(DaemonAction::Node(action)) => actions.send(action).await,
                E::Daemon(DaemonAction::InitDkg {
                    group_path,
                    is_leader,
                    timeout,
                }) => {
                    let res: Result<()> = {
                        // Check if group already exists
                        // TODO

                        // Read Group from source file
                        let group: Group = key::load_from_file(&group_path)?;
                        // TODO: ensure at least 5 members
                        // TODO: ensure threshold < vss.MinimumT(group.len())

                        // Extract Entropy

                        let self_index = match group.index(self.local_key_pair.public()) {
                            Some(i) => i,
                            None => {
                                bail!("self, not in group: abort");
                            }
                        };
                        // Start DKG if is_leader
                        if is_leader {
                            actions
                                .send(NodeAction::SendDkg(DkgProtocolMessage::Start))
                                .await;
                        }

                        // otherwise wait for dkg response
                        Ok(())
                    };
                    if let Err(err) = res {
                        error!("init-dkg failed: {}", err);
                    }
                }
                E::Swarm(NodeEvent::ReceiveDkg(msg)) => {
                    info!("got dkg message: {:?}", msg);
                    match msg {
                        DkgProtocolMessage::Start => {
                            // TODO: setup board and run dkg
                        }
                        DkgProtocolMessage::Message(msg) => {
                            // TODO: send message to the board
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

pub async fn stop(control_port: usize) -> Result<()> {
    let addr = format!("http://127.0.0.1:{}/", control_port);
    let client = control::Client::new(addr);
    client.stop().await
}

pub async fn ping(control_port: usize) -> Result<()> {
    let addr = format!("http://127.0.0.1:{}/", control_port);
    let client = control::Client::new(addr);
    client.ping().await
}

pub async fn init_dkg(
    group_path: &PathBuf,
    is_leader: bool,
    timeout: Duration,
    control_port: usize,
) -> Result<()> {
    let addr = format!("http://127.0.0.1:{}/", control_port);
    let client = control::Client::new(addr);

    // TODO: Pass optional entropy source info

    client.init_dkg(group_path, is_leader, timeout).await
}

/// Action to be executed on the daemon in general, sent from the control.
pub enum DaemonAction {
    Stop,
    Node(NodeAction),
    InitDkg {
        group_path: PathBuf,
        is_leader: bool,
        timeout: Duration,
    },
}
