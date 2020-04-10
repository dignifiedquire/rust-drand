use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use async_std::prelude::*;
use async_std::{sync::channel, task};
use futures::StreamExt;
use libp2p::Multiaddr;
use log::{error, info};

use crate::control;
use crate::key::{self, Group, Pair, Store};
use crate::swarm::{Node, NodeAction};

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

    fn create_node(&self) -> Result<Node> {
        Node::new(
            self.local_key_pair.private_swarm(),
            self.local_key_pair.public().peer_id(),
            self.local_key_pair.public().address().clone(),
        )
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("daemon starting");

        let (control_sender, mut control_receiver) = channel(100);
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
        let mut node = self.create_node()?;
        let actions = node.action_sender();
        task::spawn(async move { node.run().await });

        // Initial connect to the known peers.
        for addr in &self.config.addrs {
            actions.send(NodeAction::Dial(addr.clone())).await;
        }

        while let Some(action) = control_receiver.next().await {
            match action {
                DaemonAction::Stop => {
                    actions.send(NodeAction::Stop).await;
                    shutdown_control_sender.send(()).await;
                }
                DaemonAction::Node(action) => actions.send(action).await,
                DaemonAction::InitDkg {
                    group_path,
                    is_leader,
                    timeout,
                } => {
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

                        // otherwise wait for dkg response
                        Ok(())
                    };
                    if let Err(err) = res {
                        error!("init-dkg failed: {}", err);
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
