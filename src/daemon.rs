use std::convert::TryInto;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use async_std::prelude::*;
use async_std::{
    sync::{channel, Arc, Mutex, Receiver, RwLock, Sender},
    task,
};
use futures::StreamExt;
use libp2p::{Multiaddr, PeerId};
use log::{error, info, warn};

use crate::control;
use crate::dkg;
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
    /// Local file store.
    store: key::FileStore,
}

impl Daemon {
    /// Construct a new daemon.
    pub fn new(config: Config) -> Result<Self> {
        let store = key::FileStore::new(&config.config_folder)?;
        let local_key_pair = store.load_key_pair()?;

        Ok(Self {
            config,
            local_key_pair,
            store,
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

        let store = self.store.clone();

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
            info!("connecting to {:?}", addr);
            actions.send(NodeAction::Dial(addr.clone())).await;
        }
        enum E {
            Swarm(NodeEvent),
            Daemon(DaemonAction),
        }

        let mut cr = control_receiver.map(E::Daemon);
        let mut ar = event_receiver.map(E::Swarm);

        let board = Arc::new(Mutex::new(None));
        let sender = Arc::new(RwLock::new(None));
        let dkg_is_running = Arc::new(RwLock::new(false));

        let (dkg_done_sender, mut dkg_done_receiver): (
            Sender<(Result<dkg::Node<_>>, Group)>,
            Receiver<(Result<dkg::Node<_>>, Group)>,
        ) = channel(1);

        let save_dkg_result = |res_node, mut group: Group, store: &key::FileStore| -> Result<()> {
            let node: dkg::Node<dkg::node::Done> = res_node?;
            store.save_share(node.share()?)?;
            let dp = node.dist_public()?;
            store.save_dist_public(&dp)?;
            group.set_public_key(dp);

            store.save_group(&group)?;

            Ok(())
        };

        let dkg1 = dkg_is_running.clone();
        task::spawn(async move {
            while let Some((res_node, group)) = dkg_done_receiver.next().await {
                let res = save_dkg_result(res_node, group, &store);
                *dkg1.write().await = false;
                if let Err(err) = res {
                    error!("{:?}", err);
                }
            }
        });

        let local_key_pair = &self.local_key_pair;

        let init_dkg = |board: Arc<Mutex<Option<_>>>,
                        sender: Arc<RwLock<Option<_>>>,
                        dkg_is_running: Arc<RwLock<bool>>,
                        dkg_done_sender: Sender<_>,
                        group_path,
                        timeout,
                        is_leader,
                        actions: Sender<_>| async move {
            if board.lock().await.is_some() {
                bail!("dkg already in progress");
            }
            // Check if group already exists
            // TODO

            let (group, b, node, s, mut receiver) =
                setup_board(local_key_pair, actions.clone(), group_path, timeout).await?;
            let b = b.start();
            *sender.write().await = Some(s);

            let actions1 = actions.clone();
            task::spawn(async move {
                let actions = actions1;
                // Forward messages from the board to the network
                while let Some((_peer, msg)) = receiver.next().await {
                    info!("sending message: {:?}", &msg);
                    actions
                        .send(NodeAction::SendDkg(DkgProtocolMessage::Message(msg)))
                        .await;
                }
            });

            // Start DKG if is_leader
            if is_leader {
                *dkg_is_running.write().await = true;
                let dkg_done_sender = dkg_done_sender.clone();
                task::spawn(async move {
                    let node = b.run_dkg(node).await;
                    dkg_done_sender.send((node, group)).await;
                });

                actions
                    .send(NodeAction::SendDkg(DkgProtocolMessage::Start))
                    .await;
            } else {
                *board.lock().await = Some((b, group, node));
            }

            // otherwise wait for dkg response
            Ok(())
        };

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
                    info!("Init DKG (leader: {})", is_leader);
                    let res = init_dkg(
                        board.clone(),
                        sender.clone(),
                        dkg_is_running.clone(),
                        dkg_done_sender.clone(),
                        group_path,
                        timeout,
                        is_leader,
                        actions.clone(),
                    )
                    .await;
                    if let Err(err) = res {
                        error!("init-dkg failed: {}", err);
                    }
                }
                E::Swarm(NodeEvent::ReceiveDkg(peer, msg)) => {
                    info!("got dkg message: {:?}", msg);
                    match msg {
                        DkgProtocolMessage::Start => {
                            if *dkg_is_running.read().await {
                                error!("cannot start dkg, already running");
                                continue;
                            }

                            if let Some((board, group, node)) = board.lock().await.take() {
                                *dkg_is_running.write().await = true;
                                let dkg_done_sender = dkg_done_sender.clone();
                                task::spawn(async move {
                                    let node = board.run_dkg(node).await;
                                    dkg_done_sender.send((node, group)).await;
                                });
                            } else {
                                error!("cannot start dkg, needs dkg-init");
                            }
                        }
                        DkgProtocolMessage::Message(msg) => {
                            if let Some(ref sender) = &*sender.read().await {
                                sender.send((peer, msg)).await;
                            } else {
                                warn!("incoming dkg message, but no dkg setup: {:?}", msg);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

async fn setup_board(
    local_key_pair: &Pair,
    actions: Sender<NodeAction>,
    group_path: PathBuf,
    timeout: Duration,
) -> Result<(
    Group,
    dkg::Board<dkg::board::Start>,
    dkg::Node<dkg::node::Start>,
    Sender<(PeerId, dkg::ProtocolMessage)>,
    Receiver<(PeerId, dkg::ProtocolMessage)>,
)> {
    // Read Group from source file
    let group: Group = key::load_from_file(&group_path)?;
    // TODO: ensure at least 5 members
    // TODO: ensure threshold < vss.MinimumT(group.len())

    // Extract Entropy

    let self_index = match group.index(local_key_pair.public()) {
        Some(i) => i,
        None => {
            bail!("self, not in group: abort");
        }
    };

    // Initial connect to the group peers.
    for node in group.identities() {
        info!("connecting to {:?}", node.address());
        actions.send(NodeAction::Dial(node.address().clone())).await;
    }

    let (to_board_send, to_board_recv) = channel(3 * group.len());
    let (from_board_send, from_board_recv) = channel(3 * group.len());
    let dkg_group: dkg::Group = group.clone().try_into()?;

    let kp = local_key_pair;
    let node = dkg::Node::new(
        self_index,
        kp.private().clone().into(),
        kp.public().public_key().clone().into(),
        kp.public().peer_id().clone(),
        dkg_group.clone(),
    )?;

    Ok((
        group,
        dkg::Board::new(dkg_group, from_board_send, to_board_recv, timeout),
        node,
        to_board_send,
        from_board_recv,
    ))
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
