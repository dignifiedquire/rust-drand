use std::path::PathBuf;

use anyhow::Result;
use async_std::prelude::*;
use async_std::{sync::channel, task};
use futures::StreamExt;
use libp2p::Multiaddr;
use log::info;

use crate::control;
use crate::key::{self, Store};
use crate::swarm::{Node, NodeAction};

pub fn start(addrs: Vec<Multiaddr>, config_folder: &PathBuf, control_port: usize) -> Result<()> {
    info!("daemon starting");

    let store = key::FileStore::new(config_folder)?;
    let local_key_pair = store.load_key_pair()?;

    task::block_on(async move {
        let (control_sender, mut control_receiver) = channel(100);
        let (shutdown_control_sender, shutdown_control_receiver) = channel(1);

        task::spawn(async move {
            use futures::future::FutureExt;

            let control_server = control::Server::new(control_sender);
            // TODO: configurable address
            let addr = format!("127.0.0.1:{}", control_port);
            info!("Control server listening at {}", &addr);
            control_server
                .listen(addr)
                .race(shutdown_control_receiver.recv().map(|_| Ok(())))
                .await
        });

        let mut node = Node::new(
            local_key_pair.private_swarm(),
            local_key_pair.public().peer_id(),
            local_key_pair.public().address().clone(),
        )?;
        let actions = node.action_sender();
        task::spawn(async move { node.run().await });

        for addr in addrs {
            actions.send(NodeAction::Dial(addr)).await;
        }

        while let Some(action) = control_receiver.next().await {
            match action {
                DaemonAction::Stop => {
                    actions.send(NodeAction::Stop).await;
                    shutdown_control_sender.send(()).await;
                }
                DaemonAction::Node(_action) => todo!(),
            }
        }

        Ok(())
    })
}

pub fn stop(control_port: usize) -> Result<()> {
    let addr = format!("http://127.0.0.1:{}/", control_port);
    let client = control::Client::new(addr);
    task::block_on(async move { client.stop().await })
}

pub fn ping(control_port: usize) -> Result<()> {
    let addr = format!("http://127.0.0.1:{}/", control_port);
    let client = control::Client::new(addr);
    task::block_on(async move { client.ping().await })
}

/// Action to be executed on the daemon in general, sent from the control.
pub enum DaemonAction {
    Stop,
    Node(NodeAction),
}
