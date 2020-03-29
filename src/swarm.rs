use std::{
    io::Error,
    path::PathBuf,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::Result;
use async_std::prelude::*;
use async_std::{
    io,
    sync::{channel, Receiver, Sender},
    task,
};
use futures::StreamExt;
use libp2p::{
    core,
    core::muxing::StreamMuxerBox,
    core::transport::boxed::Boxed,
    floodsub::{self, Floodsub, FloodsubEvent},
    identity, mplex, noise,
    swarm::{self, NetworkBehaviourEventProcess},
    yamux, Multiaddr, NetworkBehaviour, PeerId, Swarm, Transport,
};
use log::{info, warn};

type Libp2pStream = Boxed<(PeerId, StreamMuxerBox), Error>;
type Libp2pBehaviour = NodeBehaviour;

pub struct Node {
    swarm: Swarm<Libp2pBehaviour>,
    topic: floodsub::Topic,
    action_receiver: Receiver<NodeAction>,
    action_sender: Sender<NodeAction>,
}

pub enum NodeAction {
    Stop,
    Dial(Multiaddr),
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "NetworkEvent", poll_method = "poll")]
struct NodeBehaviour {
    floodsub: Floodsub,
}

#[derive(Debug, Clone)]
enum NetworkEvent {
    Dummy,
}

impl NodeBehaviour {
    /// Consumes the events list when polled.
    fn poll<TBehaviourIn>(
        &mut self,
        _: &mut Context,
        _params: &mut impl swarm::PollParameters,
    ) -> Poll<swarm::NetworkBehaviourAction<TBehaviourIn, NetworkEvent>> {
        // if !self.events.is_empty() {
        // return Poll::Ready(swarm::NetworkBehaviourAction::GenerateEvent(
        //     NetworkEvent::Dummy,
        // ));
        // }
        Poll::Pending
    }
}

impl NetworkBehaviourEventProcess<FloodsubEvent> for NodeBehaviour {
    // Called when `floodsub` produces an event.
    fn inject_event(&mut self, message: FloodsubEvent) {
        if let FloodsubEvent::Message(message) = message {
            info!(
                "Received: '{:?}' from {:?}",
                String::from_utf8_lossy(&message.data),
                message.source
            );
        }
    }
}

impl Node {
    pub fn new(
        local_key: &identity::ed25519::Keypair,
        local_peer_id: &PeerId,
        listen_addr: Multiaddr,
    ) -> Result<Self> {
        let local_key = identity::Keypair::Ed25519(local_key.clone());
        info!("Local peer id: {:?}", local_peer_id);

        let transport = build_transport(local_key);

        let floodsub_topic = floodsub::Topic::new("drand-dkg");

        // Create a Swarm to manage peers and events
        let mut swarm = {
            let mut behaviour = NodeBehaviour {
                floodsub: Floodsub::new(local_peer_id.clone()),
            };

            behaviour.floodsub.subscribe(floodsub_topic.clone());
            Swarm::new(transport, behaviour, local_peer_id.clone())
        };

        Swarm::listen_on(&mut swarm, listen_addr)?;

        let (action_sender, action_receiver) = channel(10);

        Ok(Node {
            swarm,
            topic: floodsub_topic,
            action_sender,
            action_receiver,
        })
    }

    pub fn action_sender(&self) -> Sender<NodeAction> {
        self.action_sender.clone()
    }

    /// Starts the `Libp2pService` networking stack. This Future resolves when shutdown occurs.
    pub async fn run(&mut self) -> Result<()> {
        // Read full lines from stdin
        let mut stdin = io::BufReader::new(io::stdin()).lines();

        let (sender, receiver) = channel(10);

        task::spawn(async move {
            while let Some(Ok(line)) = stdin.next().await {
                sender.send(line).await;
            }
        });

        enum E<Err: std::error::Error> {
            Swarm(swarm::SwarmEvent<NetworkEvent, Err>),
            Io(Option<String>),
            Action(Option<NodeAction>),
        }

        loop {
            use futures::FutureExt;
            let fut = self
                .swarm
                .next_event()
                .map(E::Swarm)
                .race(receiver.recv().map(E::Io))
                .race(self.action_receiver.recv().map(E::Action));
            match fut.await {
                E::Swarm(swarm_event) => {
                    info!("{:?}", swarm_event);
                    match swarm_event {
                        swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            // TODO: only connect to the ones we actually care about.
                            self.swarm.floodsub.add_node_to_partial_view(peer_id);
                        }
                        _ => {}
                    }
                }
                E::Io(io_event) => match io_event {
                    Some(line) => {
                        self.swarm
                            .floodsub
                            .publish(self.topic.clone(), line.as_bytes());
                    }
                    None => {
                        info!("Stdin closed");
                        break;
                    }
                },
                E::Action(action) => match action {
                    Some(NodeAction::Dial(addr)) => {
                        match Swarm::dial_addr(&mut self.swarm, addr.clone()) {
                            Ok(_) => {
                                info!("Dialed {:?}", addr);
                            }
                            Err(err) => {
                                warn!("Failed to dial {:?}: {}", addr, err);
                            }
                        }
                    }
                    Some(NodeAction::Stop) => {
                        info!("shutting down");
                        break;
                    }
                    None => {
                        info!("action channel dropped");
                        break;
                    }
                },
            }
        }

        Ok(())
    }
}

/// Builds the transport stack that LibP2P will communicate over.
fn build_transport(local_key: identity::Keypair) -> Libp2pStream {
    // TODO: support noise IK with restrictions on the peers to the group

    let dh_keys = noise::Keypair::<noise::X25519>::from_identity(&local_key)
        .expect("unable to generate Noise Keypair");

    let transport = libp2p::tcp::TcpConfig::new().nodelay(true);
    let transport = libp2p::dns::DnsConfig::new(transport).unwrap();

    transport
        .upgrade(core::upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(dh_keys).into_authenticated())
        .multiplex(core::upgrade::SelectUpgrade::new(
            yamux::Config::default(),
            mplex::MplexConfig::new(),
        ))
        .map(|(peer, muxer), _| (peer, core::muxing::StreamMuxerBox::new(muxer)))
        .timeout(Duration::from_secs(20))
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
        .boxed()
}
