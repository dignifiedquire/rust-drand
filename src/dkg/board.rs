use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, ensure, Result};
use async_std::prelude::*;
use async_std::sync::{channel, Arc, Receiver, RwLock, Sender};
use futures::future::Either;
use libp2p::PeerId;
use log::info;
use serde::{Deserialize, Serialize};
use stop_token::StopSource;
use threshold::dkg;
use threshold::*;

use super::curve::{KeyCurve, PublicKey};

pub struct Board<S> {
    group: dkg::Group<KeyCurve>,
    state: S,
    sender: Sender<(PeerId, ProtocolMessage)>,
    receiver: Receiver<(PeerId, ProtocolMessage)>,
    timeout: Duration,
    /// Token to stop the receiver stream.
    stop_source: Option<StopSource>,
    deals: Arc<RwLock<HashMap<PeerId, dkg::BundledShares<KeyCurve>>>>,
    deals_done: Option<Receiver<()>>,
    responses: Arc<RwLock<HashMap<PeerId, dkg::BundledResponses>>>,
    responses_done: Option<Receiver<()>>,
    justifications: Arc<RwLock<HashMap<PeerId, dkg::BundledJustification<KeyCurve>>>>,
    justifications_done: Option<Receiver<()>>,
}

pub struct Start;
pub struct One;
pub struct Two;
pub struct Three;
pub struct Done;

/// The messages a participant sends and receives during the dkg.
#[derive(Clone, Serialize, Deserialize)]
pub enum ProtocolMessage {
    /// Contains the share of participant.
    Deal(dkg::BundledShares<KeyCurve>),
    /// Holds the response that a participant broadcasts after receiving a deal.
    Response(dkg::BundledResponses),
    /// Holds the justification from a dealer after a participant issued a complaint of a supposedly invalid deal.
    Justification(dkg::BundledJustification<KeyCurve>),
}

impl std::fmt::Debug for ProtocolMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolMessage::Deal(_) => write!(f, "ProtocolMessage::Deal"),
            ProtocolMessage::Response(_) => write!(f, "ProtocolMessage::Response"),
            ProtocolMessage::Justification(_) => write!(f, "ProtocolMessage::Justification"),
        }
    }
}

impl Board<Start> {
    pub fn new(
        group: dkg::Group<KeyCurve>,
        sender: Sender<(PeerId, ProtocolMessage)>,
        receiver: Receiver<(PeerId, ProtocolMessage)>,
        timeout: Duration,
    ) -> Self {
        Self {
            group,
            state: Start,
            sender,
            receiver,
            timeout,
            stop_source: None,
            deals: Default::default(),
            deals_done: None,
            responses: Default::default(),
            responses_done: None,
            justifications: Default::default(),
            justifications_done: None,
        }
    }

    /// Start the DKG process.
    pub fn start(mut self) -> Board<One> {
        let deals = self.deals.clone();
        let responses = self.responses.clone();
        let justifications = self.justifications.clone();
        let group_len = self.group.len();

        let (deals_done_sender, deals_done_receiver) = channel(1);
        let (responses_done_sender, responses_done_receiver) = channel(1);
        let (justifications_done_sender, justifications_done_receiver) = channel(1);

        self.deals_done = Some(deals_done_receiver);
        self.responses_done = Some(responses_done_receiver);
        self.justifications_done = Some(justifications_done_receiver);

        let stop_source = StopSource::new();
        let token = stop_source.stop_token();
        self.stop_source = Some(stop_source);
        let mut receiver = token.stop_stream(self.receiver.clone());

        async_std::task::spawn(async move {
            while let Some((peer, msg)) = receiver.next().await {
                match msg {
                    ProtocolMessage::Deal(deal) => {
                        {
                            // ensure the lock is dropped
                            deals.write().await.insert(peer, deal);
                        }
                        if deals.read().await.len() == group_len - 1 {
                            deals_done_sender.send(()).await;
                        }
                    }
                    ProtocolMessage::Response(response) => {
                        {
                            responses.write().await.insert(peer, response);
                        }
                        if responses.read().await.len() == group_len - 1 {
                            responses_done_sender.send(()).await;
                        }
                    }
                    ProtocolMessage::Justification(just) => {
                        {
                            justifications.write().await.insert(peer, just);
                        }
                        if justifications.read().await.len() == group_len - 1 {
                            justifications_done_sender.send(()).await;
                        }
                    }
                }
            }
        });

        self.set_state(One)
    }
}

impl Board<One> {
    #[cfg(test)]
    pub(crate) async fn run_dkg_test(
        self,
        node: super::node::Node<super::node::Start>,
        no_publish: bool,
    ) -> Result<super::node::Node<super::node::Done>> {
        info!("Phase 1");

        let node = if no_publish {
            node.dkg_phase1_no_publish().await?
        } else {
            node.dkg_phase1(&self).await?
        };

        self.dkg_inner(node).await
    }

    pub async fn run_dkg(
        self,
        node: super::node::Node<super::node::Start>,
    ) -> Result<super::node::Node<super::node::Done>> {
        info!("Phase 1");
        let node = node.dkg_phase1(&self).await?;

        self.dkg_inner(node).await
    }

    async fn dkg_inner(
        self,
        node: super::node::Node<super::node::One>,
    ) -> Result<super::node::Node<super::node::Done>> {
        info!("Phase 2");
        let mut board = self.phase2().await?;
        let all_shares = board.get_shares().await;
        let node = node.dkg_phase2(&mut board, &all_shares).await?;

        info!("Phase 3");
        let mut board = board.phase3().await?;

        // end of phase 2: read all responses and see if dkg can finish
        // if there is need for justifications, nodes will publish
        let all_responses = board.get_responses().await;
        let node = node.dkg_endphase2(&mut board, &all_responses).await?;

        let node = match node {
            Either::Left(node) => {
                // needs phase3
                let all_justifs = board.get_justifications().await;
                info!(
                    "- Number of dealers that are pushing justifications: {}",
                    all_justifs.len()
                );
                node.dkg_phase3(&all_justifs)?
            }
            Either::Right(node) => node,
        };
        let _board = board.finish().await?;

        let qual = node.qual()?;

        info!("\t -> dealer has qualified set {:?}", qual);
        let dist_public = node.dist_public()?;

        info!("- Distributed public key: {:?}", dist_public.public_key());
        info!("- DKG ended");

        Ok(node)
    }

    async fn phase2(self) -> Result<Board<Two>> {
        match self
            .deals_done
            .as_ref()
            .expect("not started")
            .recv()
            .timeout(self.timeout)
            .await
        {
            Ok(Some(())) => {
                info!("received all deals");
            }
            Ok(None) => {
                info!("phase1 aborted due to interrupt");
            }
            Err(_) => {
                info!("stopped phase1 due to timeout");
            }
        }

        Ok(self.set_state(Two))
    }

    /// Called by each participant of the dkg protocol during the phase 1.
    ///
    /// NOTE: this call should verify the authenticity of the sender! This
    /// function only checks the public key at the moment - Needs further
    /// clarification from actual use case
    pub(super) async fn publish_shares(
        &self,
        peer_id: PeerId,
        sender_pk: &PublicKey,
        bundle: dkg::BundledShares<KeyCurve>,
    ) -> Result<()> {
        self.check_authenticity(sender_pk, bundle.dealer_idx)?;
        self.sender
            .send((peer_id, ProtocolMessage::Deal(bundle)))
            .await;
        Ok(())
    }
}

impl Board<Two> {
    async fn phase3(self) -> Result<Board<Three>> {
        match self
            .responses_done
            .as_ref()
            .expect("not started")
            .recv()
            .timeout(self.timeout)
            .await
        {
            Ok(Some(())) => {
                info!("received all responses");
            }
            Ok(None) => {
                info!("phase2 aborted due to interrupt");
            }
            Err(_) => {
                info!("stopped phase2 due to timeout");
            }
        }

        Ok(self.set_state(Three))
    }

    /// Called during phase 2 by participant that claim having received an invalid share.
    ///
    /// NOTE: this call should verify the authenticity of the sender! This
    /// function only checks the public key at the moment - Needs further
    /// clarification from actual use case
    pub(super) async fn publish_responses(
        &self,
        peer_id: PeerId,
        sender_pk: &PublicKey,
        bundle: dkg::BundledResponses,
    ) -> Result<()> {
        self.check_authenticity(sender_pk, bundle.share_idx)?;
        self.sender
            .send((peer_id, ProtocolMessage::Response(bundle)))
            .await;
        Ok(())
    }
}

impl Board<Three> {
    async fn finish(mut self) -> Result<Board<Done>> {
        if self.needs_justifications().await {
            match self
                .justifications_done
                .as_ref()
                .expect("not started")
                .recv()
                .timeout(self.timeout)
                .await
            {
                Ok(Some(())) => {
                    info!("received all justifications");
                }
                Ok(None) => {
                    info!("phase3 aborted due to interrupt");
                }
                Err(_) => {
                    info!("stopped phase3 due to timeout");
                }
            }
        }

        self.stop();
        Ok(self.set_state(Done))
    }

    pub(super) async fn publish_justifications(
        &self,
        peer_id: PeerId,
        sender_pk: &PublicKey,
        bundle: dkg::BundledJustification<KeyCurve>,
    ) -> Result<()> {
        self.check_authenticity(sender_pk, bundle.dealer_idx)?;
        self.sender
            .send((peer_id, ProtocolMessage::Justification(bundle)))
            .await;
        Ok(())
    }
}

impl<S> Board<S> {
    pub fn stop(&mut self) {
        // Interrupts the receiver stream, stopping the task started in `Self::start`.
        self.stop_source.take();
    }

    fn set_state<T>(self, new_state: T) -> Board<T> {
        let Self {
            group,
            sender,
            receiver,
            timeout,
            stop_source,
            deals,
            deals_done,
            responses,
            responses_done,
            justifications,
            justifications_done,
            ..
        } = self;

        Board {
            group,
            state: new_state,
            sender,
            receiver,
            timeout,
            stop_source,
            deals,
            deals_done,
            responses,
            responses_done,
            justifications,
            justifications_done,
        }
    }

    pub async fn needs_justifications(&self) -> bool {
        !self.responses.read().await.is_empty()
    }

    pub async fn get_shares(&self) -> Vec<dkg::BundledShares<KeyCurve>> {
        self.deals.read().await.values().cloned().collect()
    }

    pub async fn get_responses(&self) -> Vec<dkg::BundledResponses> {
        self.responses.read().await.values().cloned().collect()
    }

    pub async fn get_justifications(&self) -> Vec<dkg::BundledJustification<KeyCurve>> {
        self.justifications.read().await.values().cloned().collect()
    }

    fn check_authenticity(&self, sender: &PublicKey, claimed_index: Index) -> Result<Index> {
        match self.group.index(sender) {
            Some(i) => {
                // Actual verification
                ensure!(
                    i == claimed_index,
                    "publish shares called with different index than bundle",
                );

                Ok(i)
            }
            None => bail!("publish shares called with a public that does not belong to group",),
        }
    }
}
