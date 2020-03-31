use anyhow::{anyhow, bail, Result};
use async_std::sync::channel;
use futures::future::Either;
use threshold::dkg;
use threshold::sig::*;
use threshold::*;

use super::board::{self, Board};
use super::curve::{KeyCurve, Scheme};
use super::node::{self, Node};

use crate::key;

pub struct Orchestrator<S, T> {
    thr: usize,
    /// The node data of the caller.
    node: Node<S>,
    self_index: usize,
    board: Board<T>,
    // qualified group of nodes after the dkg protocol
    qual: Option<dkg::Group<KeyCurve>>,
    dist_public: Option<DistPublic<KeyCurve>>,
}

impl Orchestrator<node::Start, board::Start> {
    pub fn new(
        self_key: &key::Pair,
        self_index: usize,
        keypairs: &[key::Identity],
        thr: usize,
    ) -> Result<Orchestrator<node::Start, board::Start>> {
        let n = keypairs.len();

        println!("- New example with {} nodes and a threshold of {}", n, thr);

        let dkgnodes: Vec<_> = keypairs
            .iter()
            .enumerate()
            .map(|(i, kp)| {
                let pk: bls_signatures::PublicKey = kp.public_key().clone();
                let g1: paired::bls12_381::G1 = pk.into();
                dkg::Node::new(i as Index, g1)
            })
            .collect();
        let group = match dkg::Group::new(dkgnodes, thr) {
            Ok(group) => group,
            Err(e) => panic!(e),
        };
        let (sender, receiver) = channel(10);

        let board = Board::init(group.clone(), sender.clone(), receiver.clone());
        let node = Node::new(
            self_index,
            self_key.private().clone().into(),
            self_key.public().public_key().clone().into(),
            self_key.public().peer_id().clone(),
            group,
        )?;

        Ok(Self {
            thr,
            node,
            self_index,
            board,
            qual: None,
            dist_public: None,
        })
    }

    /// run the dkg phase by phase
    pub async fn run_dkg(self) -> Result<Orchestrator<node::Done, board::Done>> {
        println!("- DKG starting");
        let Self {
            thr,
            node,
            self_index,
            board,
            mut qual,
            mut dist_public,
        } = self;

        let board = board.start();

        // phase1: publishing shares

        println!("\t -> publish shares");
        let node = node.dkg_phase1(&board).await?;
        // phase2: read all shares and producing responses
        let mut board = board.phase2().await?;
        println!("- Phase 2: processing shares and publishing potential responses");

        let all_shares = board.get_shares().await;
        println!("\t -> node process shares");
        let node = node.dkg_phase2(&mut board, &all_shares).await?;

        let mut board = board.phase3()?;

        // end of phase 2: read all responses and see if dkg can finish
        // if there is need for justifications, nodes will publish
        let all_responses = board.get_responses().await;
        let node = node.dkg_endphase2(&mut board, &all_responses).await?;

        let node = match node {
            Either::Left(node) => {
                // needs phase3
                if !board.needs_justifications().await {
                    bail!("inconsistent state");
                }
                let all_justifs = board.get_justifications().await;
                println!(
                    "- Number of dealers that are pushing justifications: {}",
                    all_justifs.len()
                );

                let node = node.dkg_phase3(&all_justifs)?;
                qual = Some(node.qual()?.clone());
                dist_public = Some(node.dist_public()?.clone());
                println!("\t -> dealer has qualified set {:?}", node.qual());
                node
            }
            Either::Right(node) => node,
        };
        let board = board.finish().await?;

        let d = dist_public.unwrap();
        println!("- Distributed public key: {:?}", d.public_key());
        let dist_public = Some(d);
        println!("- DKG ended");

        Ok(Orchestrator {
            thr,
            node,
            self_index,
            board,
            qual,
            dist_public,
        })
    }
}

impl Orchestrator<node::Done, board::Done> {
    pub fn threshold_blind_sign(&mut self, msg: &[u8]) -> Result<()> {
        println!("\nThreshold blind signature example");
        let qual = self.qual.take().unwrap();
        println!("\t -> using qualified set {:?}\n", qual);
        // 1. blind the message for each destination
        println!("- Phase 1: client blinds the message");
        let (token, blind) = Scheme::blind(msg);
        // 2. request partial signatures from t nodes
        println!(
            "- Phase 2: request (blinded) partial signatures over the blinded message to qualified nodes"
        );

        let qual_match = qual
            .nodes
            .iter()
            .find(|n| n.id() as usize == self.self_index);
        let mut partials = Vec::new();
        if let Some(_qual_match) = qual_match {
            println!("\t -> {} is signing partial", self.self_index);
            partials.push(self.node.partial(&blind)?);
        }

        // 3. aggregate all blinded signatures together
        // It can be done by any third party
        println!(
            "- Phase 3: aggregating all blinded partial signatures into final blinded signature"
        );
        let blinded_sig =
            Scheme::aggregate(self.thr, &partials).map_err(|err| anyhow!("{}", err))?;
        // 4. unblind the signature - this is done by the "client"
        println!("- Phase 4: client unblinds the final signature");
        let final_sig = Scheme::unblind(&token, &blinded_sig).map_err(|err| anyhow!("{}", err))?;
        // 5. verify
        Scheme::verify(
            &self.dist_public.take().unwrap().public_key(),
            msg,
            &final_sig,
        )
        .map_err(|err| anyhow!("{}", err))?;
        println!("- Signature verifed against the distributed public key");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    use async_std::{sync::Arc, task};
    use libp2p::multiaddr::multiaddr;

    #[async_std::test]
    async fn test_dkg_simple_5_3() {
        dkg_simple(5, 3).await;
    }

    #[async_std::test]
    async fn test_dkg_simple_10_8() {
        dkg_simple(10, 8).await;
    }

    #[async_std::test]
    async fn test_dkg_simple_5_5() {
        dkg_simple(5, 5).await;
    }

    async fn dkg_simple(n: usize, thr: usize) {
        println!("- New example with {} nodes and a threshold of {}", n, thr);

        let mut keypairs = Vec::new();
        let mut boards = Vec::new();

        for i in 0..n {
            let addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(i as u16));
            keypairs.push(key::Pair::new(addr).unwrap());
        }
        let dkgnodes: Vec<_> = keypairs
            .iter()
            .enumerate()
            .map(|(i, kp)| {
                let pk: bls_signatures::PublicKey = kp.public().public_key().clone();
                let g1: paired::bls12_381::G1 = pk.into();
                dkg::Node::new(i as Index, g1)
            })
            .collect();

        let group = dkg::Group::new(dkgnodes, thr).unwrap();

        let nodes = keypairs
            .iter()
            .enumerate()
            .map(|(i, kp)| {
                Node::new(
                    i,
                    kp.private().clone().into(),
                    kp.public().public_key().clone().into(),
                    kp.public().peer_id().clone(),
                    group.clone(),
                )
            })
            .collect::<Result<Vec<_>>>()
            .unwrap();

        // setup channels
        let mut channels = Vec::new();
        for kp in &keypairs {
            channels.push(channel(100));
        }
        let channels = Arc::new(channels);
        for (i, kp) in keypairs.iter().enumerate() {
            let (sender, receiver) = channel(50);
            let board = Board::init(group.clone(), sender, channels[i].1.clone());

            let channels = channels.clone();

            task::spawn(async move {
                println!("{} spawning loop", i);
                while let Some((out_id, msg)) = receiver.recv().await {
                    for (j, (sender, _)) in channels.iter().enumerate() {
                        // floodsub
                        if i != j {
                            println!("{} -> {}: {:?}", i, j, msg);
                            sender.send((out_id.clone(), msg.clone())).await;
                        }
                    }
                }
            });

            boards.push(board);
        }

        let mut tasks = Vec::new();
        for (i, (node, board)) in nodes.into_iter().zip(boards.into_iter()).enumerate() {
            // node 0 is the leader
            tasks.push(task::spawn(async move {
                println!("{} - DKG starting", i);
                let is_leader = i == 0;

                let board = board.start();
                let node = node.dkg_phase1(&board).await?;

                // phase2: read all shares and producing responses
                let mut board = board.phase2().await?;
                println!(
                    "{} - Phase 2: processing shares and publishing potential responses",
                    i
                );
                let all_shares = board.get_shares().await;
                println!("{} \t -> node process shares", i);
                let node = node.dkg_phase2(&mut board, &all_shares).await?;

                let mut board = board.phase3()?;

                // end of phase 2: read all responses and see if dkg can finish
                // if there is need for justifications, nodes will publish
                let all_responses = board.get_responses().await;
                let node = node.dkg_endphase2(&mut board, &all_responses).await?;

                let node = match node {
                    Either::Left(node) => {
                        // needs phase3
                        if !board.needs_justifications().await {
                            bail!("inconsistent state");
                        }
                        let all_justifs = board.get_justifications().await;
                        println!(
                            "- Number of dealers that are pushing justifications: {}",
                            all_justifs.len()
                        );

                        let node = node.dkg_phase3(&all_justifs)?;
                        println!("\t -> dealer has qualified set {:?}", node.qual());
                        node
                    }
                    Either::Right(node) => node,
                };
                let board = board.finish().await?;

                let qual = node.qual()?;
                let dist_public = node.dist_public()?;

                println!("- Distributed public key: {:?}", dist_public.public_key());
                println!("- DKG ended");

                Ok(dist_public.clone())
            }));
        }

        let mut keys = Vec::new();
        for task in tasks.into_iter() {
            keys.push(task.await.unwrap());
        }

        for key in &keys[1..] {
            assert_eq!(key.public_key(), keys[0].public_key());
        }
    }
}
