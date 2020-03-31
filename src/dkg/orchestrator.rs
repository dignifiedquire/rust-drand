#[cfg(test)]
mod tests {
    use anyhow::{bail, Result};
    use async_std::sync::channel;
    use async_std::{sync::Arc, task};
    use futures::future::Either;
    use libp2p::multiaddr::multiaddr;
    use threshold::dkg;
    use threshold::*;

    use crate::dkg::board::Board;
    use crate::dkg::node::Node;
    use crate::key;

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
