#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::Result;
    use async_std::sync::channel;
    use async_std::{sync::Arc, task};
    use libp2p::multiaddr::multiaddr;
    use threshold::dkg;
    use threshold::*;

    use crate::dkg::board::Board;
    use crate::dkg::node::Node;
    use crate::key;

    #[async_std::test]
    async fn test_dkg_simple_5_3() {
        dkg_simple(5, 3, true).await;
        dkg_simple(5, 3, false).await;
    }

    #[async_std::test]
    async fn test_dkg_simple_10_8() {
        dkg_simple(10, 8, true).await;
        dkg_simple(10, 8, false).await;
    }

    #[async_std::test]
    async fn test_dkg_simple_5_5() {
        // dkg_simple(5, 5, true).await; will fail
        dkg_simple(5, 5, false).await;
    }

    async fn dkg_simple(n: usize, thr: usize, phase3: bool) {
        println!(
            "- New example with {} nodes and a threshold of {} (justification: {})",
            n, thr, phase3
        );

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
        for _kp in &keypairs {
            channels.push(channel(100));
        }
        let channels = Arc::new(channels);
        for (i, _kp) in keypairs.iter().enumerate() {
            let (sender, receiver) = channel(50);
            let board = Board::new(
                group.clone(),
                sender,
                channels[i].1.clone(),
                Duration::from_secs(5),
            );

            let channels = channels.clone();

            task::spawn(async move {
                while let Some((out_id, msg)) = receiver.recv().await {
                    for (j, (sender, _)) in channels.iter().enumerate() {
                        // floodsub
                        if i != j {
                            // println!("{} -> {}: {:?}", i, j, msg);
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

                let board = board.start();
                let node = board.run_dkg_test(node, i == 0 && phase3).await?;
                let qual = node.qual()?;

                println!("\t -> dealer has qualified set {:?}", qual);
                let dist_public = node.dist_public()?;

                println!("- Distributed public key: {:?}", dist_public.public_key());
                println!("- DKG ended");

                Ok::<_, anyhow::Error>(dist_public.clone())
            }));
        }

        let mut keys = Vec::new();
        for task in tasks.into_iter() {
            keys.push(task.await.unwrap());
        }

        if phase3 {
            // TODO: verify that this is the right expectation.
            for key in &keys[2..] {
                assert_eq!(key.public_key(), keys[1].public_key());
            }
        } else {
            for key in &keys[1..] {
                assert_eq!(key.public_key(), keys[0].public_key());
            }
        }
    }
}
