use anyhow::{anyhow, Result};
use threshold::dkg;
use threshold::sig::*;
use threshold::*;

use super::board::Board;
use super::curve::{KeyCurve, PrivateKey, PublicKey, Scheme};
use super::node::Node;

use crate::key;

pub struct Orchestrator {
    thr: usize,
    /// The node data of the caller.
    node: Node,
    self_index: usize,
    board: Board,
    // qualified group of nodes after the dkg protocol
    qual: Option<dkg::Group<KeyCurve>>,
    dist_public: Option<DistPublic<KeyCurve>>,
}

impl Orchestrator {
    pub fn new(
        self_key: &key::Pair,
        self_index: usize,
        keypairs: &[key::Identity],
        thr: usize,
    ) -> Orchestrator {
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
        let board = Board::init(group.clone());
        let node = Node::new(
            self_index,
            self_key.private().clone().into(),
            self_key.public().public_key().clone().into(),
            group,
        );

        Self {
            thr,
            node,
            self_index,
            board,
            qual: None,
            dist_public: None,
        }
    }

    /// run the dkg phase by phase
    /// if phase3 is set to true, the orchestrator simulates an invalid
    /// deal/share such that it requires a justification phase.
    pub fn run_dkg(&mut self, phase3: bool) -> Result<()> {
        println!("- DKG starting (justification? {:?})", phase3);
        self.board.dkg_start();
        // phase1: publishing shares

        println!("\t -> publish shares");
        self.node.dkg_phase1(&mut self.board);

        // phase2: read all shares and producing responses
        self.board.dkg_phase2();
        println!("- Phase 2: processing shares and publishing potential responses");
        let all_shares = self.board.get_shares();

        println!("\t -> node process shares");
        self.node.dkg_phase2(&mut self.board, &all_shares);

        if self.board.dkg_need_phase3() {
            println!("- Phase 3 required since responses have been issued");
            self.board.dkg_phase3();
        } else {
            println!("- Final phase of dkg - computing shares");
            self.board.finish_dkg();
        }

        // end of phase 2: read all responses and see if dkg can finish
        // if there is need for justifications, nodes will publish
        let all_responses = self.board.get_responses();
        self.node.dkg_endphase2(&mut self.board, &all_responses);

        if self.board.dkg_need_phase3() {
            let all_justifs = self.board.get_justifications();
            println!(
                "- Number of dealers that are pushing justifications: {}",
                all_justifs.len()
            );

            self.node.dkg_phase3(&all_justifs)?;
            self.qual = Some(self.node.qual());
            self.dist_public = Some(self.node.dist_public());
            println!("\t -> dealer has qualified set {:?}", self.node.qual());
        }

        let d = self.dist_public.take().unwrap();
        println!("- Distributed public key: {:?}", d.public_key());
        self.dist_public = Some(d);
        println!("- DKG ended");
        Ok(())
    }

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
        if let Some(qual_match) = qual_match {
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
