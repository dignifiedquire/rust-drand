use std::error::Error;

use anyhow::Result;
use threshold::dkg;
use threshold::sig::ThresholdScheme;
use threshold::*;

use super::board::Board;
use super::curve::{KeyCurve, PrivateKey, PublicKey, Scheme};

/// Node holds the logic of a participants, for the different phases of the example.
pub struct Node {
    public: PublicKey,
    // Index is a type alias to represent the index of a participant. It can be
    // changed depending on the size of the network - u16 is likely to work for
    // most cases though.
    index: Index,
    state: DkgState,
}

enum DkgState {
    Clear,
    Start(dkg::DKG<KeyCurve>),
    One(dkg::DKGWaitingShare<KeyCurve>),
    Two(dkg::DKGWaitingResponse<KeyCurve>),
    Three(dkg::DKGWaitingJustification<KeyCurve>),
    Done(dkg::DKGOutput<KeyCurve>),
    Error(Box<dyn Error>),
}

impl Node {
    pub fn new(
        index: usize,
        private: PrivateKey,
        public: PublicKey,
        group: dkg::Group<KeyCurve>,
    ) -> Self {
        // XXX use lifetimes to remove cloning requirement
        let d = match dkg::DKG::new(private, group.clone()) {
            Ok(dkg) => dkg,
            Err(e) => {
                println!("{}", e);
                panic!(e)
            }
        };
        Self {
            public,
            index: index as Index,
            state: DkgState::Start(d),
        }
    }

    pub fn dkg_phase1(&mut self, board: &mut Board) {
        let public = &self.public;
        take_mut::take(&mut self.state, |state| match state {
            DkgState::Start(to_phase1) => {
                let (ndkg, shares) = to_phase1.shares();
                board.publish_shares(public, shares);
                DkgState::One(ndkg)
            }
            _ => panic!("invalid state"),
        });
    }

    pub fn dkg_phase2(&mut self, board: &mut Board, shares: &Vec<dkg::BundledShares<KeyCurve>>) {
        let public = &self.public;
        let index = &self.index;

        take_mut::take(&mut self.state, |state| match state {
            DkgState::One(to_phase2) => match to_phase2.process_shares(shares) {
                Ok((ndkg, bundle_o)) => {
                    if let Some(bundle) = bundle_o {
                        println!("\t\t -> node publish {} responses", index);
                        board.publish_responses(public, bundle);
                    }
                    DkgState::Two(ndkg)
                }
                Err(e) => panic!("index {}: {:?}", index, e),
            },
            _ => panic!("invalid state"),
        })
    }

    pub fn dkg_endphase2(&mut self, board: &mut Board, bundle: &Vec<dkg::BundledResponses>) {
        let public = &self.public;
        take_mut::take(&mut self.state, |state| {
            match state {
                DkgState::Two(end_phase2) => {
                    match end_phase2.process_responses(bundle) {
                        Ok(output) => DkgState::Done(output),
                        Err((ndkg, justifs)) => {
                            // publish justifications if you have some
                            // Nodes may just see that justifications are needed but they
                            // don't have to create any, since no  complaint have been filed
                            // against their deal.
                            if let Some(j) = justifs {
                                board.publish_justifications(public, j);
                            }
                            DkgState::Three(ndkg)
                        }
                    }
                }
                _ => panic!("invalid state"),
            }
        })
    }

    pub fn dkg_phase3(
        &mut self,
        justifications: &Vec<dkg::BundledJustification<KeyCurve>>,
    ) -> Result<()> {
        take_mut::take(&mut self.state, |state| match state {
            DkgState::Three(phase3) => match phase3.process_justifications(justifications) {
                Ok(output) => DkgState::Done(output),
                Err(e) => DkgState::Error(Box::new(e)),
            },
            _ => panic!("invalid state"),
        });

        if let DkgState::Error(ref err) = self.state {
            return Err(anyhow::anyhow!("{}", err));
        }

        Ok(())
    }

    pub fn partial(&mut self, partial: &[u8]) -> Result<Vec<u8>> {
        let res = match &self.state {
            DkgState::Done(out) => Scheme::partial_sign(&out.share, partial)
                .map_err(|err| anyhow::anyhow!("{}", err))?,
            _ => {
                panic!("invalid state");
            }
        };
        Ok(res)
    }

    pub fn qual(&mut self) -> dkg::Group<KeyCurve> {
        match &self.state {
            DkgState::Done(out) => out.qual.clone(),
            _ => panic!("invalid state"),
        }
    }

    pub fn dist_public(&mut self) -> DistPublic<KeyCurve> {
        match &self.state {
            DkgState::Done(out) => out.public.clone(),
            _ => panic!("invalid state"),
        }
    }
}
