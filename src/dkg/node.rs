use anyhow::{anyhow, Result};
use futures::future::Either;
use libp2p::PeerId;
use log::info;
use threshold::dkg;
use threshold::sig::ThresholdScheme;
use threshold::*;

use super::board::{self, Board};
use super::curve::{KeyCurve, PrivateKey, PublicKey, Scheme};

/// Node holds the logic of a participants, for the different phases of the example.
pub struct Node<S> {
    public: PublicKey,
    peer_id: PeerId,
    // Index is a type alias to represent the index of a participant. It can be
    // changed depending on the size of the network - u16 is likely to work for
    // most cases though.
    index: Index,
    state: S,
}

pub struct Start(dkg::DKG<KeyCurve>);
pub struct One(dkg::DKGWaitingShare<KeyCurve>);
pub struct Two(dkg::DKGWaitingResponse<KeyCurve>);
pub struct Three(dkg::DKGWaitingJustification<KeyCurve>);
pub struct Done(Result<dkg::DKGOutput<KeyCurve>>);

impl Node<Start> {
    pub fn new(
        index: usize,
        private: PrivateKey,
        public: PublicKey,
        peer_id: PeerId,
        group: dkg::Group<KeyCurve>,
    ) -> Result<Self> {
        // XXX use lifetimes to remove cloning requirement
        let d = dkg::DKG::new(private, group.clone())?;
        Ok(Self {
            public,
            peer_id,
            index: index as Index,
            state: Start(d),
        })
    }

    #[cfg(test)]
    pub async fn dkg_phase1_no_publish(self) -> Result<Node<One>> {
        let Self {
            public,
            peer_id,
            index,
            state,
        } = self;

        let (ndkg, _shares) = state.0.shares();

        Ok(Node {
            public,
            peer_id,
            index,
            state: One(ndkg),
        })
    }

    pub async fn dkg_phase1(self, board: &Board<board::One>) -> Result<Node<One>> {
        let Self {
            public,
            peer_id,
            index,
            state,
        } = self;

        let (ndkg, shares) = state.0.shares();
        board
            .publish_shares(peer_id.clone(), &public, shares)
            .await?;

        Ok(Node {
            public,
            peer_id,
            index,
            state: One(ndkg),
        })
    }
}

impl Node<One> {
    pub async fn dkg_phase2(
        self,
        board: &mut Board<board::Two>,
        shares: &Vec<dkg::BundledShares<KeyCurve>>,
    ) -> Result<Node<Two>> {
        let Self {
            peer_id,
            public,
            index,
            state,
        } = self;

        let (ndkg, bundle) = state.0.process_shares(shares)?;
        if let Some(bundle) = bundle {
            info!("\t\t -> node publish {} responses", index);
            board
                .publish_responses(peer_id.clone(), &public, bundle)
                .await?;
        }

        Ok(Node {
            peer_id,
            public,
            index,
            state: Two(ndkg),
        })
    }
}

impl Node<Two> {
    pub async fn dkg_endphase2(
        self,
        board: &mut Board<board::Three>,
        bundle: &Vec<dkg::BundledResponses>,
    ) -> Result<Either<Node<Three>, Node<Done>>> {
        let Self {
            peer_id,
            public,
            index,
            state,
        } = self;

        match state.0.process_responses(bundle) {
            Ok(output) => Ok(Either::Right(Node {
                peer_id,
                public,
                index,
                state: Done(Ok(output)),
            })),
            Err((ndkg, justifs)) => {
                // publish justifications if you have some
                // Nodes may just see that justifications are needed but they
                // don't have to create any, since no complaint has been filed
                // against their deal.
                if let Some(j) = justifs {
                    board
                        .publish_justifications(peer_id.clone(), &public, j)
                        .await?;
                }

                Ok(Either::Left(Node {
                    peer_id,
                    public,
                    index,
                    state: Three(ndkg),
                }))
            }
        }
    }
}

impl Node<Three> {
    pub fn dkg_phase3(
        self,
        justifications: &Vec<dkg::BundledJustification<KeyCurve>>,
    ) -> Result<Node<Done>> {
        let Self {
            peer_id,
            index,
            public,
            state,
        } = self;

        let res = state
            .0
            .process_justifications(justifications)
            .map_err(|err| anyhow!(err));
        Ok(Node {
            peer_id,
            public,
            index,
            state: Done(res),
        })
    }
}

impl Node<Done> {
    pub fn partial(&self, partial: &[u8]) -> Result<Vec<u8>> {
        let state = self.state.0.as_ref().map_err(|err| anyhow!("{}", err))?;
        let res = Scheme::partial_sign(&state.share, partial).map_err(|err| anyhow!("{}", err))?;

        Ok(res)
    }

    pub fn share(&self) -> Result<&super::Share> {
        let state = self.state.0.as_ref().map_err(|err| anyhow!("{}", err))?;
        Ok(&state.share)
    }

    pub fn qual(&self) -> Result<&super::Group> {
        let state = self.state.0.as_ref().map_err(|err| anyhow!("{}", err))?;
        Ok(&state.qual)
    }

    pub fn dist_public(&self) -> Result<super::DistPublic> {
        let state = self.state.0.as_ref().map_err(|err| anyhow!("{}", err))?;
        Ok(state.public.clone().into())
    }
}
