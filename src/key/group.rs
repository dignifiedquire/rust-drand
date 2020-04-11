use std::convert::TryInto;
use std::time::Duration;

use blake2b_simd::Params;
use bls_signatures::Serialize as BlsSerialize;
use serde::{Deserialize, Serialize};

use super::{default_threshold, Identity};

/// Holds all information about a group of drand nodes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Group {
    /// The threshold to setup during the DKG or resharing protocol.
    threshold: usize,
    /// Used for the beacon randomness generation.
    period: Option<Duration>,
    /// List of ids forming this group.
    nodes: Vec<Identity>,
    /// The distributed public key of this group. It is nil if the group has not ran a DKG protocol yet.
    public_key: Option<DistPublic>,
}

/// Placeholder for DKG.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DistPublic {}

impl Group {
    /// Creates a minimal group.
    pub fn new(mut nodes: Vec<Identity>, threshold: usize) -> Self {
        // TODO: verify this sorting matches what the go impl does
        nodes.sort_by_key(|node| node.public_key().as_bytes());

        Group {
            period: None,
            nodes,
            threshold,
            public_key: None,
        }
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Creats a group with an existing public key.
    pub fn load(mut nodes: Vec<Identity>, threshold: usize, public_key: DistPublic) -> Self {
        // TODO: verify this sorting matches what the go impl does
        nodes.sort_by_key(|node| node.public_key().as_bytes());

        Group {
            period: None,
            nodes,
            threshold,
            public_key: Some(public_key),
        }
    }

    /// Merges the provided list of nodes into this group.
    pub fn merge(&mut self, nodes: &[Identity]) {
        self.threshold = default_threshold(self.nodes.len() + nodes.len());
        self.nodes.extend_from_slice(nodes);
        self.nodes.sort_by_key(|node| node.public_key().as_bytes());
    }

    /// Returns the list of the current members of this group.
    pub fn identities(&self) -> &[Identity] {
        &self.nodes
    }

    /// Returns true if the given key is contained in the list of nodes of this group.
    pub fn contains(&self, other: &Identity) -> bool {
        self.nodes.iter().find(|&n| n == other).is_some()
    }

    /// Returns an unique short representation of this group.
    /// NOTE: It currently does NOT take into account the distributed public key when
    /// set for simplicity (we want old nodes and new nodes to easily refer to the
    /// same group for example). This may cause trouble in the future and may require
    /// more thoughts.
    pub fn hash(&self) -> String {
        let mut hash = Params::new().hash_length(32).to_state();

        for (i, node) in self.nodes.iter().enumerate() {
            hash.update(&(i as u32).to_le_bytes());
            hash.update(&node.public_key().as_bytes());
        }

        hex::encode(&hash.finalize())
    }

    pub fn period(&self) -> &Option<Duration> {
        &self.period
    }

    pub fn period_mut(&mut self) -> &mut Option<Duration> {
        &mut self.period
    }

    /// Find the index of the given identity.
    pub fn index(&self, other: &Identity) -> Option<usize> {
        self.nodes.iter().position(|n| n == other)
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

impl TryInto<crate::dkg::Group> for Group {
    type Error = threshold::dkg::DKGError;

    fn try_into(self) -> Result<crate::dkg::Group, Self::Error> {
        let nodes = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, node)| {
                let pk: bls_signatures::PublicKey = node.public_key().clone();
                let g1: paired::bls12_381::G1 = pk.into();
                crate::dkg::DkgNode::new(i as crate::dkg::Index, g1)
            })
            .collect();

        crate::dkg::Group::new(nodes, self.threshold())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::Pair;

    use libp2p::multiaddr::multiaddr;

    #[test]
    fn group_save_load_test() {
        let n = 3;

        let key_pairs: Vec<_> = (0..n)
            .map(|i| Pair::new(multiaddr!(Ip4([127, 0, 0, i]), Tcp(1234u16))).unwrap())
            .collect();

        let ids: Vec<_> = key_pairs.iter().map(|kp| kp.public().clone()).collect();
        let threshold = default_threshold(n as usize);

        let group = Group::new(ids, threshold);

        let toml_str = toml::to_string(&group).unwrap();
        let group_ret = toml::from_str(&toml_str).unwrap();

        assert_eq!(group, group_ret);
    }
}
