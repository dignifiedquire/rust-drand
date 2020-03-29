use std::time::Duration;

use blake2b_simd::Params;
use bls_signatures::Serialize as BlsSerialize;
use serde::{Deserialize, Serialize};

use super::Identity;

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
}
