use std::fmt;
use std::str::FromStr;

use anyhow::Result;
use bls_signatures::{PrivateKey, PublicKey, Serialize as BlsSerialize};
use libp2p::{
    identity::{self, ed25519::Keypair},
    Multiaddr, PeerId,
};
use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

/// The default threshold is calculated as floor(n * 2/3) + 1
pub fn default_threshold(n: usize) -> usize {
    ((n * 2) as f64 / 3.0).floor() as usize + 1
}

/// Holds the public key.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Identity {
    #[serde(serialize_with = "serialize_key", deserialize_with = "deserialize_key")]
    public_key: PublicKey,
    address: Multiaddr,
    #[serde(
        serialize_with = "serialize_peer_id",
        deserialize_with = "deserialize_peer_id"
    )]
    peer_id: PeerId,
}

impl Identity {
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn address(&self) -> &Multiaddr {
        &self.address
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}

/// Holds a public private keypair.
#[derive(Serialize, Deserialize)]
pub struct Pair {
    #[serde(serialize_with = "serialize_key", deserialize_with = "deserialize_key")]
    private_key_bls: PrivateKey,
    #[serde(
        serialize_with = "serialize_key_pair",
        deserialize_with = "deserialize_key_pair"
    )]
    private_key_swarm: Keypair,
    public_key: Identity,
}

impl PartialEq for Pair {
    fn eq(&self, other: &Self) -> bool {
        self.private_key_bls == other.private_key_bls
            && self.public_key == other.public_key
            && &self.private_key_swarm.encode()[..] == &other.private_key_swarm.encode()[..]
    }
}
impl fmt::Debug for Pair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pair")
            .field("private_key_bls", &"xxx")
            .field("private_key_swarm", &"xxx")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl Pair {
    /// Returns a freshly created private / public key pair. Currently, drand only supports Bls12_381.
    pub fn new(address: Multiaddr) -> Result<Self> {
        let private_key_bls = PrivateKey::generate(&mut rand::rngs::OsRng);
        let public_key = private_key_bls.public_key();

        let private_key_swarm = Keypair::generate();
        let private_key_enum = identity::Keypair::Ed25519(private_key_swarm.clone());
        let peer_id = PeerId::from(private_key_enum.public());

        Ok(Pair {
            private_key_bls,
            private_key_swarm,
            public_key: Identity {
                public_key,
                peer_id,
                address,
            },
        })
    }

    /// Returns the private of this key pair.
    pub fn private(&self) -> &PrivateKey {
        &self.private_key_bls
    }

    pub fn private_swarm(&self) -> &Keypair {
        &self.private_key_swarm
    }

    /// Returns the public part of this key pair.
    pub fn public(&self) -> &Identity {
        &self.public_key
    }
}

fn serialize_key<S, K: BlsSerialize>(key: &K, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let raw = key.as_bytes();
    let value = hex::encode(&raw);

    serializer.serialize_str(&value)
}

fn deserialize_key<'de, D, K: BlsSerialize>(deserializer: D) -> Result<K, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_string: String = Deserialize::deserialize(deserializer)?;
    let bytes =
        hex::decode(&hex_string).map_err(|err| serde::de::Error::custom(err.to_string()))?;
    let res = K::from_bytes(&bytes).map_err(|err| serde::de::Error::custom(err.to_string()))?;

    Ok(res)
}

fn serialize_key_pair<S>(key: &Keypair, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let raw = key.encode();
    let value = hex::encode(&raw[..]);

    serializer.serialize_str(&value)
}

fn deserialize_key_pair<'de, D>(deserializer: D) -> Result<Keypair, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_string: String = Deserialize::deserialize(deserializer)?;
    let mut bytes =
        hex::decode(&hex_string).map_err(|err| serde::de::Error::custom(err.to_string()))?;
    let res =
        Keypair::decode(&mut bytes).map_err(|err| serde::de::Error::custom(err.to_string()))?;

    Ok(res)
}

fn serialize_peer_id<S>(id: &PeerId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let raw = id.to_string();
    serializer.serialize_str(&raw)
}

fn deserialize_peer_id<'de, D>(deserializer: D) -> Result<PeerId, D::Error>
where
    D: Deserializer<'de>,
{
    let raw_string: String = Deserialize::deserialize(deserializer)?;
    let res =
        PeerId::from_str(&raw_string).map_err(|err| serde::de::Error::custom(err.to_string()))?;

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    use libp2p::multiaddr::multiaddr;

    #[test]
    fn test_key_public() {
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(1234u16));
        let kp = Pair::new(addr.clone()).unwrap();

        assert_eq!(kp.public().address(), &addr);

        let toml_str = toml::to_string(&kp).unwrap();
        let kp_ret: Pair = toml::from_str(&toml_str).unwrap();

        assert_eq!(&kp, &kp_ret);

        let toml_pub = toml::to_string(kp.public()).unwrap();
        let pub_ret: Identity = toml::from_str(&toml_pub).unwrap();
        assert_eq!(kp.public(), &pub_ret);
    }
}
